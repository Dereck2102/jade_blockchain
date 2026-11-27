import fs from "node:fs";
import { Contract } from "ethers";
import {
  ZeroAddress,
  compileRegistry,
  createRpcProvider,
  fetchVerifierSnapshot,
  indexByNodeAndCounter,
  parseVerifiedLedger,
  signatureDigestHex,
  toSafeCounter,
  validateLocalAnchors,
  verifyDeployedContract,
} from "./lib.mjs";

const dataDir = process.env.JADE_DATA ?? "/data";
const chainDir = process.env.CHAIN_DATA ?? "/chain";
const nodeName = process.env.JADE_NODE ?? "demo-node";

let compiled = null;
let compileFailure = null;
try {
  compiled = compileRegistry();
} catch (error) {
  compileFailure = error;
}

let local;
try {
  const response = await fetchVerifierSnapshot(process.env.VERIFIER_URL ?? "http://metrics:9108/verify");
  local = await response.json();
  if (!response.ok) throw new Error(local.error ?? "La verificación local falló");
} catch (error) {
  console.log(JSON.stringify({
    schema_version: "1",
    status: "invalid",
    integrity: { checked: false, ok: false },
    authenticity: { checked: false, ok: false },
    anchor_coverage: {
      checked: false,
      status: "not_checked",
      anchored_prefix_by_node: {},
      pending_events_by_node: {},
    },
    event_count: 0,
    failures: [`No fue posible verificar localmente: ${error.message}`],
  }, null, 2));
  process.exit(1);
}

const failures = [...(local.failures ?? [])];
const output = {
  schema_version: "1",
  status: "incomplete",
  integrity: local.integrity ?? { checked: false, ok: false },
  authenticity: local.authenticity ?? { checked: false, ok: false },
  anchor_coverage: {
    checked: false,
    status: "not_checked",
    anchored_prefix_by_node: {},
    pending_events_by_node: {},
    contract_source_verified: false,
  },
  event_count: local.event_count ?? 0,
  failures,
};

if (local.status === "invalid" || !output.integrity.ok || !output.authenticity.ok) {
  output.status = "invalid";
  console.log(JSON.stringify(output, null, 2));
  process.exit(1);
}
if (compileFailure || !compiled) {
  output.failures.push("No se pudo compilar el fuente del contrato");
  output.anchor_coverage.status = "invalid";
  output.status = "invalid";
  console.log(JSON.stringify(output, null, 2));
  process.exit(1);
}

try {
  const ledger = fs.readFileSync(`${dataDir}/events.jsonl`);
  const events = parseVerifiedLedger(ledger, local.ledger_sha256, local.event_count);
  const anchorsPath = `${dataDir}/anchors.json`;
  const localAnchors = validateLocalAnchors(
    fs.existsSync(anchorsPath) ? JSON.parse(fs.readFileSync(anchorsPath, "utf8")) : []
  );
  const deployment = JSON.parse(fs.readFileSync(`${chainDir}/contract.json`, "utf8"));
  const provider = createRpcProvider(process.env.BESU_RPC_URL ?? "http://besu:8545");
  await verifyDeployedContract(provider, deployment, compiled);

  const registry = new Contract(deployment.address, compiled.abi, provider);
  if (
    typeof deployment.emitter !== "string"
    || (await registry.authorizedEmitter(nodeName)).toLowerCase() !== deployment.emitter.toLowerCase()
  ) {
    throw new Error("El emisor autorizado no coincide con la identidad registrada");
  }
  output.anchor_coverage.contract_source_verified = true;

  const eventsIndex = indexByNodeAndCounter(events);
  const anchorsIndex = indexByNodeAndCounter(localAnchors);
  const nodes = [...new Set([...eventsIndex.keys(), ...anchorsIndex.keys()])].sort();

  let anyRemoteAnchor = false;
  let invalidAnchor = false;
  for (const node of nodes) {
    const emitter = await registry.authorizedEmitter(node);
    if (!emitter || emitter === ZeroAddress) {
      throw new Error(`El nodo ${node} no tiene emisor autorizado en el contrato`);
    }
    if (node === deployment.node && emitter.toLowerCase() !== deployment.emitter.toLowerCase()) {
      throw new Error(`El emisor autorizado de ${node} difiere del registrado en el despliegue`);
    }

    const nodeEventBucket = eventsIndex.get(node);
    const nodeAnchorBucket = anchorsIndex.get(node);
    const nodeEvents = nodeEventBucket?.list ?? [];
    const nodeLocal = nodeAnchorBucket?.list ?? [];
    const orderedLocalCounters = nodeLocal.map((anchor) => anchor.firma_n).sort((a, b) => a - b);
    if (orderedLocalCounters.some((counter, index) => index > 0 && counter <= orderedLocalCounters[index - 1])) {
      throw new Error(`Duplicado o regresión local de ancla para ${node}`);
    }
    const localCounter = orderedLocalCounters.at(-1) ?? 0;
    const remoteCounter = toSafeCounter(await registry.lastCounter(node), "lastCounter");
    if (remoteCounter < localCounter) {
      throw new Error(`Regresión remota para ${node}: cadena=${remoteCounter}, local=${localCounter}`);
    }
    const maxNodeCounter = nodeEvents.at(-1)?.firma_n ?? 0;
    if (remoteCounter > maxNodeCounter) {
      throw new Error(`Anclas remotas sin eventos locales para ${node}`);
    }
    if (remoteCounter > 0) anyRemoteAnchor = true;

    const checkpointsToVerify = [...new Set([
      ...orderedLocalCounters,
      ...(remoteCounter > 0 ? [remoteCounter] : []),
    ])].sort((a, b) => a - b);
    for (const counter of checkpointsToVerify) {
      const event = nodeEventBucket?.byCounter.get(counter);
      if (!event) throw new Error(`Falta evento local ${node}/${counter}`);
      const remoteEventHash = await registry.eventHashAt(node, counter);
      const remoteSignatureHash = await registry.signatureHashAt(node, counter);
      const signatureHash = signatureDigestHex(event.firma);
      const timestamp = toSafeCounter(
        await registry.anchorTimestampAt(node, counter),
        "anchorTimestampAt"
      );
      const localAnchor = nodeAnchorBucket?.byCounter.get(counter);
      if (
        remoteEventHash.toLowerCase() !== `0x${event.hash}`.toLowerCase()
        || remoteSignatureHash.toLowerCase() !== signatureHash.toLowerCase()
        || timestamp <= 0
        || (localAnchor && localAnchor.hash !== event.hash)
      ) {
        invalidAnchor = true;
        failures.push(`Ancla remota inconsistente para ${node}/${counter}`);
      }
    }
    output.anchor_coverage.anchored_prefix_by_node[node] = remoteCounter;
    if (maxNodeCounter > remoteCounter) {
      output.anchor_coverage.pending_events_by_node[node] = maxNodeCounter - remoteCounter;
    }
  }
  output.anchor_coverage.checked = anyRemoteAnchor;
  if (invalidAnchor) {
    output.anchor_coverage.status = "invalid";
    output.status = "invalid";
  } else if (!anyRemoteAnchor) {
    output.anchor_coverage.status = "not_checked";
    output.status = "incomplete";
  } else if (Object.keys(output.anchor_coverage.pending_events_by_node).length > 0) {
    output.anchor_coverage.status = "partial";
    output.status = "incomplete";
  } else {
    output.anchor_coverage.status = "complete";
    output.status = "verified";
  }
} catch (error) {
  output.anchor_coverage.status = "invalid";
  output.failures.push(error.message);
  output.status = "invalid";
}

console.log(JSON.stringify(output, null, 2));
if (output.status === "invalid") process.exit(1);
if (output.status !== "verified") process.exit(2);
