import fs from "node:fs";
import crypto from "node:crypto";
import solc from "solc";
import {
  Contract,
  JsonRpcProvider,
  keccak256,
} from "ethers";

const dataDir = process.env.JADE_DATA ?? "/data";
const chainDir = process.env.CHAIN_DATA ?? "/chain";
const nodeName = process.env.JADE_NODE ?? "demo-node";
const contractSource = fs.readFileSync(new URL("./AnchorRegistry.sol", import.meta.url), "utf8");
const input = {
  language: "Solidity",
  sources: { "AnchorRegistry.sol": { content: contractSource } },
  settings: {
    optimizer: { enabled: true, runs: 200 },
    evmVersion: "london",
    outputSelection: {
      "*": { "*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"] },
    },
  },
};
const compilerOutput = JSON.parse(solc.compile(JSON.stringify(input)));
const compilerErrors = (compilerOutput.errors ?? []).filter(({ severity }) => severity === "error");
const compiled = compilerOutput.contracts?.["AnchorRegistry.sol"]?.AnchorRegistry;
let local;
try {
  const response = await fetch(process.env.VERIFIER_URL ?? "http://metrics:9108/verify");
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
if (compilerErrors.length || !compiled) {
  output.failures.push("No se pudo compilar el fuente del contrato");
  output.anchor_coverage.status = "invalid";
  output.status = "invalid";
  console.log(JSON.stringify(output, null, 2));
  process.exit(1);
}

try {
  const ledger = fs.readFileSync(`${dataDir}/events.jsonl`);
  const digest = crypto.createHash("sha256").update(ledger).digest("hex");
  if (digest !== local.ledger_sha256) {
    throw new Error("El ledger cambió después de la verificación local");
  }
  const events = ledger.toString("utf8").split(/\r?\n/).filter(Boolean)
    .map((line) => JSON.parse(line));
  const anchorsPath = `${dataDir}/anchors.json`;
  const localAnchors = fs.existsSync(anchorsPath)
    ? JSON.parse(fs.readFileSync(anchorsPath, "utf8"))
    : [];
  if (!Array.isArray(localAnchors)) throw new Error("Estado local de anclas mal formado");
  const deployment = JSON.parse(fs.readFileSync(`${chainDir}/contract.json`, "utf8"));
  const expectedSource = crypto.createHash("sha256").update(contractSource).digest("hex");
  const expectedRuntime = keccak256(`0x${compiled.evm.deployedBytecode.object}`);
  const provider = new JsonRpcProvider(process.env.BESU_RPC_URL ?? "http://besu:8545");
  const chain = await provider.getNetwork();
  if (chain.chainId !== 1337n) throw new Error(`Chain ID inesperado: ${chain.chainId}`);
  const code = await provider.getCode(deployment.address);
  if (
    code === "0x"
    || keccak256(code) !== expectedRuntime
    || deployment.runtime_keccak256 !== expectedRuntime
    || deployment.source_sha256 !== expectedSource
  ) {
    throw new Error("Fuente o bytecode desplegado no coincide con la compilación");
  }
  const registry = new Contract(deployment.address, compiled.abi, provider);
  if (
    (await registry.authorizedEmitter(nodeName)).toLowerCase()
    !== deployment.emitter.toLowerCase()
  ) {
    throw new Error("El emisor autorizado no coincide con la identidad registrada");
  }
  output.anchor_coverage.contract_source_verified = true;
  const nodes = [...new Set([
    ...events.map((event) => event.nodo),
    ...localAnchors.map((anchor) => anchor.nodo),
  ])].sort();
  let anyRemoteAnchor = false;
  let invalidAnchor = false;
  for (const node of nodes) {
    const nodeEvents = events.filter((event) => event.nodo === node);
    const nodeLocal = localAnchors.filter((anchor) => anchor.nodo === node);
    const orderedLocalCounters = nodeLocal.map((anchor) => anchor.firma_n).sort((a, b) => a - b);
    if (orderedLocalCounters.some((counter, index) => counter !== index + 1)) {
      throw new Error(`Hueco, duplicado o regresión local para ${node}`);
    }
    const localCounter = orderedLocalCounters.at(-1) ?? 0;
    const remoteCounter = Number(await registry.lastCounter(node));
    if (remoteCounter < localCounter) {
      throw new Error(`Regresión remota para ${node}: cadena=${remoteCounter}, local=${localCounter}`);
    }
    if (remoteCounter > nodeEvents.length) {
      throw new Error(`Anclas remotas sin eventos locales para ${node}`);
    }
    if (remoteCounter > 0) anyRemoteAnchor = true;
    for (let counter = 1; counter <= remoteCounter; counter += 1) {
      const event = nodeEvents.find((entry) => entry.firma_n === counter);
      if (!event) throw new Error(`Falta evento local ${node}/${counter}`);
      const remoteEventHash = await registry.eventHashAt(node, counter);
      const remoteSignatureHash = await registry.signatureHashAt(node, counter);
      const signatureHash = `0x${crypto.createHash("sha256")
        .update(Buffer.from(event.firma, "base64"))
        .digest("hex")}`;
      const timestamp = Number(await registry.anchorTimestampAt(node, counter));
      const localAnchor = nodeLocal.find((anchor) => anchor.firma_n === counter);
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
    if (nodeEvents.length > remoteCounter) {
      output.anchor_coverage.pending_events_by_node[node] = nodeEvents.length - remoteCounter;
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
