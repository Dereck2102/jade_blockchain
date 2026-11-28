import fs from "node:fs";
import { Contract, Wallet } from "ethers";
import {
  atomicWriteJson,
  compileRegistry,
  createRpcProvider,
  fetchVerifierSnapshot,
  indexByNodeAndCounter,
  parseVerifiedLedger,
  signatureDigestHex,
  toSafeCounter,
  validateLocalAnchors,
  verifyDeployedContract,
  waitForRpc,
  withFileLock,
} from "./lib.mjs";

const dataDir = process.env.JADE_DATA ?? "/data";
const chainDir = process.env.CHAIN_DATA ?? "/chain";
const nodeName = process.env.JADE_NODE ?? "demo-node";

function recordAnchorError() {
  const errorPath = `${dataDir}/anchor-errors.json`;
  let state = { counts: {} };
  try {
    if (fs.existsSync(errorPath)) state = JSON.parse(fs.readFileSync(errorPath, "utf8"));
  } catch {
    state = { counts: {} };
  }
  try {
    const counts = state?.counts && typeof state.counts === "object" && !Array.isArray(state.counts)
      ? state.counts
      : Object.create(null);
    const previous = counts[nodeName];
    counts[nodeName] = (Number.isSafeInteger(previous) && previous >= 0 ? previous : 0) + 1;
    atomicWriteJson(errorPath, { counts }, 0o600);
  } catch {
    // Keep the original failure visible even if local metric state cannot be written.
  }
}

process.on("uncaughtException", (error) => {
  recordAnchorError();
  console.error(error);
  process.exit(1);
});

const anchorIntervalSeconds = Number(process.env.ANCHOR_INTERVAL_SECONDS ?? "0");
if (!Number.isFinite(anchorIntervalSeconds) || anchorIntervalSeconds < 0) {
  throw new Error("ANCHOR_INTERVAL_SECONDS debe ser un número mayor o igual a cero");
}

const compiled = compileRegistry();
const deployment = JSON.parse(fs.readFileSync(`${chainDir}/contract.json`, "utf8"));
const wallet = new Wallet(fs.readFileSync(`${chainDir}/deployer.key`, "utf8").trim());
const provider = createRpcProvider(process.env.BESU_RPC_URL ?? "http://besu:8545");
await waitForRpc(provider);
await verifyDeployedContract(provider, deployment, compiled);
const contract = new Contract(deployment.address, compiled.abi, wallet.connect(provider));

async function anchorLatestOnce({ allowMissingEvidence = false } = {}) {
  const verifierUrl = process.env.VERIFIER_URL ?? "http://metrics:9108/verify";
  let verifierResponse;
  for (let attempt = 0; attempt < 30; attempt += 1) {
    try {
      verifierResponse = await fetchVerifierSnapshot(verifierUrl);
      break;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 1_000));
    }
  }
  if (!verifierResponse) throw new Error("El verificador Python no está disponible");
  const verification = await verifierResponse.json();
  if (!verifierResponse.ok && allowMissingEvidence && verification?.code === "missing_evidence") {
    console.log("Aún no existen eventos para anclar.");
    return;
  }
  if (
    !verifierResponse.ok
    || !verification.integrity?.ok
    || !verification.authenticity?.ok
    || verification.event_count < 1
  ) {
    throw new Error("El verificador Python no confirmó integridad y autenticidad");
  }

  const eventsPath = `${dataDir}/events.jsonl`;
  const anchorsPath = `${dataDir}/anchors.json`;
  const lockPath = `${dataDir}/.anchors.lock`;

  await withFileLock(lockPath, async () => {
    const ledger = fs.readFileSync(eventsPath);
    const events = parseVerifiedLedger(ledger, verification.ledger_sha256, verification.event_count);
    if (!events.length) throw new Error("No se ancla evidencia vacía");

    const local = validateLocalAnchors(
      fs.existsSync(anchorsPath) ? JSON.parse(fs.readFileSync(anchorsPath, "utf8")) : []
    );
    const eventsIndex = indexByNodeAndCounter(events);
    const anchorsIndex = indexByNodeAndCounter(local);
    const nodeBucket = eventsIndex.get(nodeName);
    const nodeAnchorBucket = anchorsIndex.get(nodeName);
    const remoteCounter = toSafeCounter(await contract.lastCounter(nodeName), "lastCounter");
    const localCounters = (nodeAnchorBucket?.list ?? [])
      .map((anchor) => anchor.firma_n)
      .sort((a, b) => a - b);
    if (localCounters.some((counter, index) => index > 0 && counter <= localCounters[index - 1])) {
      throw new Error("El estado local de anclas tiene duplicados o regresiones");
    }
    const localCounter = localCounters.at(-1) ?? 0;
    if (remoteCounter < localCounter) {
      throw new Error(`Regresión remota: cadena=${remoteCounter}, estado local=${localCounter}`);
    }
    const nodeEvents = nodeBucket?.list ?? [];
    if (!nodeEvents.length) throw new Error(`No hay eventos locales para ${nodeName}`);
    const maxEventCounter = nodeEvents.at(-1).firma_n;
    if (remoteCounter > maxEventCounter) {
      throw new Error("La cadena contiene anclas posteriores a los eventos locales");
    }

    const checkpointsToVerify = [...new Set([...localCounters, ...(remoteCounter > 0 ? [remoteCounter] : [])])]
      .sort((a, b) => a - b);
    for (const counter of checkpointsToVerify) {
      const event = nodeBucket.byCounter.get(counter);
      const remoteHash = await contract.eventHashAt(nodeName, counter);
      const expectedSigHash = event ? signatureDigestHex(event.firma) : "";
      const remoteSignatureHash = await contract.signatureHashAt(nodeName, counter);
      const remoteTimestamp = toSafeCounter(
        await contract.anchorTimestampAt(nodeName, counter),
        "anchorTimestampAt"
      );
      const localEntry = nodeAnchorBucket?.byCounter.get(counter);
      if (
        !event
        || remoteHash.toLowerCase() !== `0x${event.hash}`.toLowerCase()
        || remoteSignatureHash.toLowerCase() !== expectedSigHash.toLowerCase()
        || remoteTimestamp <= 0
        || (localEntry && localEntry.hash !== event.hash)
      ) {
        throw new Error(`Ancla remota inconsistente para ${nodeName}/${counter}`);
      }
      if (!localEntry) {
        local.push({
          nodo: nodeName,
          firma_n: counter,
          hash: event.hash,
          transaction_hash: null,
          anchored_at: remoteTimestamp,
        });
      }
    }

    const latestEvent = nodeEvents.at(-1);
    if (latestEvent.firma_n > remoteCounter) {
      const signatureHash = signatureDigestHex(latestEvent.firma);
      const tx = await contract.anchor(nodeName, latestEvent.firma_n, `0x${latestEvent.hash}`, signatureHash);
      const receipt = await tx.wait(1, 60_000);
      const block = await provider.getBlock(receipt.blockNumber);
      local.push({
        nodo: nodeName,
        firma_n: latestEvent.firma_n,
        hash: latestEvent.hash,
        transaction_hash: receipt.hash,
        anchored_at: toSafeCounter(block.timestamp, "block.timestamp"),
      });
      atomicWriteJson(anchorsPath, local, 0o644);
      console.log(`Verificados ${events.length} eventos; último prefijo anclado en contador ${latestEvent.firma_n}`);
    } else {
      atomicWriteJson(anchorsPath, local, 0o644);
      console.log(`Verificados ${events.length} eventos; sin cambios desde contador ${remoteCounter}`);
    }
  });
}

if (anchorIntervalSeconds === 0) {
  try {
    await anchorLatestOnce({ allowMissingEvidence: false });
  } catch (error) {
    recordAnchorError();
    console.error(error);
    process.exit(1);
  }
} else {
  const stopController = new AbortController();
  for (const signal of ["SIGINT", "SIGTERM"]) {
    process.on(signal, () => stopController.abort());
  }
  while (!stopController.signal.aborted) {
    try {
      await anchorLatestOnce({ allowMissingEvidence: true });
    } catch (error) {
      recordAnchorError();
      console.error(error);
    }
    if (stopController.signal.aborted) break;
    await new Promise((resolve) => {
      const timer = setTimeout(resolve, anchorIntervalSeconds * 1_000);
      stopController.signal.addEventListener(
        "abort",
        () => {
          clearTimeout(timer);
          resolve();
        },
        { once: true }
      );
    });
  }
}
