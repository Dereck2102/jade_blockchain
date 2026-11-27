import fs from "node:fs";
import crypto from "node:crypto";
import solc from "solc";
import {
  Contract,
  JsonRpcProvider,
  Wallet,
  keccak256,
} from "ethers";

const dataDir = process.env.JADE_DATA ?? "/data";
const chainDir = process.env.CHAIN_DATA ?? "/chain";
const nodeName = process.env.JADE_NODE ?? "demo-node";
process.on("uncaughtException", (error) => {
  const path = `${dataDir}/anchor-errors.json`;
  const node = process.env.JADE_NODE ?? "demo-node";
  let state = { counts: {} };
  try {
    if (fs.existsSync(path)) state = JSON.parse(fs.readFileSync(path, "utf8"));
  } catch {
    state = { counts: {} };
  }
  const temp = `${path}.${process.pid}.tmp`;
  try {
    const counts = state?.counts && typeof state.counts === "object" && !Array.isArray(state.counts)
      ? state.counts
      : Object.create(null);
    const previous = counts[node];
    counts[node] = (Number.isSafeInteger(previous) && previous >= 0 ? previous : 0) + 1;
    fs.writeFileSync(temp, `${JSON.stringify({ counts })}\n`, { mode: 0o600 });
    fs.renameSync(temp, path);
  } catch {
    // Keep the original failure visible even if local metric state cannot be written.
  }
  console.error(error);
  process.exitCode = 1;
});
const source = fs.readFileSync(new URL("./AnchorRegistry.sol", import.meta.url), "utf8");
const input = {
  language: "Solidity",
  sources: { "AnchorRegistry.sol": { content: source } },
  settings: {
    optimizer: { enabled: true, runs: 200 },
    evmVersion: "london",
    outputSelection: {
      "*": { "*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"] },
    },
  },
};
const output = JSON.parse(solc.compile(JSON.stringify(input)));
const errors = (output.errors ?? []).filter(({ severity }) => severity === "error");
if (errors.length) throw new Error(errors.map(({ formattedMessage }) => formattedMessage).join("\n"));
const artifact = output.contracts["AnchorRegistry.sol"].AnchorRegistry;
const deployment = JSON.parse(fs.readFileSync(`${chainDir}/contract.json`, "utf8"));
const wallet = new Wallet(fs.readFileSync(`${chainDir}/deployer.key`, "utf8").trim());
const provider = new JsonRpcProvider(process.env.BESU_RPC_URL ?? "http://besu:8545");
const contract = new Contract(deployment.address, artifact.abi, wallet.connect(provider));
const code = await provider.getCode(deployment.address);
if (code === "0x" || keccak256(code) !== keccak256(`0x${artifact.evm.deployedBytecode.object}`)) {
  throw new Error("El bytecode on-chain difiere del contrato compilado desde el fuente");
}
if (deployment.source_sha256 !== crypto.createHash("sha256").update(source).digest("hex")) {
  throw new Error("El hash de fuente desplegado no coincide");
}
const eventsPath = `${dataDir}/events.jsonl`;
let verifierResponse;
for (let attempt = 0; attempt < 30; attempt += 1) {
  try {
    verifierResponse = await fetch(process.env.VERIFIER_URL ?? "http://metrics:9108/verify");
    break;
  } catch {
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
}
if (!verifierResponse) throw new Error("El verificador Python no está disponible");
const verification = await verifierResponse.json();
if (
  !verifierResponse.ok
  || !verification.integrity?.ok
  || !verification.authenticity?.ok
  || verification.event_count < 1
) {
  throw new Error("El verificador Python no confirmó integridad y autenticidad");
}
const ledger = fs.readFileSync(eventsPath);
if (crypto.createHash("sha256").update(ledger).digest("hex") !== verification.ledger_sha256) {
  throw new Error("El ledger cambió después de la verificación Python");
}
const events = ledger.toString("utf8")
  .split(/\r?\n/)
  .filter(Boolean)
  .map((line) => JSON.parse(line));
if (!events.length) throw new Error("No se ancla evidencia vacía");

const anchorsPath = `${dataDir}/anchors.json`;
const local = fs.existsSync(anchorsPath) ? JSON.parse(fs.readFileSync(anchorsPath, "utf8")) : [];
if (!Array.isArray(local)) throw new Error("Estado local de anclas mal formado");
const remoteCounter = Number(await contract.lastCounter(nodeName));
const localCounter = local.filter((anchor) => anchor.nodo === nodeName)
  .reduce((max, anchor) => Math.max(max, anchor.firma_n), 0);
const localCounters = local.filter((anchor) => anchor.nodo === nodeName)
  .map((anchor) => anchor.firma_n).sort((a, b) => a - b);
if (localCounters.some((counter, index) => counter !== index + 1)) {
  throw new Error("El estado local de anclas tiene huecos, duplicados o regresiones");
}
if (remoteCounter < localCounter) {
  throw new Error(`Regresión remota: cadena=${remoteCounter}, estado local=${localCounter}`);
}
const nodeEvents = events.filter((event) => event.nodo === nodeName);
if (remoteCounter > nodeEvents.length) {
  throw new Error("La cadena contiene anclas posteriores a los eventos locales");
}
for (let counter = 1; counter <= remoteCounter; counter += 1) {
  const event = nodeEvents.find((item) => item.firma_n === counter);
  const remoteHash = await contract.eventHashAt(nodeName, counter);
  const expectedSignatureHash = `0x${crypto.createHash("sha256").update(Buffer.from(event?.firma ?? "", "base64")).digest("hex")}`;
  const remoteSignatureHash = await contract.signatureHashAt(nodeName, counter);
  if (
    !event
    || remoteHash.toLowerCase() !== `0x${event.hash}`.toLowerCase()
    || remoteSignatureHash.toLowerCase() !== expectedSignatureHash.toLowerCase()
  ) {
    throw new Error(`Ancla remota inconsistente para ${nodeName}/${counter}`);
  }
  if (!local.some((anchor) => anchor.nodo === nodeName && anchor.firma_n === counter)) {
    local.push({
      nodo: nodeName,
      firma_n: counter,
      hash: event.hash,
      transaction_hash: null,
      anchored_at: Number(await contract.anchorTimestampAt(nodeName, counter)),
    });
  }
}
for (const event of events) {
  if (event.nodo !== nodeName || event.firma_n <= remoteCounter) continue;
  const signatureHash = `0x${crypto.createHash("sha256").update(Buffer.from(event.firma, "base64")).digest("hex")}`;
  const tx = await contract.anchor(nodeName, event.firma_n, `0x${event.hash}`, signatureHash);
  const receipt = await tx.wait();
  const block = await provider.getBlock(receipt.blockNumber);
  local.push({
    nodo: nodeName,
    firma_n: event.firma_n,
    hash: event.hash,
    transaction_hash: receipt.hash,
    anchored_at: Number(block.timestamp),
  });
  const temp = `${anchorsPath}.${process.pid}.tmp`;
  const fd = fs.openSync(temp, "w", 0o600);
  fs.writeFileSync(fd, `${JSON.stringify(local, null, 2)}\n`);
  fs.fsyncSync(fd);
  fs.closeSync(fd);
  fs.renameSync(temp, anchorsPath);
}
const anchorsTemp = `${anchorsPath}.${process.pid}.tmp`;
const anchorsFd = fs.openSync(anchorsTemp, "w", 0o600);
fs.writeFileSync(anchorsFd, `${JSON.stringify(local, null, 2)}\n`);
fs.fsyncSync(anchorsFd);
fs.closeSync(anchorsFd);
fs.renameSync(anchorsTemp, anchorsPath);
console.log(`Verificados ${events.length} eventos; anclado hasta contador ${events.length}`);
