import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import solc from "solc";
import { FetchRequest, JsonRpcProvider, ZeroAddress, keccak256 } from "ethers";

export const EXPECTED_CHAIN_ID = BigInt(process.env.JADE_CHAIN_ID ?? "1337");
export const MAX_SAFE_BIGINT = BigInt(Number.MAX_SAFE_INTEGER);
const HEX_64_RE = /^[0-9a-fA-F]{64}$/;

export function compileRegistry() {
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
  if (errors.length) {
    throw new Error(errors.map(({ formattedMessage }) => formattedMessage).join("\n"));
  }
  const artifact = output.contracts?.["AnchorRegistry.sol"]?.AnchorRegistry;
  if (!artifact) {
    throw new Error("No se encontró el artefacto compilado AnchorRegistry");
  }
  return {
    source,
    sourceSha256: crypto.createHash("sha256").update(source).digest("hex"),
    abi: artifact.abi,
    bytecode: `0x${artifact.evm.bytecode.object}`,
    deployedBytecode: `0x${artifact.evm.deployedBytecode.object}`,
    runtimeKeccak256: keccak256(`0x${artifact.evm.deployedBytecode.object}`),
    compilerVersion: solc.version(),
  };
}

export function createRpcProvider(rpcUrl, timeoutMs = 15_000) {
  const request = new FetchRequest(rpcUrl);
  request.timeout = timeoutMs;
  return new JsonRpcProvider(request, undefined, { staticNetwork: false });
}

export async function waitForRpc(provider, attempts = 40, delayMs = 1_500) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      await provider.getBlockNumber();
      return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
  throw new Error("Besu no respondió dentro del tiempo esperado");
}

export async function fetchVerifierSnapshot(verifierUrl, timeoutMs = 10_000) {
  return fetch(verifierUrl, {
    signal: AbortSignal.timeout(timeoutMs),
    redirect: "error",
  });
}

export async function verifyDeployedContract(provider, deployment, compiled, expectedChainId = EXPECTED_CHAIN_ID) {
  if (!deployment || typeof deployment !== "object" || typeof deployment.address !== "string") {
    throw new Error("Metadatos de contrato desplegado inválidos");
  }
  const network = await provider.getNetwork();
  if (network.chainId !== expectedChainId || deployment.chain_id !== expectedChainId.toString()) {
    throw new Error(`Chain ID inesperado: red=${network.chainId}, registro=${deployment.chain_id}`);
  }
  const code = await provider.getCode(deployment.address);
  if (
    code === "0x"
    || keccak256(code) !== compiled.runtimeKeccak256
    || deployment.runtime_keccak256 !== compiled.runtimeKeccak256
    || deployment.source_sha256 !== compiled.sourceSha256
  ) {
    throw new Error("La fuente o el bytecode desplegado no coincide con el contrato compilado");
  }
}

export function toSafeCounter(value, label = "contador") {
  const big = typeof value === "bigint" ? value : BigInt(value);
  if (big < 0n || big > MAX_SAFE_BIGINT) {
    throw new Error(`${label} fuera del rango entero seguro: ${big.toString()}`);
  }
  return Number(big);
}

export function atomicWriteJson(targetPath, value, mode = 0o600) {
  const dirPath = path.dirname(targetPath);
  fs.mkdirSync(dirPath, { recursive: true });
  const temp = `${targetPath}.${crypto.randomUUID()}.tmp`;
  const fd = fs.openSync(temp, "wx", mode);
  try {
    fs.writeFileSync(fd, `${JSON.stringify(value, null, 2)}\n`);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  try {
    fs.renameSync(temp, targetPath);
  } catch (error) {
    try {
      fs.unlinkSync(temp);
    } catch {
      // Ignore cleanup error.
    }
    throw error;
  }
  if (process.platform !== "win32") {
    const dirFd = fs.openSync(dirPath, "r");
    try {
      fs.fsyncSync(dirFd);
    } finally {
      fs.closeSync(dirFd);
    }
  }
}

export async function withFileLock(lockPath, fn, attempts = 50, delayMs = 100) {
  fs.mkdirSync(path.dirname(lockPath), { recursive: true });
  let lockFd = null;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      lockFd = fs.openSync(lockPath, "wx", 0o600);
      break;
    } catch (error) {
      if (error?.code !== "EEXIST") throw error;
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
  if (lockFd === null) {
    throw new Error(`No se pudo adquirir bloqueo sobre ${lockPath}`);
  }
  try {
    return await fn();
  } finally {
    try {
      fs.closeSync(lockFd);
    } catch {
      // Ignore close error.
    }
    try {
      fs.unlinkSync(lockPath);
    } catch {
      // Ignore unlink error.
    }
  }
}

export function parseVerifiedLedger(ledgerBuffer, expectedSha256, expectedCount) {
  const actualSha256 = crypto.createHash("sha256").update(ledgerBuffer).digest("hex");
  if (actualSha256 !== expectedSha256) {
    throw new Error("El ledger cambió después de la verificación local");
  }
  const events = ledgerBuffer
    .toString("utf8")
    .split(/\r?\n/)
    .filter((line) => line.trim().length > 0)
    .map((line, index) => {
      const parsed = JSON.parse(line);
      if (
        !parsed
        || typeof parsed !== "object"
        || Array.isArray(parsed)
        || typeof parsed.nodo !== "string"
        || !parsed.nodo
        || typeof parsed.hash !== "string"
        || !HEX_64_RE.test(parsed.hash)
        || typeof parsed.firma !== "string"
        || !Number.isSafeInteger(parsed.firma_n)
        || parsed.firma_n < 1
      ) {
        throw new Error(`Evento inválido en línea ${index + 1}`);
      }
      return parsed;
    });
  if (typeof expectedCount === "number" && events.length !== expectedCount) {
    throw new Error("La cantidad de eventos del ledger no coincide con el snapshot verificado");
  }
  return events;
}

export function validateLocalAnchors(localAnchors) {
  if (!Array.isArray(localAnchors)) {
    throw new Error("Estado local de anclas mal formado");
  }
  for (const anchor of localAnchors) {
    if (
      !anchor
      || typeof anchor !== "object"
      || Array.isArray(anchor)
      || typeof anchor.nodo !== "string"
      || !anchor.nodo
      || !Number.isSafeInteger(anchor.firma_n)
      || anchor.firma_n < 1
      || typeof anchor.hash !== "string"
      || !HEX_64_RE.test(anchor.hash)
    ) {
      throw new Error("Entrada de ancla local mal formada");
    }
  }
  return localAnchors;
}

export function signatureDigestHex(base64Signature) {
  return `0x${crypto.createHash("sha256").update(Buffer.from(base64Signature, "base64")).digest("hex")}`;
}

export { ZeroAddress };
