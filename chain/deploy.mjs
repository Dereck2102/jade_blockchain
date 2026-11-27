import fs from "node:fs";
import crypto from "node:crypto";
import solc from "solc";
import {
  Contract,
  ContractFactory,
  JsonRpcProvider,
  Wallet,
  keccak256,
} from "ethers";

const dataDir = process.env.CHAIN_DATA ?? "/chain";
const rpcUrl = process.env.BESU_RPC_URL ?? "http://besu:8545";
const nodeName = process.env.JADE_NODE ?? "demo-node";
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
const compiled = output.contracts["AnchorRegistry.sol"].AnchorRegistry;
const runtimeHash = keccak256(`0x${compiled.evm.deployedBytecode.object}`);
const sourceHash = crypto.createHash("sha256").update(source).digest("hex");
const deploymentPath = `${dataDir}/contract.json`;
fs.mkdirSync(dataDir, { recursive: true });

async function waitForRpc(provider) {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      await provider.getBlockNumber();
      return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 2000));
    }
  }
  throw new Error("Besu no respondió dentro del tiempo esperado");
}

function persistJson(target, value) {
  const temp = `${target}.${process.pid}.tmp`;
  const fd = fs.openSync(temp, "w", 0o600);
  try {
    fs.writeFileSync(fd, `${JSON.stringify(value, null, 2)}\n`);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(temp, target);
  const dir = fs.openSync(dataDir, "r");
  try {
    fs.fsyncSync(dir);
  } finally {
    fs.closeSync(dir);
  }
}

const provider = new JsonRpcProvider(rpcUrl);
await waitForRpc(provider);
const network = await provider.getNetwork();
if (network.chainId !== 1337n) throw new Error(`Chain ID inesperado: ${network.chainId}`);
const walletPath = `${dataDir}/deployer.key`;
let privateKey;
if (fs.existsSync(walletPath)) {
  privateKey = fs.readFileSync(walletPath, "utf8").trim();
} else {
  const wallet = Wallet.createRandom();
  privateKey = wallet.privateKey;
  const fd = fs.openSync(walletPath, "wx", 0o600);
  fs.writeFileSync(fd, `${privateKey}\n`);
  fs.fsyncSync(fd);
  fs.closeSync(fd);
}
const wallet = new Wallet(privateKey, provider);
let deployment;
if (fs.existsSync(deploymentPath)) {
  deployment = JSON.parse(fs.readFileSync(deploymentPath, "utf8"));
  if (deployment.chain_id !== "1337") {
    throw new Error("La red no coincide con el registro del contrato desplegado");
  }
} else {
  const factory = new ContractFactory(compiled.abi, `0x${compiled.evm.bytecode.object}`, wallet);
  const contract = await factory.deploy();
  await contract.waitForDeployment();
  const address = await contract.getAddress();
  await (await contract.authorizeEmitter(nodeName, wallet.address)).wait();
  deployment = {
    address,
    emitter: wallet.address,
    node: nodeName,
    chain_id: "1337",
    source_sha256: sourceHash,
    runtime_keccak256: runtimeHash,
  };
  persistJson(deploymentPath, deployment);
}
const deployedCode = await provider.getCode(deployment.address);
if (
  deployedCode === "0x"
  || keccak256(deployedCode) !== runtimeHash
  || deployment.runtime_keccak256 !== runtimeHash
  || deployment.source_sha256 !== sourceHash
) {
  throw new Error("La fuente o el bytecode desplegado no coincide con el contrato compilado");
}
const registry = new Contract(deployment.address, compiled.abi, wallet);
if ((await registry.authorizedEmitter(nodeName)).toLowerCase() !== wallet.address.toLowerCase()) {
  throw new Error("El emisor autorizado del contrato no coincide con la identidad local");
}
console.log(`Contrato ${deployment.address}; fuente y bytecode verificados`);
