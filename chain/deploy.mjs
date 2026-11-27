import fs from "node:fs";
import { Contract, ContractFactory, Wallet } from "ethers";
import {
  EXPECTED_CHAIN_ID,
  atomicWriteJson,
  compileRegistry,
  createRpcProvider,
  verifyDeployedContract,
  waitForRpc,
} from "./lib.mjs";

const dataDir = process.env.CHAIN_DATA ?? "/chain";
const rpcUrl = process.env.BESU_RPC_URL ?? "http://besu:8545";
const nodeName = process.env.JADE_NODE ?? "demo-node";
const compiled = compileRegistry();
const deploymentPath = `${dataDir}/contract.json`;
const walletPath = `${dataDir}/deployer.key`;
fs.mkdirSync(dataDir, { recursive: true });

if (fs.existsSync(deploymentPath) && !fs.existsSync(walletPath)) {
  throw new Error("Existe contract.json pero falta deployer.key; no se sustituye identidad");
}

const provider = createRpcProvider(rpcUrl);
await waitForRpc(provider);

let privateKey;
if (fs.existsSync(walletPath)) {
  privateKey = fs.readFileSync(walletPath, "utf8").trim();
} else {
  const created = Wallet.createRandom();
  privateKey = created.privateKey;
  const fd = fs.openSync(walletPath, "wx", 0o600);
  try {
    fs.writeFileSync(fd, `${privateKey}\n`);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

const wallet = new Wallet(privateKey, provider);
let deployment;
if (fs.existsSync(deploymentPath)) {
  deployment = JSON.parse(fs.readFileSync(deploymentPath, "utf8"));
} else {
  const network = await provider.getNetwork();
  if (network.chainId !== EXPECTED_CHAIN_ID) {
    throw new Error(`Chain ID inesperado: ${network.chainId}`);
  }
  const factory = new ContractFactory(compiled.abi, compiled.bytecode, wallet);
  const contract = await factory.deploy();
  await contract.waitForDeployment();
  const address = await contract.getAddress();
  await (await contract.authorizeEmitter(nodeName, wallet.address)).wait(1, 60_000);
  deployment = {
    address,
    emitter: wallet.address,
    node: nodeName,
    chain_id: EXPECTED_CHAIN_ID.toString(),
    source_sha256: compiled.sourceSha256,
    runtime_keccak256: compiled.runtimeKeccak256,
  };
  atomicWriteJson(deploymentPath, deployment, 0o644);
}

await verifyDeployedContract(provider, deployment, compiled);
const registry = new Contract(deployment.address, compiled.abi, wallet);
if ((await registry.authorizedEmitter(nodeName)).toLowerCase() !== wallet.address.toLowerCase()) {
  throw new Error("El emisor autorizado del contrato no coincide con la identidad local");
}
console.log(`Contrato ${deployment.address}; fuente y bytecode verificados`);
