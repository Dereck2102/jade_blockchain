import fs from "node:fs";
import { Wallet } from "ethers";

const networkDir = process.env.CHAIN_DATA ?? "/chain";
const genesisPath = `${networkDir}/networkFiles/genesis.json`;
const walletPath = `${networkDir}/deployer.key`;
const keysDir = `${networkDir}/networkFiles/keys`;
if (!fs.existsSync(genesisPath)) throw new Error("Besu no generó el genesis QBFT");
const keyDirs = fs.readdirSync(keysDir, { withFileTypes: true })
  .filter((entry) => entry.isDirectory() && entry.name !== "0")
  .map((entry) => `${keysDir}/${entry.name}`)
  .filter((directory) => fs.existsSync(`${directory}/key`));
if (keyDirs.length !== 1) throw new Error("Se esperaba exactamente una identidad validadora QBFT");
const validatorLink = `${keysDir}/0`;
fs.mkdirSync(validatorLink, { recursive: true });
const keyLink = `${validatorLink}/key`;
const relativeKey = `../${keyDirs[0].split("/").at(-1)}/key`;
if (fs.existsSync(keyLink) || fs.lstatSync(validatorLink).isSymbolicLink()) {
  if (!fs.lstatSync(keyLink).isSymbolicLink() || fs.readlinkSync(keyLink) !== relativeKey) {
    throw new Error("La ruta persistente de la identidad validadora no coincide");
  }
} else {
  fs.symlinkSync(relativeKey, keyLink);
}
const genesis = JSON.parse(fs.readFileSync(genesisPath, "utf8"));
genesis.alloc ??= {};
if (fs.existsSync(walletPath)) {
  const wallet = new Wallet(fs.readFileSync(walletPath, "utf8").trim());
  if (!genesis.alloc[wallet.address.slice(2).toLowerCase()]) {
    throw new Error("La cuenta de despliegue no está financiada en el genesis");
  }
} else {
  const wallet = Wallet.createRandom();
  const fd = fs.openSync(walletPath, "wx", 0o600);
  fs.writeFileSync(fd, `${wallet.privateKey}\n`);
  fs.fsyncSync(fd);
  fs.closeSync(fd);
  genesis.alloc[wallet.address.slice(2).toLowerCase()] = {
    balance: "0x3635C9ADC5DEA00000",
  };
  const temp = `${genesisPath}.tmp`;
  const out = fs.openSync(temp, "w", 0o644);
  fs.writeFileSync(out, `${JSON.stringify(genesis, null, 2)}\n`);
  fs.fsyncSync(out);
  fs.closeSync(out);
  fs.renameSync(temp, genesisPath);
}
