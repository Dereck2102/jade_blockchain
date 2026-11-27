import fs from "node:fs";
import solc from "solc";

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
  console.error(errors.map(({ formattedMessage }) => formattedMessage).join("\n"));
  process.exitCode = 1;
} else {
  const contract = output.contracts["AnchorRegistry.sol"].AnchorRegistry;
  console.log(`Solidity ${solc.version()}; ABI entries: ${contract.abi.length}`);
}
