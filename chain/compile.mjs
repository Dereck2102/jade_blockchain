import { compileRegistry } from "./lib.mjs";

try {
  const compiled = compileRegistry();
  console.log(`Solidity ${compiled.compilerVersion}; ABI entries: ${compiled.abi.length}`);
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
