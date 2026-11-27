import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import solc from "solc";

test("contract compiles with emitter authorization and increasing per-node counters", () => {
  const source = readFileSync(new URL("./AnchorRegistry.sol", import.meta.url), "utf8");
  const input = {
    language: "Solidity",
    sources: { "AnchorRegistry.sol": { content: source } },
    settings: {
      optimizer: { enabled: true, runs: 200 },
      evmVersion: "london",
      outputSelection: { "*": { "*": ["abi", "evm.bytecode.object"] } },
    },
  };
  const result = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (result.errors ?? []).filter(({ severity }) => severity === "error");
  assert.deepEqual(errors, []);
  const contract = result.contracts["AnchorRegistry.sol"].AnchorRegistry;
  assert.ok(contract.evm.bytecode.object.length > 100);
  assert.ok(contract.abi.some(({ name }) => name === "authorizeEmitter"));
  assert.ok(contract.abi.some(({ name }) => name === "lastCounter"));
  assert.ok(contract.abi.some(({ name }) => name === "anchor"));
});
