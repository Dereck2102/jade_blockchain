import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { Interface } from "ethers";
import {
  MAX_SAFE_BIGINT,
  atomicWriteJson,
  compileRegistry,
  indexByNodeAndCounter,
  parseVerifiedLedger,
  toSafeCounter,
  validateLocalAnchors,
  withFileLock,
} from "./lib.mjs";

test("AnchorRegistry compiles cleanly and exposes expected ABI errors, events, and functions", () => {
  const compiled = compileRegistry();
  assert.ok(compiled.bytecode.length > 200);
  assert.match(compiled.sourceSha256, /^[0-9a-f]{64}$/);
  assert.match(compiled.runtimeKeccak256, /^0x[0-9a-f]{64}$/);

  const iface = new Interface(compiled.abi);
  assert.ok(iface.getFunction("authorizeEmitter"));
  assert.ok(iface.getFunction("anchor"));
  assert.ok(iface.getFunction("lastCounter"));
  assert.ok(iface.getError("Unauthorized"));
  assert.ok(iface.getError("CounterNotIncreasing"));
  assert.ok(iface.getError("EmptyNode"));
  assert.ok(iface.getEvent("EmitterAuthorized"));
  assert.ok(iface.getEvent("EventAnchored"));

  const encoded = iface.encodeFunctionData("anchor", [
    "demo-node",
    2n,
    `0x${"11".repeat(32)}`,
    `0x${"22".repeat(32)}`,
  ]);
  assert.ok(encoded.startsWith("0x"));
});

test("toSafeCounter rejects negative values and uint64 above MAX_SAFE_INTEGER", () => {
  assert.equal(toSafeCounter(0n), 0);
  assert.equal(toSafeCounter(42n), 42);
  assert.throws(() => toSafeCounter(-1n), /fuera del rango/);
  assert.throws(() => toSafeCounter(MAX_SAFE_BIGINT + 1n), /fuera del rango/);
});

test("parseVerifiedLedger and validateLocalAnchors reject tampered or malformed inputs", () => {
  const validLine = JSON.stringify({
    nodo: "demo-node",
    hash: "a".repeat(64),
    firma: "ZmlybWE=",
    firma_n: 1,
  });
  const buf = Buffer.from(`${validLine}\n`, "utf8");
  const digest = crypto.createHash("sha256").update(buf).digest("hex");

  const parsed = parseVerifiedLedger(buf, digest, 1);
  assert.equal(parsed.length, 1);
  assert.throws(() => parseVerifiedLedger(buf, "0".repeat(64), 1), /cambió/);
  assert.throws(() => parseVerifiedLedger(buf, digest, 2), /cantidad de eventos/);

  assert.equal(
    validateLocalAnchors([{ nodo: "demo-node", firma_n: 2, hash: "b".repeat(64) }]).length,
    1
  );
  assert.throws(() => validateLocalAnchors([null]), /mal formada/);
  assert.throws(() => validateLocalAnchors([{ nodo: "", firma_n: 0, hash: "bad" }]), /mal formada/);
});

test("atomicWriteJson and withFileLock persist safely", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "jade-chain-test-"));
  try {
    const target = path.join(tmpDir, "anchors.json");
    const lock = path.join(tmpDir, ".anchors.lock");
    await withFileLock(lock, async () => {
      atomicWriteJson(target, [{ nodo: "demo-node", firma_n: 1, hash: "c".repeat(64) }], 0o600);
    });
    const saved = JSON.parse(fs.readFileSync(target, "utf8"));
    assert.equal(saved[0].firma_n, 1);
    assert.equal(fs.existsSync(lock), false);
    const indexed = indexByNodeAndCounter(saved);
    assert.equal(indexed.get("demo-node").byCounter.get(1).hash, "c".repeat(64));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
