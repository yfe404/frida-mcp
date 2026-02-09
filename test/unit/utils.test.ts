import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { resolveAddressJS, wrapForExecution, truncateResult } from "../../src/utils.js";

describe("resolveAddressJS", () => {
  it("handles absolute hex address", () => {
    const result = resolveAddressJS("0x13c7e8");
    assert.equal(result, 'ptr("0x13c7e8")');
  });

  it("handles module+offset notation", () => {
    const result = resolveAddressJS("libnative.so+0x13c7e8");
    assert.equal(
      result,
      'Process.getModuleByName("libnative.so").base.add(0x13c7e8)',
    );
  });

  it("trims whitespace around module and offset", () => {
    const result = resolveAddressJS("libc.so + 0x100");
    assert.equal(
      result,
      'Process.getModuleByName("libc.so").base.add(0x100)',
    );
  });

  it("escapes special characters in module names", () => {
    const result = resolveAddressJS('lib"weird.so+0x10');
    assert.ok(result.includes('\\"weird'));
  });

  it("wraps plain address in ptr()", () => {
    const result = resolveAddressJS("0xdeadbeef");
    assert.equal(result, 'ptr("0xdeadbeef")');
  });
});

describe("wrapForExecution", () => {
  it("returns valid JS (parseable by Function constructor)", () => {
    const code = wrapForExecution("return 42;");
    // Should not throw — valid JS
    new Function(code);
  });

  it("contains execution_receipt send call", () => {
    const code = wrapForExecution("return 1;");
    assert.ok(code.includes("execution_receipt"));
  });

  it("intercepts console.log", () => {
    const code = wrapForExecution("console.log('hello');");
    assert.ok(code.includes("__origLog"));
    assert.ok(code.includes("__logs"));
  });

  it("wraps user code in inner IIFE", () => {
    const code = wrapForExecution("return Process.arch;");
    assert.ok(code.includes("return Process.arch;"));
    assert.ok(code.startsWith("(function()"));
  });

  it("handles empty input", () => {
    const code = wrapForExecution("");
    new Function(code); // should not throw
    assert.ok(code.includes("execution_receipt"));
  });
});

describe("truncateResult", () => {
  it("returns full JSON when under limit", () => {
    const data = [1, 2, 3];
    const result = truncateResult(data);
    assert.equal(result, JSON.stringify(data));
  });

  it("truncates large arrays with truncation notice", () => {
    const data = Array.from({ length: 5000 }, (_, i) => ({
      id: i,
      name: `item_${i}_${"x".repeat(20)}`,
    }));
    const result = truncateResult(data);
    assert.ok(result.length <= 24000);
    const parsed = JSON.parse(result);
    assert.equal(parsed.truncated, true);
    assert.ok(parsed.showing < 5000);
    assert.equal(parsed.total, 5000);
    assert.ok(parsed.message.includes("Showing"));
    assert.ok(Array.isArray(parsed.items));
  });

  it("truncates large objects with notice", () => {
    const data = { big: "x".repeat(30000) };
    const result = truncateResult(data);
    assert.ok(result.length <= 24000);
    assert.ok(result.includes("[truncated"));
  });

  it("respects indent parameter", () => {
    const data = [{ a: 1 }];
    const result = truncateResult(data, 2);
    assert.equal(result, JSON.stringify(data, null, 2));
  });

  it("handles empty array", () => {
    const result = truncateResult([]);
    assert.equal(result, "[]");
  });

  it("handles null", () => {
    const result = truncateResult(null);
    assert.equal(result, "null");
  });
});
