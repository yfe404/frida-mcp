import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { hookFunctionJS, getBacktraceJS, getBacktraceAsyncJS } from "../../src/injected/hook-templates.js";

describe("hookFunctionJS", () => {
  it("returns syntactically valid JS", () => {
    const code = hookFunctionJS('ptr("0x1000")', true, true, 6, "hook_1");
    new Function(code);
  });

  it("includes hookId in send payload", () => {
    const code = hookFunctionJS('ptr("0x1000")', true, true, 6, "my_hook");
    assert.ok(code.includes("my_hook"));
  });

  it("logs args when logArgs=true", () => {
    const code = hookFunctionJS('ptr("0x1000")', true, false, 4, "h1");
    assert.ok(code.includes("onEnter"));
    assert.ok(code.includes("argVals"));
    assert.ok(code.includes("args[i]"));
  });

  it("disables arg logging when logArgs=false", () => {
    const code = hookFunctionJS('ptr("0x1000")', false, false, 6, "h2");
    assert.ok(code.includes("args logging disabled"));
    assert.ok(!code.includes("argVals"));
  });

  it("logs retval when logRetval=true", () => {
    const code = hookFunctionJS('ptr("0x1000")', false, true, 6, "h3");
    assert.ok(code.includes("retval.toString()"));
  });

  it("disables retval logging when logRetval=false", () => {
    const code = hookFunctionJS('ptr("0x1000")', false, false, 6, "h4");
    assert.ok(code.includes("retval logging disabled"));
  });

  it("uses numArgs to control loop bound", () => {
    const code = hookFunctionJS('ptr("0x1000")', true, false, 8, "h5");
    assert.ok(code.includes("i < 8"));
  });

  it("uses Interceptor.attach (not replace)", () => {
    const code = hookFunctionJS('ptr("0x1000")', true, true, 6, "h6");
    assert.ok(code.includes("Interceptor.attach"));
    assert.ok(!code.includes("Interceptor.replace"));
  });
});

describe("getBacktraceJS", () => {
  it("returns syntactically valid JS", () => {
    const code = getBacktraceJS('ptr("0x1000")', "accurate");
    new Function(code);
  });

  it("uses Backtracer.ACCURATE for accurate style", () => {
    const code = getBacktraceJS('ptr("0x1000")', "accurate");
    assert.ok(code.includes("Backtracer.ACCURATE"));
  });

  it("uses Backtracer.FUZZY for fuzzy style", () => {
    const code = getBacktraceJS('ptr("0x1000")', "fuzzy");
    assert.ok(code.includes("Backtracer.FUZZY"));
  });
});

describe("getBacktraceAsyncJS", () => {
  it("returns syntactically valid JS", () => {
    const code = getBacktraceAsyncJS('ptr("0x1000")', "accurate", "bt_1");
    new Function(code);
  });

  it("includes hookId in send payload", () => {
    const code = getBacktraceAsyncJS('ptr("0x1000")', "fuzzy", "bt_test");
    assert.ok(code.includes("bt_test"));
  });

  it("sends backtrace event via send()", () => {
    const code = getBacktraceAsyncJS('ptr("0x1000")', "accurate", "bt_2");
    assert.ok(code.includes('event: "backtrace"'));
    assert.ok(code.includes("send("));
  });

  it("self-detaches after first hit", () => {
    const code = getBacktraceAsyncJS('ptr("0x1000")', "accurate", "bt_3");
    assert.ok(code.includes("listener.detach()"));
  });
});
