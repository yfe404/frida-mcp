import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { listModulesJS, findModuleJS, listExportsJS, readMemoryJS } from "../../src/injected/helpers.js";

describe("listModulesJS", () => {
  it("returns syntactically valid JS", () => {
    const code = listModulesJS();
    new Function(code); // should not throw
  });

  it("uses Process.enumerateModules()", () => {
    const code = listModulesJS();
    assert.ok(code.includes("Process.enumerateModules()"));
  });

  it("uses var instead of const/let (Frida 17 compat)", () => {
    const code = listModulesJS();
    assert.ok(!code.includes("const "));
    assert.ok(!code.includes("let "));
    assert.ok(code.includes("var "));
  });
});

describe("findModuleJS", () => {
  it("returns syntactically valid JS", () => {
    const code = findModuleJS("libc.so");
    new Function(code);
  });

  it("injects module name into code", () => {
    const code = findModuleJS("libnative.so");
    assert.ok(code.includes("libnative.so"));
  });

  it("uses Process.findModuleByName (not deprecated Module.*)", () => {
    const code = findModuleJS("test.so");
    assert.ok(code.includes("Process.findModuleByName"));
    assert.ok(!code.includes("Module.findModuleByName"));
  });
});

describe("listExportsJS", () => {
  it("returns syntactically valid JS", () => {
    const code = listExportsJS("libc.so");
    new Function(code);
  });

  it("uses instance method enumerateExports (Frida 17)", () => {
    const code = listExportsJS("libc.so");
    assert.ok(code.includes("m.enumerateExports()"));
    assert.ok(!code.includes("Module.enumerateExports"));
  });

  it("injects module name", () => {
    const code = listExportsJS("libnative.so");
    assert.ok(code.includes("libnative.so"));
  });
});

describe("readMemoryJS", () => {
  it("returns syntactically valid JS", () => {
    const code = readMemoryJS('ptr("0x1000")', 64);
    new Function(code);
  });

  it("injects address expression and size", () => {
    const code = readMemoryJS('ptr("0xdead")', 128);
    assert.ok(code.includes('ptr("0xdead")'));
    assert.ok(code.includes("readByteArray(128)"));
  });

  it("uses NativePointer.readByteArray (not Memory.readByteArray)", () => {
    const code = readMemoryJS('ptr("0x100")', 32);
    assert.ok(code.includes("addr.readByteArray"));
    assert.ok(!code.includes("Memory.readByteArray"));
  });
});
