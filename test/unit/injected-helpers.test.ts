import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { listModulesJS, findModuleJS, listExportsJS, readMemoryJS, writeMemoryJS, searchMemoryJS } from "../../src/injected/helpers.js";

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

describe("writeMemoryJS", () => {
  it("returns syntactically valid JS", () => {
    const code = writeMemoryJS('ptr("0x1000")', "90 90 90");
    new Function(code);
  });

  it("injects address expression", () => {
    const code = writeMemoryJS('ptr("0xdead")', "cc");
    assert.ok(code.includes('ptr("0xdead")'));
  });

  it("injects hex bytes string", () => {
    const code = writeMemoryJS('ptr("0x1000")', "48 89 e5");
    assert.ok(code.includes("48 89 e5"));
  });

  it("calls Memory.protect to make writable", () => {
    const code = writeMemoryJS('ptr("0x1000")', "90");
    assert.ok(code.includes("Memory.protect"));
    assert.ok(code.includes("rwx"));
  });

  it("uses NativePointer.writeByteArray", () => {
    const code = writeMemoryJS('ptr("0x1000")', "90");
    assert.ok(code.includes("addr.writeByteArray"));
  });

  it("parses hex string and creates ArrayBuffer", () => {
    const code = writeMemoryJS('ptr("0x1000")', "ff");
    assert.ok(code.includes("parseInt"));
    assert.ok(code.includes("ArrayBuffer"));
    assert.ok(code.includes("Uint8Array"));
  });

  it("uses var not const/let", () => {
    const code = writeMemoryJS('ptr("0x1000")', "90");
    assert.ok(!code.includes("const "));
    assert.ok(!code.includes("let "));
  });
});

describe("searchMemoryJS", () => {
  it("returns syntactically valid JS", () => {
    const code = searchMemoryJS("48 89 e5", 50);
    new Function(code);
  });

  it("uses Memory.scanSync", () => {
    const code = searchMemoryJS("48 89 e5", 50);
    assert.ok(code.includes("Memory.scanSync"));
  });

  it("enumerates readable memory ranges", () => {
    const code = searchMemoryJS("48 89 e5", 50);
    assert.ok(code.includes("Process.enumerateRanges"));
    assert.ok(code.includes("r--"));
  });

  it("injects hex pattern", () => {
    const code = searchMemoryJS("de ad be ef", 10);
    assert.ok(code.includes("de ad be ef"));
  });

  it("respects maxResults", () => {
    const code = searchMemoryJS("90", 25);
    assert.ok(code.includes(">= 25"));
  });

  it("includes DebugSymbol.fromAddress for module info", () => {
    const code = searchMemoryJS("90", 50);
    assert.ok(code.includes("DebugSymbol.fromAddress"));
  });

  it("uses var not const/let", () => {
    const code = searchMemoryJS("90", 50);
    assert.ok(!code.includes("const "));
    assert.ok(!code.includes("let "));
  });
});
