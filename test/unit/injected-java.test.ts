import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  listClassesJS,
  findInstancesJS,
  listMethodsJS,
  dumpClassJS,
  runJavaJS,
  hookJavaMethodJS,
  sslPinningDisableJS,
  getCurrentActivityJS,
  fileLsJS,
  fileReadJS,
} from "../../src/injected/java-helpers.js";

describe("listClassesJS", () => {
  it("returns syntactically valid JS", () => {
    const code = listClassesJS();
    new Function(code);
  });

  it("uses Java.perform and enumerateLoadedClasses", () => {
    const code = listClassesJS();
    assert.ok(code.includes("Java.perform"));
    assert.ok(code.includes("Java.enumerateLoadedClasses"));
  });

  it("without filter does not include filter check", () => {
    const code = listClassesJS();
    assert.ok(!code.includes("indexOf"));
  });

  it("with filter includes case-insensitive check", () => {
    const code = listClassesJS("com.example");
    assert.ok(code.includes("toLowerCase"));
    assert.ok(code.includes("com.example"));
  });

  it("caps results at 500", () => {
    const code = listClassesJS();
    assert.ok(code.includes("500"));
  });
});

describe("findInstancesJS", () => {
  it("returns syntactically valid JS", () => {
    const code = findInstancesJS("com.example.MyClass", 5);
    new Function(code);
  });

  it("uses Java.choose with className", () => {
    const code = findInstancesJS("com.example.MyClass", 5);
    assert.ok(code.includes("Java.choose"));
    assert.ok(code.includes("com.example.MyClass"));
  });

  it("includes getLong for primitive long fields", () => {
    const code = findInstancesJS("com.example.MyClass", 5);
    assert.ok(code.includes("getLong"));
  });

  it("includes getInt and getBoolean reflection", () => {
    const code = findInstancesJS("any.Class", 3);
    assert.ok(code.includes("getInt"));
    assert.ok(code.includes("getBoolean"));
  });

  it("respects maxInstances parameter", () => {
    const code = findInstancesJS("Test", 10);
    assert.ok(code.includes(">= 10"));
  });

  it("uses var not const/let", () => {
    const code = findInstancesJS("Test", 5);
    assert.ok(!code.includes("const "));
    assert.ok(!code.includes("let "));
  });
});

describe("listMethodsJS", () => {
  it("returns syntactically valid JS", () => {
    const code = listMethodsJS("com.example.MyClass");
    new Function(code);
  });

  it("uses Java.use with className", () => {
    const code = listMethodsJS("com.example.MyClass");
    assert.ok(code.includes("Java.use"));
    assert.ok(code.includes("com.example.MyClass"));
  });

  it("reads method info via reflection", () => {
    const code = listMethodsJS("com.example.MyClass");
    assert.ok(code.includes("getDeclaredMethods"));
    assert.ok(code.includes("getReturnType"));
    assert.ok(code.includes("getParameterTypes"));
    assert.ok(code.includes("getModifiers"));
  });

  it("uses var not const/let", () => {
    const code = listMethodsJS("Test");
    assert.ok(!code.includes("const "));
    assert.ok(!code.includes("let "));
  });
});

describe("dumpClassJS", () => {
  it("returns syntactically valid JS", () => {
    const code = dumpClassJS("com.example.MyClass");
    new Function(code);
  });

  it("includes methods, fields, constructors, interfaces, superclass", () => {
    const code = dumpClassJS("com.example.MyClass");
    assert.ok(code.includes("getDeclaredMethods"));
    assert.ok(code.includes("getDeclaredFields"));
    assert.ok(code.includes("getDeclaredConstructors"));
    assert.ok(code.includes("getInterfaces"));
    assert.ok(code.includes("getSuperclass"));
  });

  it("injects className", () => {
    const code = dumpClassJS("android.app.Activity");
    assert.ok(code.includes("android.app.Activity"));
  });

  it("uses var not const/let", () => {
    const code = dumpClassJS("Test");
    assert.ok(!code.includes("const "));
    assert.ok(!code.includes("let "));
  });
});

describe("runJavaJS", () => {
  it("returns syntactically valid JS", () => {
    const code = runJavaJS('return Java.use("android.app.Activity").class.getName();');
    new Function(code);
  });

  it("wraps code in Java.perform", () => {
    const code = runJavaJS("return 42;");
    assert.ok(code.includes("Java.perform"));
  });

  it("injects user code into the IIFE", () => {
    const code = runJavaJS('var x = Java.use("com.example.Foo");');
    assert.ok(code.includes("com.example.Foo"));
  });
});

describe("hookJavaMethodJS", () => {
  it("returns syntactically valid JS", () => {
    const code = hookJavaMethodJS("com.example.MyClass", "doStuff", "hook_1", true, true, false);
    new Function(code);
  });

  it("uses Java.use with className", () => {
    const code = hookJavaMethodJS("com.example.MyClass", "doStuff", "hook_1", true, true, false);
    assert.ok(code.includes("Java.use"));
    assert.ok(code.includes("com.example.MyClass"));
  });

  it("hooks all overloads", () => {
    const code = hookJavaMethodJS("com.example.MyClass", "doStuff", "hook_1", true, true, false);
    assert.ok(code.includes(".overloads"));
  });

  it("sends hookId in messages", () => {
    const code = hookJavaMethodJS("com.example.MyClass", "doStuff", "my_hook", true, true, false);
    assert.ok(code.includes("my_hook"));
    assert.ok(code.includes("send("));
  });

  it("logs args when logArgs=true", () => {
    const code = hookJavaMethodJS("Cls", "m", "h1", true, false, false);
    assert.ok(code.includes("argArr"));
  });

  it("skips arg logging when logArgs=false", () => {
    const code = hookJavaMethodJS("Cls", "m", "h2", false, false, false);
    assert.ok(!code.includes("argArr"));
  });

  it("logs retval when logRetval=true", () => {
    const code = hookJavaMethodJS("Cls", "m", "h3", false, true, false);
    assert.ok(code.includes("retMsg.retval"));
  });

  it("logs backtrace when logBacktrace=true", () => {
    const code = hookJavaMethodJS("Cls", "m", "h4", false, false, true);
    assert.ok(code.includes("getStackTraceString"));
    assert.ok(code.includes("backtrace"));
  });

  it("uses var not const/let", () => {
    const code = hookJavaMethodJS("Cls", "m", "h5", true, true, true);
    assert.ok(!code.includes("const "));
    assert.ok(!code.includes("let "));
  });
});

describe("sslPinningDisableJS", () => {
  it("returns syntactically valid JS", () => {
    const code = sslPinningDisableJS();
    new Function(code);
  });

  it("registers custom TrustManager", () => {
    const code = sslPinningDisableJS();
    assert.ok(code.includes("Java.registerClass"));
    assert.ok(code.includes("X509TrustManager"));
    assert.ok(code.includes("checkServerTrusted"));
  });

  it("hooks SSLContext.init", () => {
    const code = sslPinningDisableJS();
    assert.ok(code.includes("SSLContext"));
    assert.ok(code.includes(".init"));
  });

  it("attempts OkHttp3 CertificatePinner bypass", () => {
    const code = sslPinningDisableJS();
    assert.ok(code.includes("okhttp3.CertificatePinner"));
  });

  it("attempts TrustManagerImpl bypass", () => {
    const code = sslPinningDisableJS();
    assert.ok(code.includes("TrustManagerImpl"));
  });

  it("sends result via send()", () => {
    const code = sslPinningDisableJS();
    assert.ok(code.includes("send("));
    assert.ok(code.includes("ssl_pinning_disabled"));
  });

  it("uses var not const/let", () => {
    const code = sslPinningDisableJS();
    assert.ok(!code.includes("const "));
    assert.ok(!code.includes("let "));
  });
});

describe("getCurrentActivityJS", () => {
  it("returns syntactically valid JS", () => {
    const code = getCurrentActivityJS();
    new Function(code);
  });

  it("uses ActivityThread reflection", () => {
    const code = getCurrentActivityJS();
    assert.ok(code.includes("android.app.ActivityThread"));
    assert.ok(code.includes("currentActivityThread"));
  });

  it("checks for paused state", () => {
    const code = getCurrentActivityJS();
    assert.ok(code.includes("paused"));
  });

  it("uses var not const/let", () => {
    const code = getCurrentActivityJS();
    assert.ok(!code.includes("const "));
    assert.ok(!code.includes("let "));
  });
});

describe("fileLsJS", () => {
  it("returns syntactically valid JS", () => {
    const code = fileLsJS("/data/data/com.example");
    new Function(code);
  });

  it("uses Java File API", () => {
    const code = fileLsJS("/tmp");
    assert.ok(code.includes("java.io.File"));
    assert.ok(code.includes("listFiles"));
  });

  it("injects path", () => {
    const code = fileLsJS("/data/local/tmp");
    assert.ok(code.includes("/data/local/tmp"));
  });

  it("checks directory existence", () => {
    const code = fileLsJS("/tmp");
    assert.ok(code.includes("exists"));
    assert.ok(code.includes("isDirectory"));
  });

  it("uses var not const/let", () => {
    const code = fileLsJS("/tmp");
    assert.ok(!code.includes("const "));
    assert.ok(!code.includes("let "));
  });
});

describe("fileReadJS", () => {
  it("returns syntactically valid JS", () => {
    const code = fileReadJS("/data/local/tmp/test.txt", 65536);
    new Function(code);
  });

  it("uses Java Scanner for reading", () => {
    const code = fileReadJS("/tmp/test.txt", 4096);
    assert.ok(code.includes("java.util.Scanner"));
  });

  it("checks file size against max", () => {
    const code = fileReadJS("/tmp/test.txt", 1024);
    assert.ok(code.includes("1024"));
  });

  it("injects path", () => {
    const code = fileReadJS("/data/app/config.xml", 65536);
    assert.ok(code.includes("/data/app/config.xml"));
  });

  it("uses var not const/let", () => {
    const code = fileReadJS("/tmp/test.txt", 4096);
    assert.ok(!code.includes("const "));
    assert.ok(!code.includes("let "));
  });
});
