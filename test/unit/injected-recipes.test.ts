import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { hookOkHttpJS } from "../../src/injected/recipes/okhttp.js";
import { hookJavaMethodRecipeJS } from "../../src/injected/recipes/java-method.js";
import { hookNativeExportJS } from "../../src/injected/recipes/native.js";
import { dumpMacDoFinalJS } from "../../src/injected/recipes/mac-dofinal.js";
import { traceClassMethodsJS } from "../../src/injected/recipes/trace.js";
import { bypassRootDetectionJS } from "../../src/injected/recipes/root-bypass.js";
import { compileWherePredicate } from "../../src/injected/recipes/common.js";

/**
 * These tests do not run injected JS against a real Frida agent — they
 * snapshot the shape of the generated code so we catch the regressions we
 * shipped this round (closure-captured overload, async install, predicate
 * sandbox) at build time, before any device round-trip.
 */

const ALL_JAVA_RECIPES: Record<string, string> = {
  hook_okhttp_requests:   hookOkHttpJS({}),
  hook_java_method:       hookJavaMethodRecipeJS({ className: "com.x.Y", methodName: "doStuff" }),
  dump_mac_doFinal:       dumpMacDoFinalJS({}),
  trace_class_methods:    traceClassMethodsJS({ classFilter: "com.x" }),
  bypass_root_detection:  bypassRootDetectionJS(),
};

const ALL_V8_RECIPES: Record<string, string> = {
  hook_native_export: hookNativeExportJS({ module: "libtest.so", symbol: "open" }),
};

describe("recipe templates: structural invariants", () => {
  for (const [name, src] of Object.entries({ ...ALL_JAVA_RECIPES, ...ALL_V8_RECIPES })) {
    it(`${name} parses as JavaScript`, () => {
      new Function(src);
    });

    it(`${name} includes the recipe.installed receipt`, () => {
      assert.ok(
        src.includes("'recipe.installed'") || src.includes('"recipe.installed"'),
        `${name} must emit recipe.installed via recipeAsyncInstall(V8)`,
      );
    });

    it(`${name} schedules install on Script.nextTick (does not block script.load)`, () => {
      assert.ok(
        src.includes("Script.nextTick"),
        `${name} must wrap its install body so script.load() returns immediately`,
      );
    });
  }
});

describe("recipe templates: regression — no recursive `this[methodName].apply`", () => {
  // The trace_class_methods + hook_java_method recipes used to call
  // `this[mn].apply(this, args)` from inside the hook to invoke the
  // original. That re-enters the dispatcher and recurses until the agent
  // crashes. The canonical pattern is to call the closure-captured overload
  // (`ov.apply(this, args)`).
  it("hook_java_method uses the closure-captured overload, not name lookup", () => {
    const src = hookJavaMethodRecipeJS({ className: "com.x.Y", methodName: "doStuff" });
    assert.ok(src.includes("ov.apply(this, arguments)"));
    assert.ok(!src.match(/this\["doStuff"\]\.apply/), "must not re-enter via this[mn]");
  });

  it("trace_class_methods uses the closure-captured overload", () => {
    const src = traceClassMethodsJS({ classFilter: "com.x" });
    assert.ok(src.includes("ov.apply(this, arguments)"));
    assert.ok(!src.includes("this[mn].apply"));
  });
});

describe("recipe templates: regression — Java.enumerateLoadedClasses 'stop' is gone", () => {
  it("trace_class_methods does not return 'stop' from onMatch (Java.enumerateLoadedClasses ignores it)", () => {
    const src = traceClassMethodsJS({ classFilter: "com.x" });
    assert.ok(!/return\s+['\"]stop['\"]/.test(src));
  });
});

describe("recipe templates: where predicate sandbox", () => {
  it("accepts a simple boolean expression", () => {
    const src = compileWherePredicate("event.type === 'foo'");
    assert.ok(src.includes("event.type === 'foo'"));
  });

  it("rejects backticks", () => {
    assert.throws(() => compileWherePredicate("`x`"), /backticks/);
  });

  it("rejects `while` loops", () => {
    assert.throws(() => compileWherePredicate("(function(){while(true){}})()"), /while/);
  });

  it("rejects `for` loops", () => {
    assert.throws(() => compileWherePredicate("for(;;){}"), /for/);
  });

  it("rejects function expressions", () => {
    assert.throws(() => compileWherePredicate("function(){return true}"), /function/);
  });

  it("rejects arrow functions", () => {
    assert.throws(() => compileWherePredicate("() => true"), /arrow/);
  });

  it("rejects eval and Function constructor", () => {
    assert.throws(() => compileWherePredicate("eval('1')"), /eval/);
    assert.throws(() => compileWherePredicate("Function('return 1')"), /Function/);
  });

  it("emits an agent-side 50ms watchdog around the user expression", () => {
    const src = compileWherePredicate("event.type === 'foo'");
    assert.ok(src.includes("Date.now()"));
    assert.ok(src.includes("mcp.filter.slow"));
  });
});
