/**
 * trace recipe — install minimal onEnter loggers on every method of every
 * class matching a substring or regex. Emulates `frida-trace -j 'com.x.*!*'`.
 *
 * Intentionally cheaper than the full java-method recipe: no args, no
 * retval, no stack. Use for "who calls what" discovery; switch to
 * hook_java_method on the methods of interest.
 */

import { recipePrelude, recipeAsyncInstall } from "./common.js";

export interface TraceClassMethodsOptions {
  classFilter: string;        // substring (case-insensitive) OR /regex/ if wrapped in slashes
  methodFilter?: string;      // optional substring on method name
  where?: string;
  maxMethods?: number;        // cap on # of methods hooked to keep startup time bounded
}

export function traceClassMethodsJS(opts: TraceClassMethodsOptions): string {
  const classFilter = JSON.stringify(opts.classFilter);
  const methodFilter = JSON.stringify(opts.methodFilter ?? "");
  const maxMethods = Number.isFinite(opts.maxMethods) ? (opts.maxMethods as number) : 200;

  const installBody = `
    // Modifier bits we filter on (java.lang.reflect.Modifier constants):
    //   ABSTRACT = 0x400 — no body to hook
    //   NATIVE   = 0x100 — JNI; hooking can SIGSEGV the agent
    //   BRIDGE   = 0x40  — compiler-generated forwarders
    //   SYNTHETIC= 0x1000 — compiler-generated, often causes hook faults
    var MOD_ABSTRACT = 0x400;
    var MOD_NATIVE = 0x100;
    var MOD_BRIDGE = 0x40;
    var MOD_SYNTHETIC = 0x1000;
    function __classIsHookable(name) {
      // Skip Kotlin/Java compiler-generated nested forms that frequently
      // crash the bridge when hooked. Pure Lambda$ classes are particularly
      // dangerous because their backing native invokers are not stable.
      if (name.indexOf('$$Lambda') !== -1) return false;
      if (/\\$\\$ExternalSyntheticLambda\\d+/.test(name)) return false;
      if (name.indexOf('$$serializer') !== -1) return false;
      return true;
    }
    function __methodIsHookable(method, mname) {
      if (mname.indexOf('$$') !== -1) return false;
      if (mname.indexOf('access$') === 0) return false;
      var mods = method.getModifiers();
      if ((mods & MOD_ABSTRACT) !== 0) return false;
      if ((mods & MOD_NATIVE) !== 0) return false;
      if ((mods & MOD_BRIDGE) !== 0) return false;
      if ((mods & MOD_SYNTHETIC) !== 0) return false;
      return true;
    }
    Java.enumerateLoadedClasses({
      onMatch: function (className) {
        // \`enumerateLoadedClasses\` ignores onMatch's return value, so we
        // cannot short-circuit; we just skip the rest of the work once the
        // hook cap is reached.
        if (__hookCount >= ${maxMethods}) return;
        if (!__classMatches(className)) return;
        if (!__classIsHookable(className)) return;
        try {
          var cls = Java.use(className);
          var methods = cls.class.getDeclaredMethods();
          for (var i = 0; i < methods.length && __hookCount < ${maxMethods}; i++) {
            var jmethod = methods[i];
            var mname = '' + jmethod.getName();
            if (!__methodMatches(mname)) continue;
            if (!__methodIsHookable(jmethod, mname)) continue;
            try {
              var ovs = cls[mname] && cls[mname].overloads;
              if (!ovs) continue;
              for (var j = 0; j < ovs.length && __hookCount < ${maxMethods}; j++) {
                (function(ov, cn, mn, oi) {
                  ov.implementation = function () {
                    __mcpEmit({ type: 'trace.call', cls: cn, method: mn, overload: oi, tid: Process.getCurrentThreadId() });
                    // Canonical frida-java-bridge pattern: invoke the captured
                    // Method object. Frida re-points \`ov.apply\` at the original
                    // implementation, bypassing the replacement we just set.
                    // Calling \`this[mn]\` would re-enter the dispatcher and recurse.
                    // Reference: objection/agent/src/android/hooking.ts:366-404.
                    return ov.apply(this, arguments);
                  };
                  __hookCount++;
                })(ovs[j], className, mname, j);
              }
            } catch (e) { /* skip method */ }
          }
        } catch (e) { /* skip class */ }
      },
      onComplete: function () {
        __mcpEmit({ type: 'trace.installed', class_filter: __classFilter, method_filter: __methodFilter, hooked: __hookCount });
      }
    });
  `;

  return `(function() {
  ${recipePrelude(opts.where)}
  var __hookCount = 0;
  var __classFilter = ${classFilter};
  var __methodFilter = ${methodFilter};
  function __classMatches(name) {
    var f = __classFilter;
    if (f.length > 2 && f.charAt(0) === '/' && f.charAt(f.length - 1) === '/') {
      try { return new RegExp(f.slice(1, -1)).test(name); } catch (e) { return false; }
    }
    return name.toLowerCase().indexOf(f.toLowerCase()) !== -1;
  }
  function __methodMatches(name) {
    if (!__methodFilter) return true;
    return name.toLowerCase().indexOf(__methodFilter.toLowerCase()) !== -1;
  }
  ${recipeAsyncInstall(installBody, "trace_class_methods")}
})();`;
}
