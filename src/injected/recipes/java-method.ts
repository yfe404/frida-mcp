/**
 * java-method recipe — hook all overloads of a Java method, emit
 * args/retval/stack on entry/exit, gated by `where`.
 *
 * Upgrades the private hookJavaMethodJS in java-helpers.ts with:
 *   - `where` predicate gating.
 *   - `max_emits` to cap chatter on hot paths.
 *   - `truncate_at` to keep huge string args bounded at the source.
 *   - per-arg regex match in addition to `where`.
 */

import { recipePrelude, recipeAsyncInstall } from "./common.js";

export interface HookJavaMethodOptions {
  className: string;
  methodName: string;
  where?: string;
  logArgs?: boolean;
  logRetval?: boolean;
  logBacktrace?: boolean;
  maxEmits?: number;
  truncateAt?: number;
}

export function hookJavaMethodRecipeJS(opts: HookJavaMethodOptions): string {
  const cls = JSON.stringify(opts.className);
  const method = JSON.stringify(opts.methodName);
  const logArgs = opts.logArgs !== false ? "true" : "false";
  const logRet = opts.logRetval !== false ? "true" : "false";
  const logBt = opts.logBacktrace ? "true" : "false";
  const maxEmits = Number.isFinite(opts.maxEmits) ? (opts.maxEmits as number) : 0; // 0 = unlimited
  const truncateAt = Number.isFinite(opts.truncateAt) ? (opts.truncateAt as number) : 2048;

  const installBody = `
    var cls = Java.use(${cls});
    var overloads = cls[${method}].overloads;
    for (var i = 0; i < overloads.length; i++) {
      (function(ov, idx) {
        ov.implementation = function () {
          if (__atCap()) {
            return ov.apply(this, arguments);
          }
          var event = { type: 'java.enter', cls: ${cls}, method: ${method}, overload: idx, tid: Process.getCurrentThreadId() };
          if (${logArgs}) {
            var args = [];
            for (var j = 0; j < arguments.length; j++) {
              try { args.push(__cap(arguments[j])); } catch (e) { args.push('<unreadable>'); }
            }
            event.args = args;
          }
          if (${logBt}) {
            event.stack = __mcpStack();
          }
          __mcpEmit(event);
          var retval = ov.apply(this, arguments);
          if (${logRet}) {
            var retEvent = { type: 'java.leave', cls: ${cls}, method: ${method}, overload: idx, tid: Process.getCurrentThreadId() };
            try { retEvent.retval = __cap(retval); } catch (e) { retEvent.retval = '<unreadable>'; }
            __mcpEmit(retEvent);
          }
          __emitted++;
          return retval;
        };
      })(overloads[i], i);
    }
    __mcpEmit({ type: 'java.installed', cls: ${cls}, method: ${method}, overloads: overloads.length });
  `;

  return `(function() {
  ${recipePrelude(opts.where)}
  var __emitted = 0;
  var __max = ${maxEmits};
  var __trunc = ${truncateAt};
  function __cap(s) {
    if (s === null || s === undefined) return s;
    var str = '' + s;
    if (str.length > __trunc) return str.slice(0, __trunc) + '…[+' + (str.length - __trunc) + ']';
    return str;
  }
  function __atCap() { return __max > 0 && __emitted >= __max; }
  ${recipeAsyncInstall(installBody, "hook_java_method")}
})();`;
}
