/**
 * native-export recipe — hook a single exported symbol of a native module.
 *
 * Emits onEnter (args as register-width hex), onLeave (retval as hex + utf-8
 * best-effort if it points to a C string). Uses Frida 17 `Process.getModuleByName(...)
 * .getExportByName(...)` API (the legacy `Module.findExportByName` is gone).
 */

import { recipePrelude, recipeAsyncInstallV8 } from "./common.js";

export interface HookNativeOptions {
  module: string;
  symbol: string;
  where?: string;
  numArgs?: number;
  decodeRetAsCString?: boolean;
}

export function hookNativeExportJS(opts: HookNativeOptions): string {
  const mod = JSON.stringify(opts.module);
  const sym = JSON.stringify(opts.symbol);
  const numArgs = Number.isFinite(opts.numArgs) ? (opts.numArgs as number) : 4;
  const decodeRet = opts.decodeRetAsCString ? "true" : "false";

  const installBody = `
    var m = Process.getModuleByName(${mod});
    var addr = m.getExportByName(${sym});
    if (addr.isNull()) {
      __mcpEmit({ type: 'native.error', err: 'Symbol not found', module: ${mod}, symbol: ${sym} });
      return;
    }
    Interceptor.attach(addr, {
      onEnter: function (args) {
        var captured = [];
        for (var i = 0; i < ${numArgs}; i++) {
          try { captured.push(args[i].toString()); } catch (e) { captured.push('<arg ' + i + ' err>'); }
        }
        this.__capturedArgs = captured;
      },
      onLeave: function (retval) {
        var event = {
          type: 'native.call',
          module: ${mod},
          symbol: ${sym},
          tid: Process.getCurrentThreadId(),
          args: this.__capturedArgs,
          retval: retval.toString()
        };
        if (${decodeRet}) {
          try { event.retval_utf8 = retval.readUtf8String(); } catch (e) { /* ignore */ }
        }
        __mcpEmit(event);
      }
    });
    __mcpEmit({ type: 'native.installed', module: ${mod}, symbol: ${sym}, address: addr.toString() });
  `;

  return `(function() {
  ${recipePrelude(opts.where)}
  ${recipeAsyncInstallV8(installBody, "hook_native_export")}
})();`;
}
