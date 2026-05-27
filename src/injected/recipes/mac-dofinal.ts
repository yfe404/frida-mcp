/**
 * mac-doFinal recipe — observe every `javax.crypto.Mac.doFinal` invocation.
 *
 * Catches HMAC/CMAC/Poly1305 outputs across any code path. Emits algorithm,
 * input (UTF-8 best-effort + base64), and output base64. Cheap, generic, and
 * very effective for crypto reverse-engineering — this is exactly what
 * revealed the Expedia HMAC algorithm in the engagement.
 */

import { recipePrelude, recipeAsyncInstall } from "./common.js";

export interface DumpMacOptions {
  where?: string;
  includeInput?: boolean;
}

export function dumpMacDoFinalJS(opts: DumpMacOptions): string {
  const includeInput = opts.includeInput !== false ? "true" : "false";

  const installBody = `
    var Mac = Java.use('javax.crypto.Mac');
    var doFinal0 = Mac.doFinal.overload();
    var doFinal1 = Mac.doFinal.overload('[B');

    doFinal0.implementation = function () {
      // Closure-captured overload: \`.call(this)\` dispatches to the original.
      var out = doFinal0.call(this);
      try {
        __mcpEmit({
          type: 'mac.doFinal',
          algorithm: __mcpSafe(this.getAlgorithm()),
          input_len: 0,
          out_len: out.length,
          b64: __mcpBytesToB64(out)
        });
      } catch (e) {
        __mcpEmit({ type: 'mac.error', err: String(e) });
      }
      return out;
    };

    doFinal1.implementation = function (input) {
      var out = doFinal1.call(this, input);
      try {
        var event = {
          type: 'mac.doFinal',
          algorithm: __mcpSafe(this.getAlgorithm()),
          input_len: input.length,
          out_len: out.length,
          b64: __mcpBytesToB64(out)
        };
        if (${includeInput}) {
          event.input_utf8 = __mcpBytesToUtf8(input);
          event.input_b64 = __mcpBytesToB64(input);
        }
        __mcpEmit(event);
      } catch (e) {
        __mcpEmit({ type: 'mac.error', err: String(e) });
      }
      return out;
    };

    __mcpEmit({ type: 'mac.installed', hooks: ['Mac.doFinal()', 'Mac.doFinal([B)'] });
  `;

  return `(function() {
  ${recipePrelude(opts.where)}
  ${recipeAsyncInstall(installBody, "dump_mac_doFinal")}
})();`;
}
