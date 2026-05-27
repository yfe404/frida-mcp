/**
 * okhttp recipe — emits one event per Request finalized by `Request$Builder.build`.
 *
 * Catches all OkHttp clients regardless of interceptor stack. Optionally
 * includes a Java stack trace so the caller can find which interceptor set
 * each header.
 */

import { recipePrelude, recipeAsyncInstall } from "./common.js";

export interface HookOkHttpOptions {
  where?: string;
  urlIncludes?: string;
  includeStack?: boolean;
  includeBody?: boolean;
  maxBodyBytes?: number;
}

export function hookOkHttpJS(opts: HookOkHttpOptions): string {
  const urlNeedle = opts.urlIncludes ? JSON.stringify(opts.urlIncludes) : "null";
  const includeStack = opts.includeStack ? "true" : "false";
  const includeBody = opts.includeBody ? "true" : "false";
  const maxBody = Number.isFinite(opts.maxBodyBytes) ? opts.maxBodyBytes : 8192;

  const installBody = `
    var __seq = 0;
    var Builder = Java.use('okhttp3.Request$Builder');
    var origBuild = Builder.build;
    origBuild.implementation = function () {
      var req = origBuild.call(this);
      try {
        var url = __mcpSafe(req.url());
        var needle = ${urlNeedle};
        if (needle && url.indexOf(needle) === -1) {
          return req;
        }
        var id = ++__seq;
        var method = __mcpSafe(req.method());
        var headers = req.headers();
        var hdrList = [];
        var n = headers.size();
        for (var i = 0; i < n; i++) {
          hdrList.push(__mcpSafe(headers.name(i)) + ': ' + __mcpSafe(headers.value(i)));
        }
        var event = {
          type: 'okhttp.request',
          id: id,
          method: method,
          url: url,
          headers: hdrList
        };
        if (${includeBody}) {
          try {
            var body = req.body();
            if (body !== null) {
              var Buffer = Java.use('okio.Buffer');
              var buf = Buffer.$new();
              body.writeTo(buf);
              var bytes = buf.readByteArray();
              if (bytes !== null) {
                var view = bytes.length > ${maxBody} ? Java.array('byte', Array.prototype.slice.call(bytes, 0, ${maxBody})) : bytes;
                event.body_len = bytes.length;
                event.body_b64 = __mcpBytesToB64(view);
                event.body_utf8 = __mcpBytesToUtf8(view);
                event.body_truncated = bytes.length > ${maxBody};
              }
            }
          } catch (e) {
            event.body_err = String(e);
          }
        }
        if (${includeStack}) {
          event.stack = __mcpStack();
        }
        __mcpEmit(event);
      } catch (e) {
        __mcpEmit({ type: 'okhttp.error', at: 'Builder.build', err: String(e) });
      }
      return req;
    };
  `;

  return `(function() {
  ${recipePrelude(opts.where)}
  ${recipeAsyncInstall(installBody, "hook_okhttp_requests")}
})();`;
}
