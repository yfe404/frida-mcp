/**
 * Frida 17-safe injected JS for native function hooking.
 *
 * Supports module+offset address notation.
 * Uses Interceptor.attach (not .replace) to avoid breaking the target.
 */

export function hookFunctionJS(
  addressExpr: string,
  logArgs: boolean,
  logRetval: boolean,
  numArgs: number,
  hookId: string,
): string {
  const argLogCode = logArgs
    ? `var argVals = [];
            for (var i = 0; i < ${numArgs}; i++) {
              argVals.push("x" + i + "=" + args[i]);
            }
            send({ hookId: ${JSON.stringify(hookId)}, event: "onEnter", args: argVals, tid: Process.getCurrentThreadId() });`
    : "";

  const retLogCode = logRetval
    ? `send({ hookId: ${JSON.stringify(hookId)}, event: "onLeave", retval: retval.toString(), tid: Process.getCurrentThreadId() });`
    : "";

  return `(function() {
  var addr = ${addressExpr};
  Interceptor.attach(addr, {
    onEnter: function(args) {
      ${argLogCode || `/* args logging disabled */`}
    },
    onLeave: function(retval) {
      ${retLogCode || `/* retval logging disabled */`}
    }
  });
  return "Hooked " + addr + " (id: ${hookId})";
})()`;
}

export function getBacktraceJS(addressExpr: string, style: string): string {
  const btStyle = style === "fuzzy" ? "Backtracer.FUZZY" : "Backtracer.ACCURATE";

  return `(function() {
  var addr = ${addressExpr};
  var captured = null;
  var listener = Interceptor.attach(addr, {
    onEnter: function(args) {
      var bt = Thread.backtrace(this.context, ${btStyle});
      var frames = [];
      for (var i = 0; i < bt.length; i++) {
        var sym = DebugSymbol.fromAddress(bt[i]);
        frames.push({
          address: bt[i].toString(),
          module: sym.moduleName || "unknown",
          name: sym.name || "unknown",
          offset: sym.fileName || ""
        });
      }
      captured = frames;
      listener.detach();
    }
  });
  // Wait briefly for the hook to fire (caller must trigger the function)
  return "Backtrace hook installed at " + addr + ". Trigger the function and check messages.";
})()`;
}

/**
 * Variant that sends backtrace via send() for async collection.
 */
export function getBacktraceAsyncJS(addressExpr: string, style: string, hookId: string): string {
  const btStyle = style === "fuzzy" ? "Backtracer.FUZZY" : "Backtracer.ACCURATE";

  return `(function() {
  var addr = ${addressExpr};
  var listener = Interceptor.attach(addr, {
    onEnter: function(args) {
      var bt = Thread.backtrace(this.context, ${btStyle});
      var frames = [];
      for (var i = 0; i < bt.length; i++) {
        var sym = DebugSymbol.fromAddress(bt[i]);
        frames.push({
          address: bt[i].toString(),
          module: sym.moduleName || "unknown",
          name: sym.name || "unknown"
        });
      }
      send({ hookId: ${JSON.stringify(hookId)}, event: "backtrace", frames: frames });
      listener.detach();
    }
  });
  return "Backtrace hook installed at " + addr + " (one-shot, id: ${hookId})";
})()`;
}
