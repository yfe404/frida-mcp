/**
 * Frida 17-safe injected JS generators for memory/module operations.
 *
 * Rules: var (not const/let), no arrow functions, instance methods on
 * NativePointer (not Memory.readX), Process.getModuleByName (not Module.*).
 */

export function listModulesJS(): string {
  return `(function() {
  var mods = Process.enumerateModules();
  var result = [];
  for (var i = 0; i < mods.length; i++) {
    var m = mods[i];
    result.push({ name: m.name, base: m.base.toString(), size: m.size, path: m.path });
  }
  return result;
})()`;
}

export function findModuleJS(name: string): string {
  return `(function() {
  var m = Process.findModuleByName(${JSON.stringify(name)});
  if (!m) return null;
  return { name: m.name, base: m.base.toString(), size: m.size, path: m.path };
})()`;
}

export function listExportsJS(moduleName: string): string {
  return `(function() {
  var m = Process.getModuleByName(${JSON.stringify(moduleName)});
  var exports = m.enumerateExports();
  var result = [];
  for (var i = 0; i < exports.length; i++) {
    var e = exports[i];
    result.push({ type: e.type, name: e.name, address: e.address.toString() });
  }
  return result;
})()`;
}

export function readMemoryJS(addressExpr: string, size: number): string {
  return `(function() {
  var addr = ${addressExpr};
  var buf = addr.readByteArray(${size});
  if (!buf) return null;
  var bytes = new Uint8Array(buf);
  var lines = [];
  for (var off = 0; off < bytes.length; off += 16) {
    var hex = "";
    var ascii = "";
    for (var j = 0; j < 16; j++) {
      if (off + j < bytes.length) {
        var b = bytes[off + j];
        hex += ("0" + b.toString(16)).slice(-2) + " ";
        ascii += (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : ".";
      } else {
        hex += "   ";
      }
    }
    var addrStr = addr.add(off).toString();
    lines.push(addrStr + "  " + hex + " |" + ascii + "|");
  }
  return lines.join("\\n");
})()`;
}
