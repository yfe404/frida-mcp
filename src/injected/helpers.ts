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

export function writeMemoryJS(addressExpr: string, hexBytes: string): string {
  return `(function() {
  var addr = ${addressExpr};
  var hexStr = ${JSON.stringify(hexBytes)};
  var clean = hexStr.replace(/\\s+/g, "");
  var bytes = [];
  for (var i = 0; i < clean.length; i += 2) {
    bytes.push(parseInt(clean.substr(i, 2), 16));
  }
  var buf = new ArrayBuffer(bytes.length);
  var view = new Uint8Array(buf);
  for (var i = 0; i < bytes.length; i++) {
    view[i] = bytes[i];
  }
  try {
    Memory.protect(addr, bytes.length, "rwx");
  } catch(e) {}
  addr.writeByteArray(buf);
  return { address: addr.toString(), bytesWritten: bytes.length };
})()`;
}

export function searchMemoryJS(hexPattern: string, maxResults: number): string {
  return `(function() {
  var results = [];
  var ranges = Process.enumerateRanges("r--");
  for (var i = 0; i < ranges.length; i++) {
    if (results.length >= ${maxResults}) break;
    try {
      var matches = Memory.scanSync(ranges[i].base, ranges[i].size, ${JSON.stringify(hexPattern)});
      for (var j = 0; j < matches.length; j++) {
        var addr = matches[j].address;
        var sym = DebugSymbol.fromAddress(addr);
        results.push({
          address: addr.toString(),
          size: matches[j].size,
          module: sym.moduleName || null
        });
        if (results.length >= ${maxResults}) break;
      }
    } catch(e) {}
  }
  return { pattern: ${JSON.stringify(hexPattern)}, matches: results, total: results.length };
})()`;
}
