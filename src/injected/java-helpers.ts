/**
 * Frida 17-safe injected JS for Java heap operations.
 *
 * Key project pattern: Java.choose() for finding live instances on heap,
 * with reflection fallback for primitive long fields.
 */

export function listClassesJS(filter?: string): string {
  const filterCheck = filter
    ? `if (name.toLowerCase().indexOf(${JSON.stringify(filter.toLowerCase())}) === -1) continue;`
    : "";

  return `(function() {
  var result = [];
  Java.perform(function() {
    var classes = Java.enumerateLoadedClasses();
    for (var i = 0; i < classes.length; i++) {
      var name = classes[i];
      ${filterCheck}
      result.push(name);
      if (result.length >= 500) break;
    }
  });
  return result;
})()`;
}

export function findInstancesJS(className: string, maxInstances: number): string {
  return `(function() {
  var result = [];
  Java.perform(function() {
    Java.choose(${JSON.stringify(className)}, {
      onMatch: function(instance) {
        var info = { className: ${JSON.stringify(className)}, fields: {} };
        try {
          var cls = instance.getClass();
          var fields = cls.getDeclaredFields();
          for (var i = 0; i < fields.length; i++) {
            var f = fields[i];
            var fname = "" + f.getName();
            var ftype = "" + f.getType().getName();
            f.setAccessible(true);
            var val;
            try {
              if (ftype === "long") {
                val = f.getLong(instance);
              } else if (ftype === "int") {
                val = f.getInt(instance);
              } else if (ftype === "boolean") {
                val = f.getBoolean(instance);
              } else if (ftype === "double") {
                val = f.getDouble(instance);
              } else if (ftype === "float") {
                val = f.getFloat(instance);
              } else {
                var obj = f.get(instance);
                val = obj !== null ? "" + obj : null;
              }
            } catch(e) {
              val = "<error: " + e + ">";
            }
            info.fields[fname] = { type: ftype, value: val };
          }
        } catch(e) {
          info.reflectionError = "" + e;
        }
        result.push(info);
        if (result.length >= ${maxInstances}) return "stop";
      },
      onComplete: function() {}
    });
  });
  return result;
})()`;
}
