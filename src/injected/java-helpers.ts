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

export function listMethodsJS(className: string): string {
  return `(function() {
  var result = [];
  Java.perform(function() {
    var cls = Java.use(${JSON.stringify(className)});
    var methods = cls.class.getDeclaredMethods();
    for (var i = 0; i < methods.length; i++) {
      var m = methods[i];
      var params = m.getParameterTypes();
      var paramTypes = [];
      for (var j = 0; j < params.length; j++) {
        paramTypes.push("" + params[j].getName());
      }
      result.push({
        name: "" + m.getName(),
        returnType: "" + m.getReturnType().getName(),
        parameterTypes: paramTypes,
        modifiers: m.getModifiers()
      });
    }
  });
  return result;
})()`;
}

export function dumpClassJS(className: string): string {
  return `(function() {
  var result = null;
  Java.perform(function() {
    var cls = Java.use(${JSON.stringify(className)});
    var javaClass = cls.class;
    var methodList = [];
    var methods = javaClass.getDeclaredMethods();
    for (var i = 0; i < methods.length; i++) {
      var m = methods[i];
      var params = m.getParameterTypes();
      var paramTypes = [];
      for (var j = 0; j < params.length; j++) {
        paramTypes.push("" + params[j].getName());
      }
      methodList.push({
        name: "" + m.getName(),
        returnType: "" + m.getReturnType().getName(),
        parameterTypes: paramTypes,
        modifiers: m.getModifiers()
      });
    }
    var fieldList = [];
    var fields = javaClass.getDeclaredFields();
    for (var i = 0; i < fields.length; i++) {
      var f = fields[i];
      fieldList.push({
        name: "" + f.getName(),
        type: "" + f.getType().getName(),
        modifiers: f.getModifiers()
      });
    }
    var ctorList = [];
    var constructors = javaClass.getDeclaredConstructors();
    for (var i = 0; i < constructors.length; i++) {
      var c = constructors[i];
      var cParams = c.getParameterTypes();
      var cParamTypes = [];
      for (var j = 0; j < cParams.length; j++) {
        cParamTypes.push("" + cParams[j].getName());
      }
      ctorList.push({
        parameterTypes: cParamTypes,
        modifiers: c.getModifiers()
      });
    }
    var ifaceList = [];
    var interfaces = javaClass.getInterfaces();
    for (var i = 0; i < interfaces.length; i++) {
      ifaceList.push("" + interfaces[i].getName());
    }
    var superClass = javaClass.getSuperclass();
    result = {
      className: ${JSON.stringify(className)},
      superClass: superClass ? "" + superClass.getName() : null,
      interfaces: ifaceList,
      methods: methodList,
      fields: fieldList,
      constructors: ctorList
    };
  });
  return result;
})()`;
}

export function runJavaJS(code: string): string {
  return `(function() {
  var __javaResult;
  Java.perform(function() {
    __javaResult = (function() {
      ${code}
    })();
  });
  return __javaResult;
})()`;
}

export function hookJavaMethodJS(
  className: string,
  methodName: string,
  hookId: string,
  logArgs: boolean,
  logRetval: boolean,
  logBacktrace: boolean,
): string {
  const argLog = logArgs
    ? `
          var argArr = [];
          for (var j = 0; j < arguments.length; j++) {
            try { argArr.push("" + arguments[j]); } catch(e) { argArr.push("<unreadable>"); }
          }
          msg.args = argArr;`
    : "";

  const btLog = logBacktrace
    ? `
          try {
            var bt = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
            msg.backtrace = "" + bt;
          } catch(e) {}`
    : "";

  const retLog = logRetval
    ? `try { retMsg.retval = "" + retval; } catch(e) { retMsg.retval = "<unreadable>"; }`
    : "";

  return `(function() {
  var count = 0;
  Java.perform(function() {
    var cls = Java.use(${JSON.stringify(className)});
    var overloads = cls[${JSON.stringify(methodName)}].overloads;
    count = overloads.length;
    for (var i = 0; i < overloads.length; i++) {
      (function(overload) {
        overload.implementation = function() {
          var msg = { hookId: ${JSON.stringify(hookId)}, event: "onEnter", className: ${JSON.stringify(className)}, method: ${JSON.stringify(methodName)}, tid: Process.getCurrentThreadId() };${argLog}${btLog}
          send(msg);
          var retval = this[${JSON.stringify(methodName)}].apply(this, arguments);
          var retMsg = { hookId: ${JSON.stringify(hookId)}, event: "onLeave", className: ${JSON.stringify(className)}, method: ${JSON.stringify(methodName)}, tid: Process.getCurrentThreadId() };
          ${retLog}
          send(retMsg);
          return retval;
        };
      })(overloads[i]);
    }
  });
  return "Hooked ${className}.${methodName} (" + count + " overloads)";
})()`;
}

export function sslPinningDisableJS(): string {
  return `(function() {
  var bypassed = [];
  Java.perform(function() {
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    var TrustAllCerts = Java.registerClass({
      name: "com.frida.ssl.TrustAll",
      implements: [X509TrustManager],
      methods: {
        checkClientTrusted: function(chain, authType) {},
        checkServerTrusted: function(chain, authType) {},
        getAcceptedIssuers: function() { return []; }
      }
    });
    var trustManagers = Java.array("javax.net.ssl.TrustManager", [TrustAllCerts.$new()]);
    try {
      var sslCtx = SSLContext.getInstance("TLS");
      sslCtx.init(null, trustManagers, null);
      var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
      HttpsURLConnection.setDefaultSSLSocketFactory(sslCtx.getSocketFactory());
      bypassed.push("HttpsURLConnection default SSLSocketFactory");
    } catch(e) {
      bypassed.push("HttpsURLConnection SSLSocketFactory: failed - " + e);
    }
    try {
      var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
      var TrustAllHostnames = Java.registerClass({
        name: "com.frida.ssl.TrustAllHostnames",
        implements: [HostnameVerifier],
        methods: {
          verify: function(hostname, session) { return true; }
        }
      });
      var HttpsURLConnection2 = Java.use("javax.net.ssl.HttpsURLConnection");
      HttpsURLConnection2.setDefaultHostnameVerifier(TrustAllHostnames.$new());
      bypassed.push("HttpsURLConnection default HostnameVerifier");
    } catch(e) {
      bypassed.push("HostnameVerifier: failed - " + e);
    }
    try {
      SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation = function(km, tm, sr) {
        this.init(km, trustManagers, sr);
      };
      bypassed.push("SSLContext.init hooked");
    } catch(e) {
      bypassed.push("SSLContext.init: failed - " + e);
    }
    try {
      var CertPinner = Java.use("okhttp3.CertificatePinner");
      CertPinner.check.overload("java.lang.String", "java.util.List").implementation = function() {};
      bypassed.push("OkHttp3 CertificatePinner.check");
    } catch(e) {}
    try {
      var CertPinner2 = Java.use("okhttp3.CertificatePinner");
      CertPinner2["check$okhttp"].implementation = function() {};
      bypassed.push("OkHttp3 CertificatePinner.check$okhttp");
    } catch(e) {}
    try {
      var TMI = Java.use("com.android.org.conscrypt.TrustManagerImpl");
      TMI.verifyChain.implementation = function() {
        return arguments[0];
      };
      bypassed.push("TrustManagerImpl.verifyChain");
    } catch(e) {}
  });
  send({ event: "ssl_pinning_disabled", bypassed: bypassed });
})()`;
}

export function getCurrentActivityJS(): string {
  return `(function() {
  var result = null;
  Java.perform(function() {
    try {
      var ActivityThread = Java.use("android.app.ActivityThread");
      var at = ActivityThread.currentActivityThread();
      var app = at.getApplication();
      result = { packageName: "" + app.getPackageName() };
      var activities = at.mActivities.value;
      var it = activities.values().iterator();
      while (it.hasNext()) {
        var record = it.next();
        if (!record.paused.value) {
          result.className = "" + record.activity.value.getClass().getName();
          try { result.title = "" + record.activity.value.getTitle(); } catch(e) {}
          break;
        }
      }
    } catch(e) {
      result = { error: "" + e };
    }
  });
  return result;
})()`;
}

export function fileLsJS(path: string): string {
  return `(function() {
  var result = [];
  Java.perform(function() {
    var File = Java.use("java.io.File");
    var dir = File.$new(${JSON.stringify(path)});
    if (!dir.exists()) { result = { error: "Path does not exist: " + ${JSON.stringify(path)} }; return; }
    if (!dir.isDirectory()) { result = { error: "Not a directory: " + ${JSON.stringify(path)} }; return; }
    var files = dir.listFiles();
    if (files === null) { result = { error: "Cannot list directory (permission denied?)" }; return; }
    for (var i = 0; i < files.length; i++) {
      var f = files[i];
      result.push({
        name: "" + f.getName(),
        path: "" + f.getAbsolutePath(),
        isDirectory: f.isDirectory(),
        size: f.length(),
        lastModified: f.lastModified()
      });
    }
  });
  return result;
})()`;
}

export function fileReadJS(path: string, maxSize: number): string {
  return `(function() {
  var content = null;
  Java.perform(function() {
    try {
      var File = Java.use("java.io.File");
      var file = File.$new(${JSON.stringify(path)});
      if (!file.exists()) { content = { error: "File not found: " + ${JSON.stringify(path)} }; return; }
      if (file.isDirectory()) { content = { error: "Path is a directory" }; return; }
      var fileSize = file.length();
      if (fileSize > ${maxSize}) {
        content = { error: "File too large (" + fileSize + " bytes, max ${maxSize})" };
        return;
      }
      var Scanner = Java.use("java.util.Scanner");
      var scanner = Scanner.$new(file, "UTF-8");
      scanner.useDelimiter("\\\\A");
      var text = scanner.hasNext() ? "" + scanner.next() : "";
      scanner.close();
      content = { path: ${JSON.stringify(path)}, size: fileSize, content: text };
    } catch(e) {
      content = { error: "" + e };
    }
  });
  return content;
})()`;
}
