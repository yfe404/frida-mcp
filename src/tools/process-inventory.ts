/**
 * process_inventory — one MCP call that returns the data we always end up
 * asking for in the first 10 minutes of any engagement:
 *
 *   - which native modules are loaded
 *   - which user-namespace Java classes exist
 *   - which networking stack the app uses (OkHttp / Cronet / HttpURL / …)
 *   - which anti-detection libs are present (RootBeer, Xposed, Magisk markers)
 *
 * Skips the 10-minute "what does this app use" warm-up.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { sessionManager } from "../state.js";
import { executeTransientExpression, executeTransientExpressionJava } from "../utils.js";

const INVENTORY_JS = `(function() {
  return new Promise(function(resolve, reject) {
    Java.perform(function() {
      try {
        var DETECTION_PROBES = [
          ['rootbeer', /^com\\.scottyab\\.rootbeer\\b/],
          ['safetynet', /^com\\.google\\.android\\.gms\\.safetynet\\b/],
          ['integrity', /^com\\.google\\.android\\.gms\\.integrity\\b/],
          ['xposed', /^de\\.robv\\.android\\.xposed\\b/],
          ['frida_keyword', /(?:^|\\.)Frida(?:[A-Z]|$)/],
          ['magisk_keyword', /(?:^|\\.)Magisk(?:[A-Z]|$)/],
          ['substrate_keyword', /(?:^|\\.)Substrate(?:[A-Z]|$)/],
        ];
        var NETWORK_PROBES = [
          ['okhttp3', 'okhttp3.OkHttpClient'],
          ['okhttp2', 'com.squareup.okhttp.OkHttpClient'],
          ['cronet',  'org.chromium.net.CronetEngine'],
          ['retrofit', 'retrofit2.Retrofit'],
          ['apollo_graphql', 'com.apollographql.apollo3.ApolloClient'],
          ['ktor',    'io.ktor.client.HttpClient'],
          ['httpurl', 'java.net.HttpURLConnection'],
          ['volley',  'com.android.volley.RequestQueue'],
        ];
        var detection = {};
        for (var i = 0; i < DETECTION_PROBES.length; i++) detection[DETECTION_PROBES[i][0]] = [];

        var userClasses = [];
        var SKIP = /^(android|com\\.android|java|javax|kotlin|kotlinx|org\\.bouncycastle|com\\.google\\.android|androidx|sun\\.|libcore|dalvik|j\\$)/;
        Java.enumerateLoadedClasses({
          onMatch: function(name) {
            for (var i = 0; i < DETECTION_PROBES.length; i++) {
              if (DETECTION_PROBES[i][1].test(name)) {
                if (detection[DETECTION_PROBES[i][0]].indexOf(name) === -1) detection[DETECTION_PROBES[i][0]].push(name);
              }
            }
            if (SKIP.test(name)) return;
            if (userClasses.length < 200) userClasses.push(name);
          },
          onComplete: function() {
            var network = [];
            for (var i = 0; i < NETWORK_PROBES.length; i++) {
              try {
                Java.use(NETWORK_PROBES[i][1]);
                network.push(NETWORK_PROBES[i][0]);
              } catch (e) { /* not present */ }
            }
            var appPkg = null;
            try {
              var ActivityThread = Java.use('android.app.ActivityThread');
              var at = ActivityThread.currentActivityThread();
              if (at) {
                var app = at.getApplication();
                if (app) appPkg = '' + app.getPackageName();
              }
            } catch (e) { /* not in an app context (rare) */ }
            resolve({
              app_package: appPkg,
              networking_stacks: network,
              user_classes_sample: userClasses,
              user_classes_truncated_at: userClasses.length === 200,
              detection_hits: detection
            });
          }
        });
      } catch (e) { reject(e); }
    });
  });
})();`;

const MODULES_JS = `(function() {
  var mods = Process.enumerateModules();
  var result = [];
  for (var i = 0; i < mods.length; i++) {
    var m = mods[i];
    result.push({ name: m.name, base: m.base.toString(), size: m.size, path: m.path });
  }
  return result;
})()`;

export function registerProcessInventoryTool(server: McpServer): void {
  server.tool(
    "process_inventory",
    "One-shot inventory of an attached process: loaded native modules, user-namespace Java classes (sample), detected networking stack(s), and anti-detection library hits (RootBeer/Xposed/etc.). Use early to skip the 'what does this app use' warm-up.",
    {
      session_id: z.string(),
    },
    async ({ session_id }) => {
      const session = sessionManager.requireSession(session_id);
      const javaPart = await executeTransientExpressionJava(session.fridaSession, INVENTORY_JS, 30000);
      const nativePart = await executeTransientExpression(session.fridaSession, MODULES_JS, 10000);
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            status: javaPart.status === "success" && nativePart.status === "success" ? "success" : "partial",
            java: javaPart,
            native_modules: nativePart,
          }),
        }],
      };
    },
  );
}
