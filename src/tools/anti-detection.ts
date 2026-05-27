/**
 * Anti-detection helpers: heuristic check + opt-in bypass templates.
 *
 *  - `check_frida_detection`: enumerate loaded classes and grep for known
 *    detection libs (RootBeer, SafetyNet/Play Integrity, Xposed) plus
 *    keyword classes containing "Frida"/"Magisk"/"Substrate". Returns
 *    findings + recommended bypass recipes.
 *  - `bypass_root_detection`: install File.exists / Runtime.exec / Build.TAGS
 *    patches as a persistent script (recipe shape — uses installRecipe path).
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { sessionManager } from "../state.js";
import { executeTransientExpressionJava } from "../utils.js";
import { installRecipe } from "./recipe-helpers.js";
import { bypassRootDetectionJS } from "../injected/recipes/root-bypass.js";

const DETECTION_PROBE_JS = `(function() {
  return new Promise(function(resolve, reject) {
    Java.perform(function() {
      try {
        var PROBES = [
          { id: 'rootbeer',          re: /^com\\.scottyab\\.rootbeer\\b/,                   bypass: 'bypass_root_detection' },
          { id: 'safetynet',         re: /^com\\.google\\.android\\.gms\\.safetynet\\b/,    bypass: null },
          { id: 'play_integrity',    re: /^com\\.google\\.android\\.gms\\.integrity\\b/,    bypass: null },
          { id: 'xposed',            re: /^de\\.robv\\.android\\.xposed\\b/,                 bypass: null },
          { id: 'frida_keyword',     re: /(?:^|\\.)Frida(?:[A-Z]|$)/,                        bypass: null },
          { id: 'magisk_keyword',    re: /(?:^|\\.)Magisk(?:[A-Z]|$)/,                       bypass: null },
          { id: 'substrate_keyword', re: /(?:^|\\.)Substrate(?:[A-Z]|$)/,                    bypass: null },
        ];
        var hits = {};
        for (var i = 0; i < PROBES.length; i++) hits[PROBES[i].id] = [];
        Java.enumerateLoadedClasses({
          onMatch: function(name) {
            for (var i = 0; i < PROBES.length; i++) {
              if (PROBES[i].re.test(name)) {
                if (hits[PROBES[i].id].indexOf(name) === -1 && hits[PROBES[i].id].length < 25) {
                  hits[PROBES[i].id].push(name);
                }
              }
            }
          },
          onComplete: function() {
            var recommend = [];
            for (var i = 0; i < PROBES.length; i++) {
              if (hits[PROBES[i].id].length > 0 && PROBES[i].bypass) {
                if (recommend.indexOf(PROBES[i].bypass) === -1) recommend.push(PROBES[i].bypass);
              }
            }
            resolve({ hits: hits, recommended_bypass_tools: recommend });
          }
        });
      } catch (e) { reject(e); }
    });
  });
})();`;

export function registerAntiDetectionTools(server: McpServer): void {
  server.tool(
    "check_frida_detection",
    "Enumerate loaded classes and grep for known detection libraries (RootBeer, SafetyNet, Play Integrity, Xposed) " +
    "plus keyword matches on Frida/Magisk/Substrate. Returns hits and recommended bypass tools.",
    {
      session_id: z.string(),
    },
    async ({ session_id }) => {
      const session = sessionManager.requireSession(session_id);
      const result = await executeTransientExpressionJava(session.fridaSession, DETECTION_PROBE_JS, 20000);
      return { content: [{ type: "text", text: JSON.stringify({ status: result.status, result }, null, 2) }] };
    },
  );

  server.tool(
    "bypass_root_detection",
    "Persistent root-detection bypass: patches File.exists for su paths, Runtime.exec('su'), Build.TAGS test-keys. " +
    "Opt-in only — does not auto-install on attach.",
    {
      session_id: z.string(),
      where: z.string().optional(),
    },
    async ({ session_id, where }) => {
      const session = sessionManager.requireSession(session_id);
      const source = bypassRootDetectionJS(where);
      const { script_id } = await installRecipe(session_id, session.fridaSession, "root_bypass", source);
      return { content: [{ type: "text", text: JSON.stringify({ status: "success", script_id }) }] };
    },
  );
}
