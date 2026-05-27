/**
 * Recipe tools — surface parameterised, community-vetted hook templates as
 * first-class MCP tools so the caller doesn't have to write 200 lines of
 * Frida JS for every common task.
 *
 * Each tool follows the same loading pattern as `android_hook_method`:
 *   1. Build the JS from a template module.
 *   2. createJavaBridgeScript on the session.
 *   3. Wire script.message → sessionManager.pushMessage.
 *   4. script.load().
 *   5. Register the script so it can be listed/unloaded.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { sessionManager } from "../state.js";
import { installRecipe } from "./recipe-helpers.js";
import { hookOkHttpJS } from "../injected/recipes/okhttp.js";
import { hookJavaMethodRecipeJS } from "../injected/recipes/java-method.js";
import { hookNativeExportJS } from "../injected/recipes/native.js";
import { dumpMacDoFinalJS } from "../injected/recipes/mac-dofinal.js";
import { traceClassMethodsJS } from "../injected/recipes/trace.js";
import { sslPinningDisableJS } from "../injected/java-helpers.js";
import { RECIPES } from "../injected/recipes/index.js";

export function registerRecipeTools(server: McpServer): void {
  // ---- hook_okhttp_requests ------------------------------------------------
  server.tool(
    "hook_okhttp_requests",
    "Recipe: snoop every finalized OkHttp Request across all clients.",
    {
      session_id: z.string(),
      url_includes: z.string().optional().describe("Skip emit unless URL contains this substring."),
      where: z.string().optional().describe("JS predicate on event; default 'true'."),
      include_stack: z.boolean().optional().default(false),
      include_body: z.boolean().optional().default(false),
      max_body_bytes: z.number().int().positive().optional().default(8192),
    },
    async ({ session_id, url_includes, where, include_stack, include_body, max_body_bytes }) => {
      const session = sessionManager.requireSession(session_id);
      const source = hookOkHttpJS({
        urlIncludes: url_includes,
        where,
        includeStack: include_stack,
        includeBody: include_body,
        maxBodyBytes: max_body_bytes,
      });
      const { script_id } = await installRecipe(session_id, session.fridaSession, "hook_okhttp", source);
      return { content: [{ type: "text", text: JSON.stringify({ status: "success", script_id }) }] };
    },
  );

  // ---- hook_java_method (recipe version) -----------------------------------
  server.tool(
    "hook_java_method_recipe",
    "Recipe: hook all overloads of a Java method with source-side filter, " +
    "emit cap, and per-string truncation. Use this in preference to the simpler " +
    "android_hook_method when you need to keep events bounded.",
    {
      session_id: z.string(),
      class_name: z.string(),
      method_name: z.string(),
      where: z.string().optional(),
      log_args: z.boolean().optional().default(true),
      log_retval: z.boolean().optional().default(true),
      log_backtrace: z.boolean().optional().default(false),
      max_emits: z.number().int().nonnegative().optional().default(0),
      truncate_at: z.number().int().positive().optional().default(2048),
    },
    async ({
      session_id, class_name, method_name, where, log_args, log_retval, log_backtrace, max_emits, truncate_at,
    }) => {
      const session = sessionManager.requireSession(session_id);
      const source = hookJavaMethodRecipeJS({
        className: class_name,
        methodName: method_name,
        where,
        logArgs: log_args,
        logRetval: log_retval,
        logBacktrace: log_backtrace,
        maxEmits: max_emits,
        truncateAt: truncate_at,
      });
      const { script_id } = await installRecipe(session_id, session.fridaSession, "hook_java", source);
      return { content: [{ type: "text", text: JSON.stringify({ status: "success", script_id }) }] };
    },
  );

  // ---- hook_native_export --------------------------------------------------
  server.tool(
    "hook_native_export",
    "Recipe: attach to a single exported symbol of a native module via " +
    "Process.getModuleByName(...).getExportByName(...).",
    {
      session_id: z.string(),
      module: z.string(),
      symbol: z.string(),
      where: z.string().optional(),
      num_args: z.number().int().nonnegative().optional().default(4),
      decode_ret_as_cstring: z.boolean().optional().default(false),
    },
    async ({ session_id, module, symbol, where, num_args, decode_ret_as_cstring }) => {
      const session = sessionManager.requireSession(session_id);
      const source = hookNativeExportJS({
        module,
        symbol,
        where,
        numArgs: num_args,
        decodeRetAsCString: decode_ret_as_cstring,
      });
      const { script_id } = await installRecipe(session_id, session.fridaSession, "hook_native", source);
      return { content: [{ type: "text", text: JSON.stringify({ status: "success", script_id }) }] };
    },
  );

  // ---- trace_class_methods -------------------------------------------------
  server.tool(
    "trace_class_methods",
    "Recipe: lightweight call tracer over class+method patterns. " +
    "Emulates `frida-trace -j 'pkg.*!*'`. Use for discovery.",
    {
      session_id: z.string(),
      class_filter: z.string().describe("Substring or '/regex/' against loaded class FQCN."),
      method_filter: z.string().optional(),
      where: z.string().optional(),
      max_methods: z.number().int().positive().optional().default(200),
    },
    async ({ session_id, class_filter, method_filter, where, max_methods }) => {
      const session = sessionManager.requireSession(session_id);
      const source = traceClassMethodsJS({
        classFilter: class_filter,
        methodFilter: method_filter,
        where,
        maxMethods: max_methods,
      });
      const { script_id } = await installRecipe(session_id, session.fridaSession, "trace", source);
      return { content: [{ type: "text", text: JSON.stringify({ status: "success", script_id }) }] };
    },
  );

  // ---- dump_mac_doFinal ----------------------------------------------------
  server.tool(
    "dump_mac_doFinal",
    "Recipe: observe every javax.crypto.Mac.doFinal call. Emits algorithm, " +
    "input (utf-8 + base64), output (base64). Generic crypto observer.",
    {
      session_id: z.string(),
      where: z.string().optional(),
      include_input: z.boolean().optional().default(true),
    },
    async ({ session_id, where, include_input }) => {
      const session = sessionManager.requireSession(session_id);
      const source = dumpMacDoFinalJS({ where, includeInput: include_input });
      const { script_id } = await installRecipe(session_id, session.fridaSession, "mac_dofinal", source);
      return { content: [{ type: "text", text: JSON.stringify({ status: "success", script_id }) }] };
    },
  );

  // ---- bypass_ssl_pinning (surface existing template under recipe shape) ---
  server.tool(
    "bypass_ssl_pinning",
    "Recipe: TrustAllCerts + OkHttp3 CertificatePinner + Conscrypt TrustManagerImpl " +
    "bypass. Equivalent to android_ssl_pinning_disable but uniform with the recipe shape.",
    {
      session_id: z.string(),
    },
    async ({ session_id }) => {
      const session = sessionManager.requireSession(session_id);
      const source = sslPinningDisableJS();
      const { script_id } = await installRecipe(session_id, session.fridaSession, "ssl_bypass", source);
      return { content: [{ type: "text", text: JSON.stringify({ status: "success", script_id }) }] };
    },
  );

  // ---- search_recipes / describe_recipe ------------------------------------
  server.tool(
    "search_recipes",
    "Search the recipe registry by free-text. Returns matching slugs + one-liners.",
    {
      query: z.string().describe("Free-text query matched against slug + description."),
    },
    async ({ query }) => {
      const q = query.toLowerCase();
      const hits = RECIPES.filter((r) =>
        r.slug.toLowerCase().includes(q) || r.description.toLowerCase().includes(q),
      ).map((r) => ({ slug: r.slug, description: r.description }));
      return { content: [{ type: "text", text: JSON.stringify({ query, hits }, null, 2) }] };
    },
  );

  server.tool(
    "describe_recipe",
    "Return parameter schema + emitted event types for a recipe by slug.",
    {
      slug: z.string(),
    },
    async ({ slug }) => {
      const r = RECIPES.find((x) => x.slug === slug);
      if (!r) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: `Unknown recipe '${slug}'` }) }] };
      }
      return { content: [{ type: "text", text: JSON.stringify(r, null, 2) }] };
    },
  );

  // ---- set_session_filter --------------------------------------------------
  server.tool(
    "set_session_filter",
    "Install a global event filter for the current session's recipe scripts. " +
    "All subsequently emitted recipe events are passed through this predicate " +
    "FIRST, then through each script's own `where`. Pass an empty string to clear.",
    {
      session_id: z.string(),
      predicate_js: z.string().describe("JS expression that returns boolean, e.g. \"event.type === 'mac.doFinal'\"."),
    },
    async ({ session_id, predicate_js }) => {
      const session = sessionManager.requireSession(session_id);
      const expr = predicate_js.trim();
      if (/`/.test(expr)) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: "predicate_js must not contain backticks" }) }] };
      }
      const body = expr.length === 0
        ? "globalThis.__mcp_filter = function() { return true; };"
        : `globalThis.__mcp_filter = function(event) { try { return (${expr}); } catch (e) { return false; } };`;
      // We need to evaluate the predicate update from a transient script on this session.
      // Pull executeTransientScript locally to avoid a circular import.
      const { executeTransientScript } = await import("../utils.js");
      const result = await executeTransientScript(session.fridaSession, body, 3000);
      return { content: [{ type: "text", text: JSON.stringify({ status: result.status, predicate_js: expr, result }) }] };
    },
  );
}
