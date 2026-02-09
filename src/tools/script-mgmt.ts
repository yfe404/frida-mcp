/**
 * Script management tools — load from disk, list, unload, call RPC exports.
 *
 * Load scripts from disk, detect rpc.exports, and invoke them remotely.
 * Scripts with rpc.exports are auto-detected on load.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { readFile } from "node:fs/promises";
import { resolve as pathResolve } from "node:path";
import { sessionManager } from "../state.js";

export function registerScriptMgmtTools(server: McpServer): void {
  server.tool(
    "load_script",
    "Load a Frida JavaScript file from disk into a session. Detects rpc.exports automatically. Use call_rpc_export to invoke exported methods.",
    {
      session_id: z.string().describe("Session ID"),
      file_path: z.string().describe("Path to the JS file to load (absolute or relative to CWD)"),
      script_id: z.string().optional().describe("Custom script ID (auto-generated if omitted)"),
    },
    async ({ session_id, file_path, script_id }) => {
      const session = sessionManager.requireSession(session_id);
      const absPath = pathResolve(file_path);
      const source = await readFile(absPath, "utf-8");
      const sid = script_id || sessionManager.generateScriptId();

      const script = await session.fridaSession.createScript(source);

      // Attach message handler for persistent messages
      script.message.connect((message, data: Buffer | null) => {
        sessionManager.pushMessage(session_id, {
          type: message.type,
          payload: message.type === "send" ? message.payload : undefined,
          description: message.type === "error" ? (message as { description?: string }).description : undefined,
          stack: message.type === "error" ? (message as { stack?: string }).stack : undefined,
          data: data,
          timestamp: Date.now(),
        });
      });

      await script.load();

      // Detect RPC exports by checking the exports proxy
      const rpcExports: string[] = [];
      try {
        // Script exports are available after load. We probe for common patterns.
        // frida-node's script.exports is a proxy — we detect exports by checking
        // if the source contains rpc.exports assignments
        const rpcMatch = source.match(/rpc\.exports\s*=\s*\{([^}]+)\}/s);
        if (rpcMatch) {
          const body = rpcMatch[1];
          const methodMatches = body.matchAll(/(\w+)\s*:\s*function/g);
          for (const m of methodMatches) {
            rpcExports.push(m[1]);
          }
        }
      } catch {}

      sessionManager.addScript(session_id, sid, script, source, true, rpcExports);

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            status: "success",
            script_id: sid,
            file_path: absPath,
            rpc_exports: rpcExports,
            message: rpcExports.length > 0
              ? `Loaded with RPC exports: ${rpcExports.join(", ")}. Use call_rpc_export to invoke.`
              : "Loaded successfully (no RPC exports detected).",
          }),
        }],
      };
    },
  );

  server.tool(
    "list_scripts",
    "List all loaded scripts in a session with their metadata",
    {
      session_id: z.string().describe("Session ID"),
    },
    async ({ session_id }) => {
      const session = sessionManager.requireSession(session_id);
      const scripts = [...session.scripts.values()].map((s) => ({
        id: s.id,
        persistent: s.persistent,
        rpc_exports: s.rpcExports,
        loaded_at: new Date(s.loadedAt).toISOString(),
        source_length: s.source.length,
      }));
      return { content: [{ type: "text", text: JSON.stringify(scripts, null, 2) }] };
    },
  );

  server.tool(
    "unload_script",
    "Unload a script from a session",
    {
      session_id: z.string().describe("Session ID"),
      script_id: z.string().describe("Script ID to unload"),
    },
    async ({ session_id, script_id }) => {
      const managed = sessionManager.requireScript(session_id, script_id);
      await managed.fridaScript.unload();
      sessionManager.removeScript(session_id, script_id);
      return {
        content: [{ type: "text", text: JSON.stringify({ status: "success", unloaded: script_id }) }],
      };
    },
  );

  server.tool(
    "call_rpc_export",
    "Call an RPC-exported method on a loaded script. The script must have rpc.exports defined. Returns the method's return value.",
    {
      session_id: z.string().describe("Session ID"),
      script_id: z.string().describe("Script ID that has the RPC export"),
      method: z.string().describe("Method name to call (e.g., 'sign')"),
      args: z.array(z.unknown()).optional().default([]).describe("Arguments to pass to the method"),
    },
    async ({ session_id, script_id, method, args }) => {
      const managed = sessionManager.requireScript(session_id, script_id);
      try {
        // frida-node exports proxy: script.exports.methodName(...args)
        const exports = managed.fridaScript.exports as Record<string, (...a: unknown[]) => Promise<unknown>>;
        const fn = exports[method];
        if (typeof fn !== "function") {
          return {
            content: [{
              type: "text",
              text: JSON.stringify({ status: "error", error: `No RPC export '${method}' found. Available: ${managed.rpcExports.join(", ") || "none detected"}` }),
            }],
          };
        }
        const result = await fn(...(args || []));
        return {
          content: [{ type: "text", text: JSON.stringify({ status: "success", result }, null, 2) }],
        };
      } catch (e) {
        return {
          content: [{ type: "text", text: JSON.stringify({ status: "error", error: String(e) }) }],
        };
      }
    },
  );
}
