/**
 * Session tools — managed interactive sessions with Promise-based execution.
 *
 * Key improvement over Python: execute_in_session uses Promise-based message
 * collection instead of time.sleep(0.2).
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { resolveDevice, executeTransientScript, wrapForExecution, truncateResult, createV8Script } from "../utils.js";
import { sessionManager } from "../state.js";
import type { ScriptMessage } from "../state.js";

export function registerSessionTools(server: McpServer): void {
  server.tool(
    "create_interactive_session",
    "Attach to a process and create a managed session for script execution. Returns a session_id for use with other tools.",
    {
      process_id: z.number().describe("PID to attach to"),
      device_id: z.string().optional().describe("Device ID (default: USB)"),
    },
    async ({ process_id, device_id }) => {
      try {
        const device = await resolveDevice(device_id);
        const fridaSession = await device.attach(process_id);
        const sessionId = sessionManager.generateSessionId(process_id);
        sessionManager.addSession(sessionId, fridaSession, device, process_id);

        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              status: "success",
              process_id,
              session_id: sessionId,
              message: `Interactive session created. Use execute_in_session or load_script with session_id '${sessionId}'.`,
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: String(e) }) }] };
      }
    },
  );

  server.tool(
    "execute_in_session",
    "Execute JavaScript code in an existing session. Code is wrapped in an IIFE with console.log capture. Result is collected via Promise (no sleep). Set keep_alive=true for persistent scripts (hooks, interceptors).",
    {
      session_id: z.string().describe("Session ID from create_interactive_session"),
      javascript_code: z.string().describe("JavaScript code to execute in target process"),
      keep_alive: z.boolean().optional().default(false).describe("Keep script loaded for persistent hooks (default: false)"),
    },
    async ({ session_id, javascript_code, keep_alive }) => {
      const session = sessionManager.requireSession(session_id);

      try {
        if (!keep_alive) {
          // Transient: execute and unload
          const result = await executeTransientScript(session.fridaSession, javascript_code);
          return { content: [{ type: "text", text: JSON.stringify(result) }] };
        }

        // Persistent: load script, attach message handler, keep alive
        const wrapped = wrapForExecution(javascript_code);
        const script = await createV8Script(session.fridaSession, wrapped);
        const scriptId = sessionManager.generateScriptId();

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
        sessionManager.addScript(session_id, scriptId, script, javascript_code, true);

        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              status: "success",
              script_id: scriptId,
              message: "Script loaded persistently. Use get_session_messages to retrieve async messages.",
              script_unloaded: false,
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: String(e) }) }] };
      }
    },
  );

  server.tool(
    "get_session_messages",
    "Retrieve and clear queued messages from persistent scripts in a session. Use limit/offset for pagination.",
    {
      session_id: z.string().describe("Session ID"),
      limit: z.number().optional().default(100).describe("Max messages to return (default: 100)"),
      offset: z.number().optional().default(0).describe("Skip first N messages (default: 0)"),
    },
    async ({ session_id, limit, offset }) => {
      sessionManager.requireSession(session_id);
      const allMessages = sessionManager.drainMessages(session_id);
      const page = allMessages.slice(offset, offset + limit);
      return {
        content: [{
          type: "text",
          text: truncateResult({
            status: "success",
            session_id,
            messages_retrieved: page.length,
            total_messages: allMessages.length,
            offset,
            limit,
            messages: page,
          }),
        }],
      };
    },
  );
}
