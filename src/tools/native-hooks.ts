/**
 * Native hook tools — attach Interceptor hooks, capture backtraces.
 * Supports module+offset address notation for all address parameters.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { sessionManager } from "../state.js";
import { executeTransientScript, resolveAddressJS } from "../utils.js";
import { hookFunctionJS, getBacktraceAsyncJS } from "../injected/hook-templates.js";

export function registerNativeHookTools(server: McpServer): void {
  server.tool(
    "hook_function",
    "Install a persistent Interceptor.attach hook on a native function. Logs arguments and/or return value as messages. Supports 'libnative.so+0x1234' notation.",
    {
      session_id: z.string().describe("Session ID"),
      address: z.string().describe("Address: absolute '0x...' or 'module+0xoffset'"),
      log_args: z.boolean().optional().default(true).describe("Log function arguments (default: true)"),
      log_retval: z.boolean().optional().default(true).describe("Log return value (default: true)"),
      num_args: z.number().optional().default(6).describe("Number of args to capture (default: 6)"),
      script_id: z.string().optional().describe("Custom script ID for this hook"),
    },
    async ({ session_id, address, log_args, log_retval, num_args, script_id }) => {
      const session = sessionManager.requireSession(session_id);
      const hookId = script_id || `hook_${Date.now()}`;
      const addrExpr = resolveAddressJS(address);
      const code = hookFunctionJS(addrExpr, log_args, log_retval, num_args, hookId);

      // Load as persistent script so hook messages accumulate
      const script = await session.fridaSession.createScript(code);
      script.message.connect((message, data: Buffer | null) => {
        sessionManager.pushMessage(session_id, {
          type: message.type,
          payload: message.type === "send" ? message.payload : undefined,
          description: message.type === "error" ? (message as { description?: string }).description : undefined,
          data: data,
          timestamp: Date.now(),
        });
      });
      await script.load();
      sessionManager.addScript(session_id, hookId, script, code, true);

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            status: "success",
            hook_id: hookId,
            address,
            message: `Hook installed. Use get_session_messages to retrieve arg/retval logs. Unload with unload_script('${hookId}').`,
          }),
        }],
      };
    },
  );

  server.tool(
    "get_backtrace",
    "Install a one-shot hook that captures a stack backtrace when the function at the given address is called. Self-detaches after first hit. Check get_session_messages for the frames.",
    {
      session_id: z.string().describe("Session ID"),
      address: z.string().describe("Address: absolute '0x...' or 'module+0xoffset'"),
      style: z.enum(["accurate", "fuzzy"]).optional().default("accurate").describe("Backtrace style (default: accurate)"),
    },
    async ({ session_id, address, style }) => {
      const session = sessionManager.requireSession(session_id);
      const hookId = `bt_${Date.now()}`;
      const addrExpr = resolveAddressJS(address);
      const code = getBacktraceAsyncJS(addrExpr, style, hookId);

      const script = await session.fridaSession.createScript(code);
      script.message.connect((message, data: Buffer | null) => {
        sessionManager.pushMessage(session_id, {
          type: message.type,
          payload: message.type === "send" ? message.payload : undefined,
          description: message.type === "error" ? (message as { description?: string }).description : undefined,
          data: data,
          timestamp: Date.now(),
        });
      });
      await script.load();
      sessionManager.addScript(session_id, hookId, script, code, true);

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            status: "success",
            hook_id: hookId,
            address,
            message: `One-shot backtrace hook installed. Trigger the function, then call get_session_messages for frames.`,
          }),
        }],
      };
    },
  );
}
