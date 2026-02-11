/**
 * Android-specific tools — SSL pinning bypass, activity introspection,
 * app enumeration, and file operations on target device.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { sessionManager } from "../state.js";
import { resolveDevice, executeTransientScript, truncateResult, createV8Script } from "../utils.js";
import {
  sslPinningDisableJS,
  getCurrentActivityJS,
  fileLsJS,
  fileReadJS,
} from "../injected/java-helpers.js";

export function registerAndroidTools(server: McpServer): void {
  server.tool(
    "android_ssl_pinning_disable",
    "Bypass SSL certificate pinning by installing a custom TrustManager that accepts all certificates. Hooks SSLContext.init, HttpsURLConnection, OkHttp3 CertificatePinner, and TrustManagerImpl.",
    {
      session_id: z.string().describe("Session ID"),
      script_id: z.string().optional().describe("Custom script ID"),
    },
    async ({ session_id, script_id }) => {
      const session = sessionManager.requireSession(session_id);
      const id = script_id || `ssl_bypass_${Date.now()}`;
      const code = sslPinningDisableJS();

      const script = await createV8Script(session.fridaSession, code);
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
      sessionManager.addScript(session_id, id, script, code, true);

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            status: "success",
            script_id: id,
            message: `SSL pinning bypass installed. Check get_session_messages for details on what was hooked. Unload with unload_script('${id}').`,
          }),
        }],
      };
    },
  );

  server.tool(
    "android_get_current_activity",
    "Get the current foreground Android activity name and package via ActivityThread reflection",
    {
      session_id: z.string().describe("Session ID"),
    },
    async ({ session_id }) => {
      const session = sessionManager.requireSession(session_id);
      const result = await executeTransientScript(
        session.fridaSession,
        getCurrentActivityJS(),
        5000,
      );
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    },
  );

  server.tool(
    "list_apps",
    "List installed applications on the device (identifier, name, running PID)",
    {
      device_id: z.string().optional().describe("Device ID (default: USB)"),
    },
    async ({ device_id }) => {
      const device = await resolveDevice(device_id);
      const apps = await device.enumerateApplications();
      const result = apps.map((a) => ({
        identifier: a.identifier,
        name: a.name,
        pid: a.pid,
      }));
      return { content: [{ type: "text", text: truncateResult(result, 2) }] };
    },
  );

  server.tool(
    "file_ls",
    "List directory contents on the target device (uses Java File API, requires Java runtime)",
    {
      session_id: z.string().describe("Session ID"),
      path: z.string().describe("Directory path on the target device"),
    },
    async ({ session_id, path }) => {
      const session = sessionManager.requireSession(session_id);
      const result = await executeTransientScript(
        session.fridaSession,
        fileLsJS(path),
        10000,
      );
      return { content: [{ type: "text", text: truncateResult(result, 2) }] };
    },
  );

  server.tool(
    "file_read",
    "Read a text file from the target device (uses Java Scanner, requires Java runtime)",
    {
      session_id: z.string().describe("Session ID"),
      path: z.string().describe("File path on the target device"),
      max_size: z.number().optional().default(65536).describe("Maximum file size in bytes (default: 64KB)"),
    },
    async ({ session_id, path, max_size }) => {
      const session = sessionManager.requireSession(session_id);
      const result = await executeTransientScript(
        session.fridaSession,
        fileReadJS(path, max_size),
        10000,
      );
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    },
  );
}
