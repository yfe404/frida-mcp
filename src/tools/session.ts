/**
 * Session tools — managed interactive sessions with Promise-based execution.
 *
 * Key improvement over Python: execute_in_session uses Promise-based message
 * collection instead of time.sleep(0.2).
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import {
  resolveDevice,
  executeTransientScript,
  executeTransientJavaScript,
  wrapForExecution,
  truncateResult,
  createV8Script,
  createJavaBridgeScript,
  sourceUsesJavaBridge,
} from "../utils.js";
import { sessionManager } from "../state.js";

function isPTraceLikeAttachError(errorText: string): boolean {
  return /(ptrace|pokedata|permission denied|operation not permitted|i\/o error)/i.test(errorText);
}

async function collectAttachDiagnostics(
  device: Awaited<ReturnType<typeof resolveDevice>>,
  processId: number,
) {
  const result: {
    process_exists?: boolean;
    process_name?: string;
    app_identifier?: string;
    app_name?: string;
    warning?: string;
  } = {};

  try {
    const processes = await device.enumerateProcesses();
    const proc = processes.find((p) => p.pid === processId);
    result.process_exists = !!proc;
    if (proc) {
      result.process_name = proc.name;
    }
  } catch (e) {
    result.warning = `Failed to enumerate processes: ${String(e)}`;
  }

  try {
    const apps = await device.enumerateApplications();
    const app = apps.find((a) => a.pid === processId);
    if (app) {
      result.app_identifier = app.identifier;
      result.app_name = app.name;
    }
  } catch {
    // Some targets don't support app enumeration; ignore.
  }

  return result;
}

function ptraceHints(): string[] {
  return [
    "Verify target PID is still alive.",
    "Run frida-server with sufficient privileges (often root on Android).",
    "Check SELinux policy / anti-debug restrictions on target process.",
    "Verify frida client/server versions are compatible.",
    "Use spawn + attach for hardened targets when live attach is blocked.",
  ];
}

export function registerSessionTools(server: McpServer): void {
  server.tool(
    "create_interactive_session",
    "Attach to a process and create a managed session for script execution. On ptrace-like attach failures, can automatically fall back to spawn+attach.",
    {
      process_id: z.number().describe("PID to attach to"),
      device_id: z.string().optional().describe("Device ID (default: USB)"),
      spawn_fallback: z.boolean().optional().default(false).describe("If attach fails with ptrace-like error, try spawn+attach fallback (default: false)"),
      app_identifier: z.string().optional().describe("Optional app/package identifier to use for spawn fallback"),
      auto_resume_spawned: z.boolean().optional().default(false).describe("Resume the spawned process automatically when fallback succeeds"),
    },
    async ({ process_id, device_id, spawn_fallback, app_identifier, auto_resume_spawned }) => {
      const device = await resolveDevice(device_id);

      try {
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
              fallback_used: false,
              message: `Interactive session created. Use execute_in_session or load_script with session_id '${sessionId}'.`,
            }),
          }],
        };
      } catch (e) {
        const errorText = String(e);
        const diagnostics = await collectAttachDiagnostics(device, process_id);
        const fallbackEligible = spawn_fallback && isPTraceLikeAttachError(errorText);
        const fallbackIdentifier = app_identifier || diagnostics.app_identifier;

        if (fallbackEligible && fallbackIdentifier) {
          try {
            const spawnedPid = await device.spawn(fallbackIdentifier);
            const fridaSession = await device.attach(spawnedPid);
            const sessionId = sessionManager.generateSessionId(spawnedPid);
            sessionManager.addSession(sessionId, fridaSession, device, spawnedPid);

            if (auto_resume_spawned) {
              await device.resume(spawnedPid);
            }

            return {
              content: [{
                type: "text",
                text: JSON.stringify({
                  status: "success",
                  session_id: sessionId,
                  original_process_id: process_id,
                  process_id: spawnedPid,
                  fallback_used: true,
                  fallback_strategy: "spawn_attach",
                  app_identifier: fallbackIdentifier,
                  resumed: auto_resume_spawned,
                  message: auto_resume_spawned
                    ? `Attach to PID ${process_id} failed; spawned '${fallbackIdentifier}' and resumed PID ${spawnedPid}.`
                    : `Attach to PID ${process_id} failed; spawned '${fallbackIdentifier}' and attached to suspended PID ${spawnedPid}. Resume with resume_process.`,
                  diagnostics: {
                    attach_error: errorText,
                    ...diagnostics,
                    hints: ptraceHints(),
                  },
                }),
              }],
            };
          } catch (spawnError) {
            return {
              content: [{
                type: "text",
                text: JSON.stringify({
                  status: "error",
                  error: errorText,
                  fallback_attempted: true,
                  fallback_strategy: "spawn_attach",
                  fallback_identifier: fallbackIdentifier,
                  fallback_error: String(spawnError),
                  diagnostics: {
                    ...diagnostics,
                    hints: ptraceHints(),
                  },
                }),
              }],
            };
          }
        }

        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              status: "error",
              error: errorText,
              fallback_attempted: false,
              spawn_fallback_enabled: spawn_fallback,
              diagnostics: {
                ...diagnostics,
                hints: isPTraceLikeAttachError(errorText) ? ptraceHints() : undefined,
              },
            }),
          }],
        };
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
          const result = sourceUsesJavaBridge(javascript_code)
            ? await executeTransientJavaScript(session.fridaSession, javascript_code)
            : await executeTransientScript(session.fridaSession, javascript_code);
          return { content: [{ type: "text", text: JSON.stringify(result) }] };
        }

        // Persistent: load script, attach message handler, keep alive
        const wrapped = wrapForExecution(javascript_code);
        const script = sourceUsesJavaBridge(javascript_code)
          ? await createJavaBridgeScript(session.fridaSession, wrapped)
          : await createV8Script(session.fridaSession, wrapped);
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
    "Retrieve queued messages from persistent scripts in a session with pagination. By default messages are preserved; use clear_mode to acknowledge returned messages or clear the queue.",
    {
      session_id: z.string().describe("Session ID"),
      limit: z.number().int().nonnegative().optional().default(100).describe("Max messages to return (default: 100)"),
      offset: z.number().int().nonnegative().optional().default(0).describe("Skip first N messages (default: 0)"),
      clear_mode: z.enum(["none", "returned", "all"]).optional().default("none").describe("Message clearing strategy: none=preserve queue, returned=remove only this page, all=clear entire queue"),
    },
    async ({ session_id, limit, offset, clear_mode }) => {
      sessionManager.requireSession(session_id);
      const allMessages = sessionManager.peekMessages(session_id);
      const totalMessages = allMessages.length;
      const page = allMessages.slice(offset, offset + limit);

      let cleared = 0;
      if (clear_mode === "returned") {
        cleared = sessionManager.clearMessageRange(session_id, offset, page.length);
      } else if (clear_mode === "all") {
        cleared = sessionManager.clearMessages(session_id);
      }

      const remaining = sessionManager.peekMessages(session_id).length;
      return {
        content: [{
          type: "text",
          text: truncateResult({
            status: "success",
            session_id,
            messages_retrieved: page.length,
            total_messages: totalMessages,
            offset,
            limit,
            clear_mode,
            messages_cleared: cleared,
            remaining_messages: remaining,
            messages: page,
          }),
        }],
      };
    },
  );
}
