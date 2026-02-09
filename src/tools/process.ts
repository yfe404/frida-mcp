/**
 * Process tools — enumerate, find, attach, spawn, resume, kill.
 * Ported from Python cli.py. Default device = USB.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { resolveDevice, truncateResult } from "../utils.js";

export function registerProcessTools(server: McpServer): void {
  server.tool(
    "enumerate_processes",
    "List all running processes on a device (default: USB)",
    {
      device_id: z.string().optional().describe("Device ID (default: USB)"),
    },
    async ({ device_id }) => {
      const device = await resolveDevice(device_id);
      const procs = await device.enumerateProcesses();
      const result = procs.map((p) => ({ pid: p.pid, name: p.name }));
      return { content: [{ type: "text", text: truncateResult(result, 2) }] };
    },
  );

  server.tool(
    "get_process_by_name",
    "Find a process by name (case-insensitive substring match)",
    {
      name: z.string().describe("Process name or substring to search for"),
      device_id: z.string().optional().describe("Device ID (default: USB)"),
    },
    async ({ name, device_id }) => {
      const device = await resolveDevice(device_id);
      const procs = await device.enumerateProcesses();
      const needle = name.toLowerCase();
      const match = procs.find((p) => p.name.toLowerCase().includes(needle));
      if (match) {
        return {
          content: [{ type: "text", text: JSON.stringify({ pid: match.pid, name: match.name, found: true }) }],
        };
      }
      return {
        content: [{ type: "text", text: JSON.stringify({ found: false, error: `Process '${name}' not found` }) }],
      };
    },
  );

  server.tool(
    "attach_to_process",
    "Attach Frida to a process by PID",
    {
      pid: z.number().describe("Process ID to attach to"),
      device_id: z.string().optional().describe("Device ID (default: USB)"),
    },
    async ({ pid, device_id }) => {
      try {
        const device = await resolveDevice(device_id);
        const session = await device.attach(pid);
        // We don't store the session here — use create_interactive_session for managed sessions
        // This is a lightweight attach check, matching the Python behavior
        return {
          content: [{
            type: "text",
            text: JSON.stringify({ pid, success: true, note: "Use create_interactive_session for a managed session with script execution." }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ success: false, error: String(e) }) }] };
      }
    },
  );

  server.tool(
    "spawn_process",
    "Spawn a new process (e.g., app package name on Android)",
    {
      program: z.string().describe("Program or package identifier to spawn"),
      args: z.array(z.string()).optional().describe("Arguments for the program"),
      device_id: z.string().optional().describe("Device ID (default: USB)"),
    },
    async ({ program, args, device_id }) => {
      const device = await resolveDevice(device_id);
      const pid = await device.spawn(program, { argv: args });
      return { content: [{ type: "text", text: JSON.stringify({ pid }) }] };
    },
  );

  server.tool(
    "resume_process",
    "Resume a spawned/suspended process by PID",
    {
      pid: z.number().describe("Process ID to resume"),
      device_id: z.string().optional().describe("Device ID (default: USB)"),
    },
    async ({ pid, device_id }) => {
      const device = await resolveDevice(device_id);
      await device.resume(pid);
      return { content: [{ type: "text", text: JSON.stringify({ success: true, pid }) }] };
    },
  );

  server.tool(
    "kill_process",
    "Kill a process by PID",
    {
      pid: z.number().describe("Process ID to kill"),
      device_id: z.string().optional().describe("Device ID (default: USB)"),
    },
    async ({ pid, device_id }) => {
      const device = await resolveDevice(device_id);
      await device.kill(pid);
      return { content: [{ type: "text", text: JSON.stringify({ success: true, pid }) }] };
    },
  );
}
