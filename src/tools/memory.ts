/**
 * Memory/module tools — list modules, find exports, read memory.
 * Uses injected JS templates for Frida 17 compatibility.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { sessionManager } from "../state.js";
import { executeTransientScript, resolveAddressJS, truncateResult } from "../utils.js";
import { listModulesJS, findModuleJS, listExportsJS, readMemoryJS } from "../injected/helpers.js";

export function registerMemoryTools(server: McpServer): void {
  server.tool(
    "list_modules",
    "List all loaded native modules in the target process (name, base address, size, path)",
    {
      session_id: z.string().describe("Session ID"),
    },
    async ({ session_id }) => {
      const session = sessionManager.requireSession(session_id);
      const result = await executeTransientScript(session.fridaSession, listModulesJS());
      return { content: [{ type: "text", text: truncateResult(result, 2) }] };
    },
  );

  server.tool(
    "find_module",
    "Find a specific native module by name (e.g., 'libc.so')",
    {
      session_id: z.string().describe("Session ID"),
      name: z.string().describe("Module name to find"),
    },
    async ({ session_id, name }) => {
      const session = sessionManager.requireSession(session_id);
      const result = await executeTransientScript(session.fridaSession, findModuleJS(name));
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    },
  );

  server.tool(
    "list_exports",
    "List exported symbols from a native module",
    {
      session_id: z.string().describe("Session ID"),
      module_name: z.string().describe("Module name (e.g., 'libc.so')"),
    },
    async ({ session_id, module_name }) => {
      const session = sessionManager.requireSession(session_id);
      const result = await executeTransientScript(session.fridaSession, listExportsJS(module_name));
      return { content: [{ type: "text", text: truncateResult(result, 2) }] };
    },
  );

  server.tool(
    "read_memory",
    "Read bytes at an address and display as hex dump. Supports 'libnative.so+0x1234' notation.",
    {
      session_id: z.string().describe("Session ID"),
      address: z.string().describe("Address: absolute '0x...' or module-relative 'module+0xoffset'"),
      size: z.number().optional().default(64).describe("Number of bytes to read (default: 64, max: 4096)"),
    },
    async ({ session_id, address, size }) => {
      const session = sessionManager.requireSession(session_id);
      const clampedSize = Math.min(size, 4096);
      const addrExpr = resolveAddressJS(address);
      const result = await executeTransientScript(
        session.fridaSession,
        readMemoryJS(addrExpr, clampedSize),
      );
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    },
  );
}
