/**
 * Memory/module tools — list modules, find exports, read memory.
 * Uses injected JS templates for Frida 17 compatibility.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { sessionManager } from "../state.js";
import { executeTransientScript, resolveAddressJS, truncateResult } from "../utils.js";
import { listModulesJS, findModuleJS, listExportsJS, readMemoryJS, writeMemoryJS, searchMemoryJS } from "../injected/helpers.js";

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

  server.tool(
    "write_memory",
    "Write bytes to a memory address. Automatically adjusts memory protection to allow writing. Supports 'libnative.so+0x1234' notation.",
    {
      session_id: z.string().describe("Session ID"),
      address: z.string().describe("Address: absolute '0x...' or module-relative 'module+0xoffset'"),
      hex_bytes: z.string().describe("Hex string of bytes to write (e.g., '90 90 90' or '909090')"),
    },
    async ({ session_id, address, hex_bytes }) => {
      const session = sessionManager.requireSession(session_id);
      const addrExpr = resolveAddressJS(address);
      const result = await executeTransientScript(
        session.fridaSession,
        writeMemoryJS(addrExpr, hex_bytes),
      );
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    },
  );

  server.tool(
    "search_memory",
    "Search process memory for a hex pattern or string. Scans all readable memory ranges using Memory.scanSync().",
    {
      session_id: z.string().describe("Session ID"),
      pattern: z.string().describe("Search pattern: hex bytes like '48 89 e5' with ?? wildcards, or a text string"),
      pattern_type: z.enum(["hex", "string"]).optional().default("hex").describe("Pattern type: 'hex' for byte pattern, 'string' for text search (default: hex)"),
      max_results: z.number().optional().default(50).describe("Maximum number of matches to return (default: 50)"),
    },
    async ({ session_id, pattern, pattern_type, max_results }) => {
      const session = sessionManager.requireSession(session_id);
      let hexPattern: string;
      if (pattern_type === "string") {
        hexPattern = Array.from(Buffer.from(pattern))
          .map((b) => b.toString(16).padStart(2, "0"))
          .join(" ");
      } else {
        hexPattern = pattern;
      }
      const result = await executeTransientScript(
        session.fridaSession,
        searchMemoryJS(hexPattern, max_results),
        30000,
      );
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    },
  );
}
