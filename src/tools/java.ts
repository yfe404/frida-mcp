/**
 * Java tools — enumerate loaded classes, find live instances on heap.
 *
 * Key pattern: find_instances uses Java.choose() + reflection to find
 * live object instances on the heap with full field introspection.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { sessionManager } from "../state.js";
import { executeTransientScript, truncateResult } from "../utils.js";
import { listClassesJS, findInstancesJS } from "../injected/java-helpers.js";

export function registerJavaTools(server: McpServer): void {
  server.tool(
    "list_classes",
    "List loaded Java classes, optionally filtered by substring (max 500 results). Wraps Java.enumerateLoadedClasses().",
    {
      session_id: z.string().describe("Session ID"),
      filter: z.string().optional().describe("Substring filter (case-insensitive)"),
    },
    async ({ session_id, filter }) => {
      const session = sessionManager.requireSession(session_id);
      const result = await executeTransientScript(
        session.fridaSession,
        listClassesJS(filter),
        10000, // class enumeration can be slow
      );
      return { content: [{ type: "text", text: truncateResult(result, 2) }] };
    },
  );

  server.tool(
    "find_instances",
    "Find live Java object instances on the heap using Java.choose(). Reads all fields via reflection, handling primitive types (long, int, boolean) via type-specific getters.",
    {
      session_id: z.string().describe("Session ID"),
      class_name: z.string().describe("Fully qualified class name (e.g., 'com.example.MyClass')"),
      max_instances: z.number().optional().default(5).describe("Max instances to return (default: 5)"),
    },
    async ({ session_id, class_name, max_instances }) => {
      const session = sessionManager.requireSession(session_id);
      const result = await executeTransientScript(
        session.fridaSession,
        findInstancesJS(class_name, max_instances ?? 5),
        15000, // heap scanning can be slow
      );
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    },
  );
}
