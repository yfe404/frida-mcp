/**
 * Documentation tool — keyword search over pre-indexed Frida 17 API docs.
 * Returns full section content so Claude can use the API correctly.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { docStore } from "../docs/index.js";

export function registerDocsTools(server: McpServer): void {
  server.tool(
    "search_frida_docs",
    "Search the Frida 17 JavaScript API documentation. Returns matching sections with full content and examples. Use this to look up API signatures, parameters, and Frida 17 migration patterns.",
    {
      query: z.string().describe("Search query (e.g., 'Interceptor.attach', 'Java.choose', 'Module.findExportByName')"),
      limit: z.number().optional().default(5).describe("Max results to return (default: 5)"),
    },
    async ({ query, limit }) => {
      if (docStore.isEmpty()) {
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              status: "no_docs",
              message: "Frida API docs not built yet. Run: npm run fetch-docs",
            }),
          }],
        };
      }

      const results = docStore.search(query, limit);

      if (results.length === 0) {
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              status: "no_results",
              query,
              message: "No matching documentation sections found.",
              available_sections: docStore.listSections().map((s) => s.title),
            }),
          }],
        };
      }

      const formatted = results.map((s) => ({
        id: s.id,
        title: s.title,
        category: s.category,
        content: s.content,
        examples: s.examples,
      }));

      return {
        content: [{
          type: "text",
          text: JSON.stringify({ status: "success", query, results: formatted }, null, 2),
        }],
      };
    },
  );
}
