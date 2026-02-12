/**
 * Documentation tool — keyword search over pre-indexed Frida 17 API docs.
 * Returns paginated, size-safe snippets to fit MCP transport limits.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { docStore } from "../docs/index.js";
import type { DocSection } from "../docs/index.js";
import { truncateResult } from "../utils.js";

const RESPONSE_BUDGET_CHARS = 22000;
const DEFAULT_EXAMPLE_CHARS = 600;
const MIN_SNIPPET_CHARS = 300;
const SNIPPET_SHRINK_STEP = 200;

interface FormattedDocResult {
  id: string;
  title: string;
  category: string;
  snippet: string;
  snippet_truncated: boolean;
  examples: string[];
  examples_truncated: boolean;
}

function tokenizeQuery(query: string): string[] {
  return query
    .toLowerCase()
    .split(/[\s.,:;()+]+/)
    .filter((t) => t.length > 1);
}

function clipText(text: string, maxChars: number): { value: string; truncated: boolean } {
  if (text.length <= maxChars) {
    return { value: text, truncated: false };
  }
  return { value: text.slice(0, Math.max(0, maxChars - 3)).trimEnd() + "...", truncated: true };
}

function makeSnippet(content: string, tokens: string[], maxChars: number): { value: string; truncated: boolean } {
  const normalized = content.replace(/\s+/g, " ").trim();
  if (normalized.length <= maxChars) {
    return { value: normalized, truncated: false };
  }

  const lower = normalized.toLowerCase();
  let hit = -1;
  for (const token of tokens) {
    hit = lower.indexOf(token);
    if (hit !== -1) break;
  }

  const start = hit === -1 ? 0 : Math.max(0, hit - Math.floor(maxChars * 0.35));
  const window = normalized.slice(start, start + maxChars).trim();
  const prefix = start > 0 ? "..." : "";
  const suffix = start + maxChars < normalized.length ? "..." : "";
  return {
    value: prefix + window + suffix,
    truncated: true,
  };
}

function formatSection(
  section: DocSection,
  tokens: string[],
  snippetChars: number,
  includeExamples: boolean,
): FormattedDocResult {
  const snippet = makeSnippet(section.content, tokens, snippetChars);
  const examples: string[] = [];
  let examplesTruncated = false;

  if (includeExamples && section.examples.length > 0) {
    const clipped = clipText(section.examples[0], DEFAULT_EXAMPLE_CHARS);
    examples.push(clipped.value);
    examplesTruncated = clipped.truncated || section.examples.length > 1;
  }

  return {
    id: section.id,
    title: section.title,
    category: section.category,
    snippet: snippet.value,
    snippet_truncated: snippet.truncated,
    examples,
    examples_truncated: examplesTruncated,
  };
}

function buildResponse(
  query: string,
  offset: number,
  limit: number,
  totalMatches: number,
  sections: DocSection[],
  tokens: string[],
  snippetChars: number,
  includeExamples: boolean,
  truncated: boolean,
) {
  const results = sections.map((section) =>
    formatSection(section, tokens, snippetChars, includeExamples),
  );
  const returnedCount = results.length;
  return {
    status: "success",
    query,
    offset,
    limit,
    total_matches: totalMatches,
    returned_count: returnedCount,
    truncated,
    next_offset: offset + returnedCount < totalMatches ? offset + returnedCount : null,
    results,
  };
}

export function registerDocsTools(server: McpServer): void {
  server.tool(
    "search_frida_docs",
    "Search the Frida 17 JavaScript API documentation. Returns paginated snippet results with strict size limits.",
    {
      query: z.string().describe("Search query (e.g., 'Interceptor.attach', 'Java.choose', 'Module.findExportByName')"),
      limit: z.number().int().min(1).max(20).optional().default(5).describe("Max results to return (default: 5, max: 20)"),
      offset: z.number().int().nonnegative().optional().default(0).describe("Result offset for pagination (default: 0)"),
      snippet_chars: z.number().int().min(200).max(3000).optional().default(1000).describe("Max snippet length per result (default: 1000)"),
    },
    async ({ query, limit, offset, snippet_chars }) => {
      if (docStore.isEmpty()) {
        return {
          content: [{
            type: "text",
            text: truncateResult({
              status: "no_docs",
              query,
              offset,
              limit,
              total_matches: 0,
              returned_count: 0,
              truncated: false,
              next_offset: null,
              message: "Frida API docs not built yet. Run: npm run fetch-docs",
            }, 2),
          }],
        };
      }

      const { items, totalMatches } = docStore.searchWithMeta(query, limit, offset);

      if (totalMatches === 0) {
        return {
          content: [{
            type: "text",
            text: truncateResult({
              status: "no_results",
              query,
              offset,
              limit,
              total_matches: 0,
              returned_count: 0,
              truncated: false,
              next_offset: null,
              message: "No matching documentation sections found.",
              available_sections: docStore.listSections().map((s) => s.title),
            }, 2),
          }],
        };
      }

      const tokens = tokenizeQuery(query);
      let includeExamples = true;
      let snippetChars = snippet_chars;
      let truncated = false;

      let response = buildResponse(
        query,
        offset,
        limit,
        totalMatches,
        items,
        tokens,
        snippetChars,
        includeExamples,
        truncated,
      );

      while (JSON.stringify(response).length > RESPONSE_BUDGET_CHARS) {
        if (includeExamples) {
          includeExamples = false;
          truncated = true;
        } else if (snippetChars > MIN_SNIPPET_CHARS) {
          snippetChars = Math.max(MIN_SNIPPET_CHARS, snippetChars - SNIPPET_SHRINK_STEP);
          truncated = true;
        } else if (items.length > 1) {
          items.pop();
          truncated = true;
        } else {
          break;
        }

        response = buildResponse(
          query,
          offset,
          limit,
          totalMatches,
          items,
          tokens,
          snippetChars,
          includeExamples,
          truncated,
        );
      }

      return {
        content: [{
          type: "text",
          text: truncateResult(response, 2),
        }],
      };
    },
  );
}
