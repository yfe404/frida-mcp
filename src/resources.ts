/**
 * MCP Resources — runtime info + Frida API documentation.
 *
 * Runtime resources (ported from Python):
 *   frida://version, frida://processes, frida://devices
 *
 * Doc resources (new, auto-registered from frida-api.json):
 *   frida://docs/index, frida://docs/{topic}, ...
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import frida from "frida";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { docStore } from "./docs/index.js";

function getFridaVersion(): string {
  try {
    const __dirname = dirname(fileURLToPath(import.meta.url));
    const pkgPath = join(__dirname, "..", "node_modules", "frida", "package.json");
    const pkg = JSON.parse(readFileSync(pkgPath, "utf-8"));
    return pkg.version;
  } catch {
    return "unknown";
  }
}

export function registerResources(server: McpServer): void {
  // ── Runtime Resources ──

  server.resource(
    "frida_version",
    "frida://version",
    async (uri) => ({
      contents: [{ uri: uri.href, text: getFridaVersion() }],
    }),
  );

  server.resource(
    "frida_processes",
    "frida://processes",
    async (uri) => {
      try {
        const device = await frida.getUsbDevice();
        const procs = await device.enumerateProcesses();
        const text = procs.map((p) => `PID: ${p.pid}, Name: ${p.name}`).join("\n");
        return { contents: [{ uri: uri.href, text }] };
      } catch (e) {
        return { contents: [{ uri: uri.href, text: `Error: ${e}` }] };
      }
    },
  );

  server.resource(
    "frida_devices",
    "frida://devices",
    async (uri) => {
      const devices = await frida.enumerateDevices();
      const text = devices.map((d) => `ID: ${d.id}, Name: ${d.name}, Type: ${d.type}`).join("\n");
      return { contents: [{ uri: uri.href, text }] };
    },
  );

  // ── Documentation Resources ──

  if (!docStore.isEmpty()) {
    // Index resource listing all sections
    server.resource(
      "docs_index",
      "frida://docs/index",
      async (uri) => {
        const sections = docStore.listSections();
        const text = sections
          .map((s) => `- ${s.id}: ${s.title} [${s.category}]`)
          .join("\n");
        return {
          contents: [{
            uri: uri.href,
            text: `Frida ${docStore.getVersion()} API Documentation Index\n${"=".repeat(50)}\n\n${text}`,
          }],
        };
      },
    );

    // Individual section resources
    for (const { id, title } of docStore.listSections()) {
      server.resource(
        `docs_${id}`,
        `frida://docs/${id}`,
        async (uri) => {
          const section = docStore.getSection(id);
          if (!section) {
            return { contents: [{ uri: uri.href, text: `Section '${id}' not found` }] };
          }
          return {
            contents: [{
              uri: uri.href,
              text: `# ${section.title}\nCategory: ${section.category}\n\n${section.content}`,
            }],
          };
        },
      );
    }
  }
}
