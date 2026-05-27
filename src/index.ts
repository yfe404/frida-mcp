#!/usr/bin/env node
/**
 * Frida MCP Server (TypeScript) — entry point.
 *
 * Creates an McpServer connected via stdio.
 * Tools are organized into modules:
 *   device, process, session, script-mgmt, memory, java, native-hooks, docs,
 *   android, export, bootstrap.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { registerDeviceTools } from "./tools/device.js";
import { registerProcessTools } from "./tools/process.js";
import { registerSessionTools } from "./tools/session.js";
import { registerScriptMgmtTools } from "./tools/script-mgmt.js";
import { registerMemoryTools } from "./tools/memory.js";
import { registerJavaTools } from "./tools/java.js";
import { registerNativeHookTools } from "./tools/native-hooks.js";
import { registerDocsTools } from "./tools/docs.js";
import { registerAndroidTools } from "./tools/android.js";
import { registerExportTools } from "./tools/export.js";
import { registerBootstrapTools } from "./tools/bootstrap.js";
import { registerRecipeTools } from "./tools/recipes.js";
import { registerProcessInventoryTool } from "./tools/process-inventory.js";
import { registerAntiDetectionTools } from "./tools/anti-detection.js";
import { registerResources } from "./resources.js";

async function main() {
  const server = new McpServer({
    name: "frida",
    version: "1.0.0",
  });

  // Register all tool modules
  registerDeviceTools(server);
  registerProcessTools(server);
  registerSessionTools(server);
  registerScriptMgmtTools(server);
  registerMemoryTools(server);
  registerJavaTools(server);
  registerNativeHookTools(server);
  registerDocsTools(server);
  registerAndroidTools(server);
  registerExportTools(server);
  registerBootstrapTools(server);
  registerRecipeTools(server);
  registerProcessInventoryTool(server);
  registerAntiDetectionTools(server);

  // Register resources (runtime + docs)
  registerResources(server);

  // Connect via stdio transport
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
