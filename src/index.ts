/**
 * Frida MCP Server (TypeScript) — entry point.
 *
 * Creates an McpServer with 26 tools and ~18 resources, connects via stdio.
 * Tools are organized into 8 modules:
 *   device, process, session, script-mgmt, memory, java, native-hooks, docs
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
