import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

import { registerDeviceTools } from "../../src/tools/device.js";
import { registerProcessTools } from "../../src/tools/process.js";
import { registerSessionTools } from "../../src/tools/session.js";
import { registerScriptMgmtTools } from "../../src/tools/script-mgmt.js";
import { registerMemoryTools } from "../../src/tools/memory.js";
import { registerJavaTools } from "../../src/tools/java.js";
import { registerNativeHookTools } from "../../src/tools/native-hooks.js";
import { registerDocsTools } from "../../src/tools/docs.js";
import { registerAndroidTools } from "../../src/tools/android.js";
import { registerResources } from "../../src/resources.js";

describe("MCP Server Integration", () => {
  let server: McpServer;
  let client: Client;
  let closeTransport: () => Promise<void>;

  beforeEach(async () => {
    server = new McpServer({ name: "frida-test", version: "1.0.0" });

    registerDeviceTools(server);
    registerProcessTools(server);
    registerSessionTools(server);
    registerScriptMgmtTools(server);
    registerMemoryTools(server);
    registerJavaTools(server);
    registerNativeHookTools(server);
    registerDocsTools(server);
    registerAndroidTools(server);
    registerResources(server);

    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

    client = new Client({ name: "test-client", version: "1.0.0" });

    await server.connect(serverTransport);
    await client.connect(clientTransport);

    closeTransport = async () => {
      await client.close();
      await server.close();
    };
  });

  afterEach(async () => {
    await closeTransport();
  });

  describe("tools/list", () => {
    it("returns all 37 tools", async () => {
      const result = await client.listTools();
      assert.equal(result.tools.length, 37);
    });

    it("each tool has description and inputSchema", async () => {
      const result = await client.listTools();
      for (const tool of result.tools) {
        assert.ok(tool.description, `Tool ${tool.name} missing description`);
        assert.ok(tool.inputSchema, `Tool ${tool.name} missing inputSchema`);
      }
    });

    it("includes key tools by name", async () => {
      const result = await client.listTools();
      const names = result.tools.map((t) => t.name);
      assert.ok(names.includes("create_interactive_session"));
      assert.ok(names.includes("execute_in_session"));
      assert.ok(names.includes("hook_function"));
      assert.ok(names.includes("list_modules"));
      assert.ok(names.includes("find_instances"));
      assert.ok(names.includes("search_frida_docs"));
      assert.ok(names.includes("list_methods"));
      assert.ok(names.includes("dump_class"));
      assert.ok(names.includes("run_java"));
      assert.ok(names.includes("android_hook_method"));
      assert.ok(names.includes("write_memory"));
      assert.ok(names.includes("search_memory"));
      assert.ok(names.includes("android_ssl_pinning_disable"));
      assert.ok(names.includes("android_get_current_activity"));
      assert.ok(names.includes("list_apps"));
      assert.ok(names.includes("file_ls"));
      assert.ok(names.includes("file_read"));
    });
  });

  describe("resources/list", () => {
    it("includes runtime resources", async () => {
      const result = await client.listResources();
      const uris = result.resources.map((r) => r.uri);
      assert.ok(uris.includes("frida://version"));
      assert.ok(uris.includes("frida://devices"));
    });
  });

  describe("search_frida_docs", () => {
    it("returns results for valid query", async () => {
      const result = await client.callTool({
        name: "search_frida_docs",
        arguments: { query: "Interceptor" },
      });
      assert.ok(result.content);
      assert.equal(result.content.length, 1);
      const text = (result.content[0] as { text: string }).text;
      // Should return results or no_docs (depending on whether frida-api.json is built)
      const parsed = JSON.parse(text);
      assert.ok(parsed.status === "success" || parsed.status === "no_docs" || parsed.status === "no_results");
    });
  });

  describe("session error handling", () => {
    it("returns error for nonexistent session (execute_in_session)", async () => {
      const result = await client.callTool({
        name: "execute_in_session",
        arguments: { session_id: "nonexistent", javascript_code: "1+1" },
      });
      const text = (result.content[0] as { text: string }).text;
      assert.ok(text.includes("not found") || text.includes("error"));
    });

    it("returns error for nonexistent session (list_modules)", async () => {
      const result = await client.callTool({
        name: "list_modules",
        arguments: { session_id: "nonexistent" },
      });
      const text = (result.content[0] as { text: string }).text;
      assert.ok(text.includes("not found") || text.includes("error"));
    });

    it("returns error for nonexistent session (get_session_messages)", async () => {
      const result = await client.callTool({
        name: "get_session_messages",
        arguments: { session_id: "nonexistent" },
      });
      const text = (result.content[0] as { text: string }).text;
      assert.ok(text.includes("not found") || text.includes("error"));
    });

    it("server stays healthy after error", async () => {
      // Trigger an error
      await client.callTool({
        name: "execute_in_session",
        arguments: { session_id: "bad", javascript_code: "1" },
      });
      // Subsequent call should still work
      const result = await client.listTools();
      assert.equal(result.tools.length, 37);
    });
  });

  describe("resources/read", () => {
    it("reads frida://version resource", async () => {
      const result = await client.readResource({ uri: "frida://version" });
      assert.ok(result.contents);
      assert.ok(result.contents.length > 0);
    });
  });
});
