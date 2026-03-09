import { afterEach, beforeEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { sessionManager } from "../../src/state.js";
import { registerExportTools } from "../../src/tools/export.js";

function mockFridaSession(): any {
  return {
    detached: { connect: () => {} },
  };
}

function mockFridaDevice(): any {
  return {
    id: "mock-device",
    name: "Mock Device",
    type: "local",
  };
}

function mockFridaScript(exportsMap: Record<string, (...args: unknown[]) => Promise<unknown>>): any {
  return {
    exports: exportsMap,
  };
}

function uniqueId(prefix: string): string {
  return `${prefix}_${Date.now()}_${Math.random().toString(16).slice(2)}`;
}

describe("export tools", () => {
  let server: McpServer;
  let client: Client;
  let closeTransport: () => Promise<void>;
  let workDir: string;
  const cleanupSessionIds = new Set<string>();

  beforeEach(async () => {
    workDir = await mkdtemp(join(tmpdir(), "frida-export-tools-"));

    server = new McpServer({ name: "frida-export-test", version: "1.0.0" });
    registerExportTools(server);

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

    for (const sessionId of cleanupSessionIds) {
      sessionManager.removeSession(sessionId);
      await rm(join(sessionManager.getBlobBaseDir(), sessionId), { recursive: true, force: true });
    }
    cleanupSessionIds.clear();

    await rm(workDir, { recursive: true, force: true });
  });

  function addSessionWithScript(exportsMap: Record<string, (...args: unknown[]) => Promise<unknown>>) {
    const sessionId = uniqueId("session");
    const scriptId = uniqueId("script");

    cleanupSessionIds.add(sessionId);
    sessionManager.addSession(sessionId, mockFridaSession(), mockFridaDevice(), 1337);
    sessionManager.addScript(
      sessionId,
      scriptId,
      mockFridaScript(exportsMap),
      "rpc.exports = {};",
      true,
      Object.keys(exportsMap),
    );

    return { sessionId, scriptId };
  }

  it("defaults to path_only and offloads large RPC results without duplicating them in the bundle", async () => {
    const largeResult = "x".repeat(2501);
    const { sessionId, scriptId } = addSessionWithScript({
      large: async () => largeResult,
    });
    const outputPath = join(workDir, "large-bundle.jsonl");

    const result = await client.callTool({
      name: "export_capture_bundle",
      arguments: {
        session_id: sessionId,
        rpc: { script_id: scriptId, method: "large", args: [] },
        include_messages: false,
        output_path: outputPath,
      },
    });

    const text = (result.content[0] as { text: string }).text;
    const parsed = JSON.parse(text);
    assert.equal(parsed.response_detail, "path_only");
    assert.equal(parsed.rpc_summary.status, "success");
    assert.equal(typeof parsed.rpc_summary.blob_id, "string");
    assert.ok(!("inline_preview" in parsed.rpc_summary));
    assert.ok(!text.includes(largeResult.slice(0, 64)));

    const lines = (await readFile(outputPath, "utf8")).trim().split("\n").map((line) => JSON.parse(line));
    const rpcRecord = lines.find((line) => line.kind === "rpc_result");
    assert.ok(rpcRecord);
    assert.equal(rpcRecord.result_blob_id, parsed.rpc_summary.blob_id);
    assert.ok(!("result_json" in rpcRecord));
    assert.equal(typeof rpcRecord.result_preview, "string");
    assert.equal(rpcRecord.result_preview_truncated, true);

    const blobPath = join(sessionManager.getBlobBaseDir(), rpcRecord.result_blob_id);
    const blobContent = await readFile(blobPath, "utf8");
    assert.equal(blobContent, largeResult);
  });

  it("supports compact responses while exporting RPC output and queued messages together", async () => {
    const { sessionId, scriptId } = addSessionWithScript({
      small: async () => ({ ok: true, nested: { value: 7 } }),
    });
    const outputPath = join(workDir, "compact-bundle.jsonl");

    sessionManager.pushMessage(sessionId, {
      type: "send",
      payload: { event: "hook_hit", args: [1, 2, 3] },
      timestamp: Date.now(),
    });

    const result = await client.callTool({
      name: "export_capture_bundle",
      arguments: {
        session_id: sessionId,
        rpc: { script_id: scriptId, method: "small", args: [] },
        include_messages: true,
        clear_mode: "returned",
        output_path: outputPath,
        response_detail: "compact",
      },
    });

    const parsed = JSON.parse((result.content[0] as { text: string }).text);
    assert.equal(parsed.response_detail, "compact");
    assert.equal(parsed.rpc_summary.status, "success");
    assert.match(parsed.rpc_summary.inline_preview, /"ok":true/);
    assert.equal(parsed.messages_summary.in_memory_exported, 1);
    assert.equal(parsed.messages_summary.messages_cleared, 1);
    assert.equal(sessionManager.peekMessages(sessionId).length, 0);
    assert.ok(Array.isArray(parsed.next_steps));

    const lines = (await readFile(outputPath, "utf8")).trim().split("\n").map((line) => JSON.parse(line));
    const rpcRecord = lines.find((line) => line.kind === "rpc_result");
    const messageRecord = lines.find((line) => line.kind === "message");
    assert.ok(rpcRecord);
    assert.deepEqual(rpcRecord.result_json, "{\"ok\":true,\"nested\":{\"value\":7}}");
    assert.ok(messageRecord);
    assert.equal(messageRecord.source, "inmem");
    assert.equal(messageRecord.message.payload.event, "hook_hit");
  });

  it("writes durable RPC error records when the requested export method is missing", async () => {
    const { sessionId, scriptId } = addSessionWithScript({
      existing: async () => "ok",
    });
    const outputPath = join(workDir, "missing-rpc.jsonl");

    const result = await client.callTool({
      name: "export_capture_bundle",
      arguments: {
        session_id: sessionId,
        rpc: { script_id: scriptId, method: "missing", args: [] },
        include_messages: false,
        output_path: outputPath,
      },
    });

    const parsed = JSON.parse((result.content[0] as { text: string }).text);
    assert.equal(parsed.status, "error");
    assert.equal(parsed.rpc_summary.status, "error");
    assert.match(parsed.rpc_summary.error, /No RPC export 'missing' found/);

    const lines = (await readFile(outputPath, "utf8")).trim().split("\n").map((line) => JSON.parse(line));
    const errorRecord = lines.find((line) => line.kind === "rpc_error");
    assert.ok(errorRecord);
    assert.equal(errorRecord.method, "missing");
    assert.match(errorRecord.error, /No RPC export 'missing' found/);
  });
});
