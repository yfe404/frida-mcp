import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { createReadStream, existsSync } from "node:fs";
import { createInterface } from "node:readline";
import { appendJsonlRecordSync, ensureParentDirSync, makeSafeFileStem, resolveExportPath, serializeForExport } from "../export-bundle.js";
import { writeTextBlobSync } from "../message-store.js";
import { sessionManager } from "../state.js";
import { truncateResult } from "../utils.js";

const RPC_PREVIEW_MAX_CHARS = 1200;
const RPC_BLOB_THRESHOLD_CHARS = 2000;
type ResponseDetail = "path_only" | "compact";

const rpcRequestSchema = z.object({
  script_id: z.string().describe("Script ID that has the RPC export"),
  method: z.string().describe("RPC export method to call"),
  args: z.array(z.unknown()).optional().default([]).describe("Arguments to pass to the RPC export"),
});

function buildRpcSummary(
  responseDetail: ResponseDetail,
  summary: {
    status: "success" | "error";
    script_id: string;
    method: string;
    error?: string;
    result_size_chars?: number;
    blob_id?: string;
    inline_preview?: string;
  },
): Record<string, unknown> {
  const out: Record<string, unknown> = {
    status: summary.status,
    script_id: summary.script_id,
    method: summary.method,
  };

  if (summary.status === "error") {
    out.error = summary.error ?? "Unknown RPC export error";
    return out;
  }

  if (summary.result_size_chars !== undefined) {
    out.result_size_chars = summary.result_size_chars;
  }
  if (summary.blob_id) {
    out.blob_id = summary.blob_id;
  }
  if (responseDetail === "compact" && summary.inline_preview !== undefined) {
    out.inline_preview = summary.inline_preview;
  }
  return out;
}

export function registerExportTools(server: McpServer): void {
  server.tool(
    "export_capture_bundle",
    "Export RPC output and captured session messages to a disk JSONL bundle. Designed for large payloads and token-safe extraction.",
    {
      session_id: z.string().describe("Session ID"),
      rpc: rpcRequestSchema.optional().nullable().describe("Optional RPC export call to include"),
      include_messages: z.boolean().optional().default(true).describe("Include in-memory queued session messages"),
      include_archived_messages: z.boolean().optional().default(false).describe("Include archived session messages from disk"),
      clear_mode: z.enum(["none", "returned", "all"]).optional().default("none").describe("How to clear in-memory messages after export"),
      output_path: z.string().optional().describe("Optional output file path. Defaults under session blob directory."),
      format: z.enum(["jsonl"]).optional().default("jsonl").describe("Bundle format (v1 supports jsonl only)"),
      response_detail: z.enum(["path_only", "compact"]).optional().default("path_only").describe("How much detail to return in the MCP response. path_only keeps results slim; compact adds previews."),
    },
    async ({ session_id, rpc, include_messages, include_archived_messages, clear_mode, output_path, format, response_detail }) => {
      sessionManager.requireSession(session_id);

      const resolved = resolveExportPath(sessionManager.getBlobBaseDir(), session_id, output_path);
      ensureParentDirSync(resolved.outputPath);

      let recordsWritten = 0;
      let bytesWritten = 0;
      const appendRecord = (record: unknown): void => {
        bytesWritten += appendJsonlRecordSync(resolved.outputPath, record);
        recordsWritten += 1;
      };

      appendRecord({
        kind: "meta",
        event: "bundle_start",
        ts: Date.now(),
        session_id,
        format,
        include_messages,
        include_archived_messages,
        clear_mode,
        rpc_requested: !!rpc,
      });

      let rpcSummary: Record<string, unknown> | null = null;

      if (rpc) {
        try {
          const managed = sessionManager.requireScript(session_id, rpc.script_id);
          const exportsProxy = managed.fridaScript.exports as Record<string, (...a: unknown[]) => Promise<unknown>>;
          const fn = exportsProxy[rpc.method];

          if (typeof fn !== "function") {
            const errorText = `No RPC export '${rpc.method}' found. Available: ${managed.rpcExports.join(", ") || "none detected"}`;
            appendRecord({
              kind: "rpc_error",
              ts: Date.now(),
              session_id,
              script_id: rpc.script_id,
              method: rpc.method,
              args: rpc.args,
              error: errorText,
            });
            rpcSummary = {
              status: "error",
              script_id: rpc.script_id,
              method: rpc.method,
              error: errorText,
            };
          } else {
            const result = await fn(...rpc.args);
            const resultJson = serializeForExport(result);
            const resultSizeChars = resultJson.length;
            const preview = resultJson.slice(0, RPC_PREVIEW_MAX_CHARS);

            let blobId: string | undefined;
            if (resultSizeChars > RPC_BLOB_THRESHOLD_CHARS) {
              const scriptStem = makeSafeFileStem(rpc.script_id, "script");
              const methodStem = makeSafeFileStem(rpc.method, "method");
              const blobName = `${Date.now()}_${scriptStem}_${methodStem}_rpc_result.json`;
              const blobWrite = writeTextBlobSync(
                sessionManager.getBlobBaseDir(),
                session_id,
                blobName,
                resultJson,
              );
              blobId = blobWrite.blob_id;
            }

            const rpcRecord: Record<string, unknown> = {
              kind: "rpc_result",
              ts: Date.now(),
              session_id,
              script_id: rpc.script_id,
              method: rpc.method,
              args: rpc.args,
              result_size_chars: resultSizeChars,
            };
            if (blobId) {
              rpcRecord.result_blob_id = blobId;
              rpcRecord.result_preview = preview;
              rpcRecord.result_preview_truncated = preview.length < resultSizeChars;
            } else {
              rpcRecord.result_json = resultJson;
            }
            appendRecord(rpcRecord);

            rpcSummary = buildRpcSummary(response_detail, {
              status: "success",
              script_id: rpc.script_id,
              method: rpc.method,
              result_size_chars: resultSizeChars,
              inline_preview: preview,
              blob_id: blobId,
            });
          }
        } catch (e) {
          appendRecord({
            kind: "rpc_error",
            ts: Date.now(),
            session_id,
            script_id: rpc.script_id,
            method: rpc.method,
            args: rpc.args,
            error: String(e),
          });
          rpcSummary = buildRpcSummary(response_detail, {
            status: "error",
            script_id: rpc.script_id,
            method: rpc.method,
            error: String(e),
          });
        }
      }

      let inMemoryExported = 0;
      let archivedExported = 0;
      let messagesCleared = 0;

      if (include_messages) {
        const messages = sessionManager.peekMessages(session_id);
        inMemoryExported = messages.length;

        for (const msg of messages) {
          appendRecord({
            kind: "message",
            source: "inmem",
            ts: Date.now(),
            session_id,
            message: msg,
          });
        }

        if (clear_mode === "returned" && inMemoryExported > 0) {
          messagesCleared = sessionManager.clearMessageRange(session_id, 0, inMemoryExported);
        } else if (clear_mode === "all") {
          messagesCleared = sessionManager.clearMessages(session_id);
        }
      }

      if (include_archived_messages) {
        const archivePath = sessionManager.getArchivePath(session_id);
        if (existsSync(archivePath)) {
          const stream = createReadStream(archivePath, { encoding: "utf8" });
          const rl = createInterface({ input: stream, crlfDelay: Infinity });
          try {
            for await (const line of rl) {
              if (!line) continue;
              let parsed: unknown = line;
              try {
                parsed = JSON.parse(line);
              } catch {
                // Preserve raw text if a line is malformed.
              }
              appendRecord({
                kind: "message",
                source: "archive",
                ts: Date.now(),
                session_id,
                message: parsed,
              });
              archivedExported += 1;
            }
          } finally {
            rl.close();
            stream.destroy();
          }
        }
      }

      appendRecord({
        kind: "meta",
        event: "bundle_complete",
        ts: Date.now(),
        session_id,
        records_written: recordsWritten,
        bytes_written: bytesWritten,
        in_memory_messages_exported: inMemoryExported,
        archived_messages_exported: archivedExported,
      });

      const hasRpcError = rpcSummary?.status === "error";
      const hasMessageData = inMemoryExported > 0 || archivedExported > 0;
      const status = hasRpcError
        ? (hasMessageData ? "partial_success" : "error")
        : "success";

      const response: Record<string, unknown> = {
        status,
        session_id,
        format,
        response_detail,
        output_path: resolved.outputPath,
        generated_default_path: resolved.generatedDefault,
        records_written: recordsWritten,
        bytes_written: bytesWritten,
        messages_summary: {
          in_memory_exported: inMemoryExported,
          archived_exported: archivedExported,
          messages_cleared: messagesCleared,
          clear_mode_applied: include_messages ? clear_mode : "none",
        },
      };
      if (rpcSummary) {
        response.rpc_summary = rpcSummary;
      }
      if (response_detail === "compact") {
        response.next_steps = [
          `Read bundle: ${resolved.outputPath}`,
          "Use read_session_message_blob when bundle records include blob ids.",
        ];
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
