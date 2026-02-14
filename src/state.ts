/**
 * SessionManager — singleton managing all Frida sessions, scripts, and messages.
 * Replaces the Python server's 4 separate global dicts with a unified state.
 */

import type frida from "frida";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  appendJsonlSync,
  writeBinaryBlobSync,
  writeTextBlobSync,
} from "./message-store.js";

export interface ScriptMessage {
  type: string;
  payload?: unknown;
  description?: string;
  stack?: string;
  data?: Buffer | null;
  timestamp: number;
}

export interface StoredScriptMessage {
  id: string;
  seq: number;
  type: string;
  timestamp: number;

  // Safe preview only; full content may be offloaded to disk and referenced by blob ids.
  payload?: unknown;
  payload_blob_id?: string;
  payload_size_chars?: number;

  description?: string;
  stack?: string;

  data_preview_base64?: string;
  data_blob_id?: string;
  data_size_bytes?: number;

  truncated_fields?: string[];
  offload_error?: string;
}

export interface ManagedScript {
  id: string;
  fridaScript: frida.Script;
  source: string;
  persistent: boolean;
  rpcExports: string[];
  loadedAt: number;
}

export interface ManagedSession {
  id: string;
  fridaSession: frida.Session;
  device: frida.Device;
  pid: number;
  scripts: Map<string, ManagedScript>;
  messages: StoredScriptMessage[];
  nextMessageSeq: number;
  archivedCount: number;
  archiveFile: string;
  diskBytes: number;
  offloadDisabled: boolean;
  archiveDisabled: boolean;
  createdAt: number;
}

let nextSessionNum = 1;
let nextScriptNum = 1;

export interface SessionManagerOptions {
  blobBaseDir: string;
  maxInmemMessages: number;
  inlinePayloadMaxChars: number;
  inlineDataMaxBytes: number;
  maxDiskBytesPerSession: number;
  maxErrorTextChars: number;
}

function envInt(name: string, def: number): number {
  const raw = process.env[name];
  if (!raw) return def;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) ? n : def;
}

export class SessionManager {
  private sessions = new Map<string, ManagedSession>();
  private readonly opts: SessionManagerOptions;

  constructor(opts?: Partial<SessionManagerOptions>) {
    const blobBaseDir = opts?.blobBaseDir
      ?? process.env.FRIDA_MCP_BLOB_DIR
      ?? join(tmpdir(), "frida-mcp-blobs");

    this.opts = {
      blobBaseDir,
      maxInmemMessages: opts?.maxInmemMessages ?? envInt("FRIDA_MCP_MAX_INMEM_MESSAGES", 1000),
      inlinePayloadMaxChars: opts?.inlinePayloadMaxChars ?? envInt("FRIDA_MCP_INLINE_PAYLOAD_MAX_CHARS", 2000),
      inlineDataMaxBytes: opts?.inlineDataMaxBytes ?? envInt("FRIDA_MCP_INLINE_DATA_MAX_BYTES", 256),
      maxDiskBytesPerSession: opts?.maxDiskBytesPerSession ?? envInt("FRIDA_MCP_MAX_DISK_BYTES_PER_SESSION", 200 * 1024 * 1024),
      maxErrorTextChars: opts?.maxErrorTextChars ?? envInt("FRIDA_MCP_MAX_ERROR_TEXT_CHARS", 4000),
    };
  }

  generateSessionId(pid: number): string {
    return `session_${pid}_${nextSessionNum++}`;
  }

  generateScriptId(): string {
    return `script_${nextScriptNum++}`;
  }

  addSession(
    id: string,
    fridaSession: frida.Session,
    device: frida.Device,
    pid: number,
  ): ManagedSession {
    const managed: ManagedSession = {
      id,
      fridaSession,
      device,
      pid,
      scripts: new Map(),
      messages: [],
      nextMessageSeq: 1,
      archivedCount: 0,
      archiveFile: "archive.jsonl",
      diskBytes: 0,
      offloadDisabled: false,
      archiveDisabled: false,
      createdAt: Date.now(),
    };
    this.sessions.set(id, managed);

    // Auto-cleanup on detach
    fridaSession.detached.connect(() => {
      this.sessions.delete(id);
    });

    return managed;
  }

  getSession(id: string): ManagedSession | undefined {
    return this.sessions.get(id);
  }

  requireSession(id: string): ManagedSession {
    const s = this.sessions.get(id);
    if (!s) throw new Error(`Session '${id}' not found or detached`);
    return s;
  }

  listSessions(): ManagedSession[] {
    return [...this.sessions.values()];
  }

  removeSession(id: string): boolean {
    return this.sessions.delete(id);
  }

  addScript(
    sessionId: string,
    scriptId: string,
    fridaScript: frida.Script,
    source: string,
    persistent: boolean,
    rpcExports: string[] = [],
  ): ManagedScript {
    const session = this.requireSession(sessionId);
    const managed: ManagedScript = {
      id: scriptId,
      fridaScript,
      source,
      persistent,
      rpcExports,
      loadedAt: Date.now(),
    };
    session.scripts.set(scriptId, managed);
    return managed;
  }

  getScript(sessionId: string, scriptId: string): ManagedScript | undefined {
    return this.sessions.get(sessionId)?.scripts.get(scriptId);
  }

  requireScript(sessionId: string, scriptId: string): ManagedScript {
    const s = this.getScript(sessionId, scriptId);
    if (!s) throw new Error(`Script '${scriptId}' not found in session '${sessionId}'`);
    return s;
  }

  removeScript(sessionId: string, scriptId: string): boolean {
    return this.sessions.get(sessionId)?.scripts.delete(scriptId) ?? false;
  }

  pushMessage(sessionId: string, msg: ScriptMessage): void {
    const session = this.sessions.get(sessionId);
    if (session) {
      const seq = session.nextMessageSeq++;
      const stored = this.sanitizeAndOffloadMessage(session, seq, msg);
      session.messages.push(stored);

      // Cap messages to prevent unbounded growth; evicted messages are archived.
      const max = Math.max(0, this.opts.maxInmemMessages);
      if (max > 0 && session.messages.length > max) {
        const evictCount = session.messages.length - max;
        const evicted = session.messages.splice(0, evictCount);
        this.archiveMessages(session, evicted);
      }
    }
  }

  peekMessages(sessionId: string): StoredScriptMessage[] {
    const session = this.sessions.get(sessionId);
    if (!session) return [];
    return [...session.messages];
  }

  clearMessages(sessionId: string): number {
    const session = this.sessions.get(sessionId);
    if (!session) return 0;
    const toClear = session.messages.slice();
    const cleared = toClear.length;
    this.archiveMessages(session, toClear);
    session.messages.length = 0;
    return cleared;
  }

  clearMessageRange(sessionId: string, offset: number, count: number): number {
    const session = this.sessions.get(sessionId);
    if (!session) return 0;
    if (count <= 0) return 0;

    const start = Math.max(0, Math.min(offset, session.messages.length));
    const size = Math.max(0, Math.min(count, session.messages.length - start));
    if (size === 0) return 0;

    const removed = session.messages.splice(start, size);
    this.archiveMessages(session, removed);
    return removed.length;
  }

  drainMessages(sessionId: string): StoredScriptMessage[] {
    const msgs = this.peekMessages(sessionId);
    this.clearMessages(sessionId);
    return msgs;
  }

  getBlobBaseDir(): string {
    return this.opts.blobBaseDir;
  }

  getArchivePath(sessionId: string): string {
    const session = this.requireSession(sessionId);
    return join(this.opts.blobBaseDir, session.id, session.archiveFile);
  }

  getArchivedCount(sessionId: string): number {
    const session = this.requireSession(sessionId);
    return session.archivedCount;
  }

  private hasDiskBudget(session: ManagedSession, bytesToWrite: number): boolean {
    const max = Math.max(0, this.opts.maxDiskBytesPerSession);
    if (max === 0) return false;
    if (session.diskBytes + bytesToWrite > max) return false;
    return true;
  }

  private archiveMessages(session: ManagedSession, msgs: StoredScriptMessage[]): void {
    if (session.archiveDisabled) return;
    if (msgs.length === 0) return;

    const lines: string[] = [];
    for (const m of msgs) {
      lines.push(JSON.stringify(m));
    }

    const estimatedBytes = lines.reduce((acc, l) => acc + Buffer.byteLength(l, "utf8") + 1, 0);
    if (!this.hasDiskBudget(session, estimatedBytes)) {
      session.archiveDisabled = true;
      return;
    }

    try {
      const bytesAppended = appendJsonlSync(
        this.opts.blobBaseDir,
        session.id,
        session.archiveFile,
        lines,
      );
      session.diskBytes += bytesAppended;
      session.archivedCount += msgs.length;
    } catch {
      session.archiveDisabled = true;
    }
  }

  private sanitizeAndOffloadMessage(
    session: ManagedSession,
    seq: number,
    msg: ScriptMessage,
  ): StoredScriptMessage {
    const truncated_fields: string[] = [];
    const stored: StoredScriptMessage = {
      id: `msg_${seq}`,
      seq,
      type: msg.type,
      timestamp: msg.timestamp,
    };

    // Payload: keep inline if small; otherwise offload and keep a short preview.
    if (msg.payload !== undefined) {
      try {
        const payloadJson = typeof msg.payload === "string" ? msg.payload : JSON.stringify(msg.payload);
        stored.payload_size_chars = payloadJson.length;

        if (!session.offloadDisabled && payloadJson.length > this.opts.inlinePayloadMaxChars) {
          const preview = payloadJson.slice(0, Math.max(0, this.opts.inlinePayloadMaxChars));
          stored.payload = preview;
          truncated_fields.push("payload");

          const bytes = Buffer.byteLength(payloadJson, "utf8");
          if (this.hasDiskBudget(session, bytes)) {
            try {
              const res = writeTextBlobSync(
                this.opts.blobBaseDir,
                session.id,
                `${seq}_payload.json`,
                payloadJson,
              );
              stored.payload_blob_id = res.blob_id;
              session.diskBytes += res.bytes_written;
            } catch (e) {
              stored.offload_error = String(e);
            }
          } else {
            stored.offload_error = "Disk quota exceeded; payload not offloaded";
            session.offloadDisabled = true;
          }
        } else {
          stored.payload = msg.payload;
        }
      } catch (e) {
        stored.payload = "[unserializable payload]";
        stored.offload_error = String(e);
        truncated_fields.push("payload");
      }
    }

    // Error strings can be huge; keep bounded previews.
    if (msg.description) {
      if (msg.description.length > this.opts.maxErrorTextChars) {
        stored.description = msg.description.slice(0, this.opts.maxErrorTextChars);
        truncated_fields.push("description");
      } else {
        stored.description = msg.description;
      }
    }
    if (msg.stack) {
      if (msg.stack.length > this.opts.maxErrorTextChars) {
        stored.stack = msg.stack.slice(0, this.opts.maxErrorTextChars);
        truncated_fields.push("stack");
      } else {
        stored.stack = msg.stack;
      }
    }

    // Data: never keep Buffer inline (serializes to massive JSON). Store a base64 preview and offload full bytes if large.
    const dataBuf = msg.data ?? null;
    if (dataBuf) {
      stored.data_size_bytes = dataBuf.length;
      const previewBytes = Math.max(0, this.opts.inlineDataMaxBytes);
      const head = dataBuf.subarray(0, previewBytes);
      stored.data_preview_base64 = head.toString("base64");
      if (dataBuf.length > previewBytes) {
        truncated_fields.push("data");
      }

      if (!session.offloadDisabled && dataBuf.length > previewBytes) {
        const bytes = dataBuf.length;
        if (this.hasDiskBudget(session, bytes)) {
          try {
            const res = writeBinaryBlobSync(
              this.opts.blobBaseDir,
              session.id,
              `${seq}_data.bin`,
              dataBuf,
            );
            stored.data_blob_id = res.blob_id;
            session.diskBytes += res.bytes_written;
          } catch (e) {
            stored.offload_error = String(e);
          }
        } else {
          stored.offload_error = "Disk quota exceeded; data not offloaded";
          session.offloadDisabled = true;
        }
      }
    }

    if (truncated_fields.length > 0) stored.truncated_fields = truncated_fields;
    return stored;
  }
}

// Singleton
export const sessionManager = new SessionManager();
