import { existsSync, mkdirSync, writeFileSync, appendFileSync, createReadStream } from "node:fs";
import { open, stat } from "node:fs/promises";
import { join, relative, resolve } from "node:path";
import { createInterface } from "node:readline";

export interface BlobWriteResult {
  blob_id: string;
  bytes_written: number;
}

export function ensureSessionDirSync(baseDir: string, sessionId: string): string {
  const dir = join(baseDir, sessionId);
  mkdirSync(dir, { recursive: true });
  return dir;
}

export function writeTextBlobSync(
  baseDir: string,
  sessionId: string,
  filename: string,
  content: string,
): BlobWriteResult {
  const dir = ensureSessionDirSync(baseDir, sessionId);
  const fullPath = join(dir, filename);
  writeFileSync(fullPath, content, "utf8");
  return {
    blob_id: `${sessionId}/${filename}`,
    bytes_written: Buffer.byteLength(content, "utf8"),
  };
}

export function writeBinaryBlobSync(
  baseDir: string,
  sessionId: string,
  filename: string,
  data: Buffer,
): BlobWriteResult {
  const dir = ensureSessionDirSync(baseDir, sessionId);
  const fullPath = join(dir, filename);
  writeFileSync(fullPath, data);
  return {
    blob_id: `${sessionId}/${filename}`,
    bytes_written: data.length,
  };
}

export function appendJsonlSync(
  baseDir: string,
  sessionId: string,
  filename: string,
  lines: string[],
): number {
  const dir = ensureSessionDirSync(baseDir, sessionId);
  const fullPath = join(dir, filename);
  const content = lines.map((l) => l.endsWith("\n") ? l : (l + "\n")).join("");
  appendFileSync(fullPath, content, "utf8");
  return Buffer.byteLength(content, "utf8");
}

export function resolveBlobPath(baseDir: string, blobId: string): string {
  // blobId is user-controlled via MCP tools. Keep it a clean relative path and
  // reject traversal (e.g. "s1/../s2/secret") even if it would normalize inside baseDir.
  if (!blobId) throw new Error("Invalid blob_id");
  if (blobId.startsWith("/") || blobId.startsWith("\\")) throw new Error("Invalid blob_id");
  if (blobId.includes("\\") || blobId.includes("\0")) throw new Error("Invalid blob_id");
  const parts = blobId.split("/");
  if (parts.some((p) => p.length === 0 || p === "." || p === "..")) throw new Error("Invalid blob_id");

  const base = resolve(baseDir);
  const full = resolve(baseDir, blobId);
  const rel = relative(base, full);
  if (rel === "" || rel.startsWith("..")) {
    throw new Error("Invalid blob_id");
  }
  return full;
}

export async function readBlobChunk(
  baseDir: string,
  blobId: string,
  offset: number,
  limit: number,
): Promise<{ total_bytes: number; bytes_read: number; chunk: Buffer }> {
  const fullPath = resolveBlobPath(baseDir, blobId);
  const st = await stat(fullPath);
  const total = st.size;
  const start = Math.max(0, offset);
  const remaining = Math.max(0, total - start);
  const toRead = Math.min(Math.max(0, limit), remaining);
  if (toRead === 0) {
    return { total_bytes: total, bytes_read: 0, chunk: Buffer.alloc(0) };
  }

  const fh = await open(fullPath, "r");
  try {
    const buf = Buffer.allocUnsafe(toRead);
    const { bytesRead } = await fh.read(buf, 0, toRead, start);
    return { total_bytes: total, bytes_read: bytesRead, chunk: buf.subarray(0, bytesRead) };
  } finally {
    await fh.close();
  }
}

export async function readJsonlPage(
  filePath: string,
  offset: number,
  limit: number,
): Promise<unknown[]> {
  if (!existsSync(filePath)) return [];
  const messages: unknown[] = [];
  const start = Math.max(0, offset);
  const max = Math.max(0, limit);
  if (max === 0) return [];

  let idx = 0;
  const stream = createReadStream(filePath, { encoding: "utf8" });
  const rl = createInterface({ input: stream, crlfDelay: Infinity });
  try {
    for await (const line of rl) {
      if (idx++ < start) continue;
      if (!line) continue;
      try {
        messages.push(JSON.parse(line));
      } catch {
        // ignore parse errors in corrupted lines
      }
      if (messages.length >= max) break;
    }
  } finally {
    rl.close();
    stream.destroy();
  }
  return messages;
}
