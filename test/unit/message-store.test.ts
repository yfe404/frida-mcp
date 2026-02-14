import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { readBlobChunk, resolveBlobPath, writeTextBlobSync } from "../../src/message-store.js";

describe("message-store", () => {
  let baseDir: string;

  beforeEach(async () => {
    baseDir = await mkdtemp(join(tmpdir(), "frida-mcp-msgstore-"));
  });

  afterEach(async () => {
    await rm(baseDir, { recursive: true, force: true });
  });

  it("rejects path traversal in blob ids", () => {
    assert.throws(
      () => resolveBlobPath(baseDir, "../etc/passwd"),
      /Invalid blob_id/,
    );
    assert.throws(
      () => resolveBlobPath(baseDir, "s1/../s2/secret.bin"),
      /Invalid blob_id/,
    );
    assert.throws(
      () => resolveBlobPath(baseDir, "/etc/passwd"),
      /Invalid blob_id/,
    );
  });

  it("reads blob chunks correctly", async () => {
    const content = "hello world";
    const { blob_id } = writeTextBlobSync(baseDir, "s1", "1_payload.json", content);

    const res = await readBlobChunk(baseDir, blob_id, 0, 5);
    assert.equal(res.total_bytes, content.length);
    assert.equal(res.bytes_read, 5);
    assert.equal(res.chunk.toString("utf8"), "hello");
  });
});
