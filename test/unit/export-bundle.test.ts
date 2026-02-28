import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  appendJsonlRecordSync,
  ensureParentDirSync,
  makeSafeFileStem,
  resolveExportPath,
  serializeForExport,
} from "../../src/export-bundle.js";

describe("resolveExportPath", () => {
  it("creates a default path under session exports when output_path is omitted", () => {
    const now = new Date("2026-02-28T12:34:56.789Z");
    const resolved = resolveExportPath("/tmp/frida-blobs", "session_1", undefined, now);
    assert.equal(resolved.generatedDefault, true);
    assert.equal(
      resolved.outputPath,
      "/tmp/frida-blobs/session_1/exports/2026-02-28T12-34-56-789Z-bundle.jsonl",
    );
  });

  it("uses provided output path when supplied", () => {
    const resolved = resolveExportPath("/tmp/frida-blobs", "session_1", "./out/custom.jsonl");
    assert.equal(resolved.generatedDefault, false);
    assert.ok(resolved.outputPath.endsWith("/out/custom.jsonl"));
  });
});

describe("appendJsonlRecordSync", () => {
  it("writes newline-delimited JSON records", async () => {
    const dir = await mkdtemp(join(tmpdir(), "frida-export-test-"));
    try {
      const file = join(dir, "bundle", "records.jsonl");
      ensureParentDirSync(file);

      const b1 = appendJsonlRecordSync(file, { kind: "meta", ok: true });
      const b2 = appendJsonlRecordSync(file, { kind: "message", seq: 1 });

      assert.ok(b1 > 0);
      assert.ok(b2 > 0);
      const content = await readFile(file, "utf8");
      const lines = content.trim().split("\n");
      assert.equal(lines.length, 2);
      assert.equal(JSON.parse(lines[0]).kind, "meta");
      assert.equal(JSON.parse(lines[1]).seq, 1);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("serializeForExport", () => {
  it("returns string input unchanged", () => {
    assert.equal(serializeForExport("{\"a\":1}"), "{\"a\":1}");
  });

  it("stringifies objects", () => {
    assert.equal(serializeForExport({ a: 1 }), "{\"a\":1}");
  });

  it("handles undefined values", () => {
    assert.equal(serializeForExport(undefined), "undefined");
  });
});

describe("makeSafeFileStem", () => {
  it("normalizes unsafe chars", () => {
    assert.equal(makeSafeFileStem("script id/with spaces", "fallback"), "script_id_with_spaces");
  });

  it("uses fallback for fully invalid input", () => {
    assert.equal(makeSafeFileStem("////", "fallback"), "fallback");
  });
});
