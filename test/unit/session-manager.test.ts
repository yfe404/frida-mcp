import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { SessionManager } from "../../src/state.js";
import type { ManagedSession, ScriptMessage } from "../../src/state.js";

// Minimal mock frida objects
function mockFridaSession(): any {
  return {
    detached: { connect: () => {} },
  };
}

function mockFridaDevice(): any {
  return { id: "mock-device", name: "Mock", type: "usb" };
}

function mockFridaScript(): any {
  return {
    message: { connect: () => {} },
    load: async () => {},
    unload: async () => {},
  };
}

describe("SessionManager", () => {
  let mgr: SessionManager;
  let blobDir: string;

  beforeEach(async () => {
    blobDir = await mkdtemp(join(tmpdir(), "frida-mcp-test-"));
    mgr = new SessionManager({ blobBaseDir: blobDir });
  });

  afterEach(async () => {
    await rm(blobDir, { recursive: true, force: true });
  });

  describe("session ID generation", () => {
    it("generates session IDs with pid prefix", () => {
      const id = mgr.generateSessionId(1234);
      assert.ok(id.startsWith("session_1234_"));
    });

    it("generates unique session IDs", () => {
      const id1 = mgr.generateSessionId(100);
      const id2 = mgr.generateSessionId(100);
      assert.notEqual(id1, id2);
    });
  });

  describe("script ID generation", () => {
    it("generates script IDs with prefix", () => {
      const id = mgr.generateScriptId();
      assert.ok(id.startsWith("script_"));
    });

    it("generates unique script IDs", () => {
      const id1 = mgr.generateScriptId();
      const id2 = mgr.generateScriptId();
      assert.notEqual(id1, id2);
    });
  });

  describe("addSession / getSession", () => {
    it("adds and retrieves a session", () => {
      const session = mgr.addSession("s1", mockFridaSession(), mockFridaDevice(), 42);
      assert.equal(session.id, "s1");
      assert.equal(session.pid, 42);
      const got = mgr.getSession("s1");
      assert.ok(got);
      assert.equal(got!.id, "s1");
    });

    it("returns undefined for unknown session", () => {
      assert.equal(mgr.getSession("nonexistent"), undefined);
    });
  });

  describe("requireSession", () => {
    it("returns session when it exists", () => {
      mgr.addSession("s1", mockFridaSession(), mockFridaDevice(), 42);
      const session = mgr.requireSession("s1");
      assert.equal(session.id, "s1");
    });

    it("throws for unknown session ID", () => {
      assert.throws(
        () => mgr.requireSession("nonexistent"),
        /not found or detached/,
      );
    });
  });

  describe("removeSession", () => {
    it("removes an existing session", () => {
      mgr.addSession("s1", mockFridaSession(), mockFridaDevice(), 42);
      assert.equal(mgr.removeSession("s1"), true);
      assert.equal(mgr.getSession("s1"), undefined);
    });

    it("returns false for nonexistent session", () => {
      assert.equal(mgr.removeSession("nonexistent"), false);
    });
  });

  describe("listSessions", () => {
    it("lists all sessions", () => {
      mgr.addSession("s1", mockFridaSession(), mockFridaDevice(), 1);
      mgr.addSession("s2", mockFridaSession(), mockFridaDevice(), 2);
      const list = mgr.listSessions();
      assert.equal(list.length, 2);
    });
  });

  describe("script management", () => {
    it("adds and retrieves a script", () => {
      mgr.addSession("s1", mockFridaSession(), mockFridaDevice(), 42);
      const script = mgr.addScript("s1", "sc1", mockFridaScript(), "code", true, ["sign"]);
      assert.equal(script.id, "sc1");
      assert.deepEqual(script.rpcExports, ["sign"]);
    });

    it("requireScript throws for unknown script", () => {
      mgr.addSession("s1", mockFridaSession(), mockFridaDevice(), 42);
      assert.throws(
        () => mgr.requireScript("s1", "nonexistent"),
        /not found in session/,
      );
    });

    it("removes a script", () => {
      mgr.addSession("s1", mockFridaSession(), mockFridaDevice(), 42);
      mgr.addScript("s1", "sc1", mockFridaScript(), "code", true);
      assert.equal(mgr.removeScript("s1", "sc1"), true);
      assert.equal(mgr.getScript("s1", "sc1"), undefined);
    });
  });

  describe("message queue", () => {
    it("pushes and peeks messages without clearing", () => {
      mgr.addSession("s1", mockFridaSession(), mockFridaDevice(), 42);
      const msg: ScriptMessage = { type: "send", payload: { test: 1 }, timestamp: Date.now() };
      mgr.pushMessage("s1", msg);
      mgr.pushMessage("s1", { type: "send", payload: { test: 2 }, timestamp: Date.now() });

      const peeked = mgr.peekMessages("s1");
      assert.equal(peeked.length, 2);
      assert.equal((peeked[0].payload as any).test, 1);

      // Queue should remain intact after peek
      assert.equal(mgr.peekMessages("s1").length, 2);
    });

    it("clears all messages and returns cleared count", () => {
      mgr.addSession("s1", mockFridaSession(), mockFridaDevice(), 42);
      mgr.pushMessage("s1", { type: "send", payload: { test: 1 }, timestamp: Date.now() });
      mgr.pushMessage("s1", { type: "send", payload: { test: 2 }, timestamp: Date.now() });

      const cleared = mgr.clearMessages("s1");
      assert.equal(cleared, 2);
      assert.equal(mgr.peekMessages("s1").length, 0);
    });

    it("clears a range of messages for paged acknowledgements", () => {
      mgr.addSession("s1", mockFridaSession(), mockFridaDevice(), 42);
      for (let i = 0; i < 5; i++) {
        mgr.pushMessage("s1", { type: "send", payload: i, timestamp: Date.now() });
      }

      const cleared = mgr.clearMessageRange("s1", 1, 2);
      assert.equal(cleared, 2);
      const remaining = mgr.peekMessages("s1").map((m) => m.payload);
      assert.deepEqual(remaining, [0, 3, 4]);
    });

    it("still supports drain semantics", () => {
      mgr.addSession("s1", mockFridaSession(), mockFridaDevice(), 42);
      mgr.pushMessage("s1", { type: "send", payload: { test: 1 }, timestamp: Date.now() });
      mgr.pushMessage("s1", { type: "send", payload: { test: 2 }, timestamp: Date.now() });

      const drained = mgr.drainMessages("s1");
      assert.equal(drained.length, 2);
      assert.equal(mgr.peekMessages("s1").length, 0);
    });

    it("caps messages at 1000", () => {
      mgr.addSession("s1", mockFridaSession(), mockFridaDevice(), 42);
      for (let i = 0; i < 1100; i++) {
        mgr.pushMessage("s1", { type: "send", payload: i, timestamp: Date.now() });
      }
      const peeked = mgr.peekMessages("s1");
      assert.equal(peeked.length, 1000);
      // Should have the latest messages (100-1099)
      assert.equal(peeked[0].payload, 100);
    });

    it("offloads large payloads to disk and keeps a preview", async () => {
      const big = "x".repeat(500);
      const localMgr = new SessionManager({
        blobBaseDir: blobDir,
        inlinePayloadMaxChars: 20,
        inlineDataMaxBytes: 16,
      });
      localMgr.addSession("s1", mockFridaSession(), mockFridaDevice(), 42);
      localMgr.pushMessage("s1", { type: "send", payload: big, timestamp: Date.now() });

      const [m] = localMgr.peekMessages("s1");
      assert.ok(m);
      assert.equal(typeof m.payload, "string");
      assert.ok((m.payload as string).length <= 20);
      assert.ok(m.payload_blob_id);
      assert.equal(m.payload_size_chars, big.length);

      const onDisk = await readFile(join(blobDir, m.payload_blob_id!), "utf8");
      assert.equal(onDisk, big);
    });

    it("offloads large Buffers to disk and keeps a base64 preview", async () => {
      const buf = Buffer.alloc(64, 0x41); // 'A'
      const localMgr = new SessionManager({
        blobBaseDir: blobDir,
        inlinePayloadMaxChars: 1000,
        inlineDataMaxBytes: 8,
      });
      localMgr.addSession("s1", mockFridaSession(), mockFridaDevice(), 42);
      localMgr.pushMessage("s1", { type: "send", payload: { ok: true }, data: buf, timestamp: Date.now() });

      const [m] = localMgr.peekMessages("s1");
      assert.ok(m);
      assert.equal(typeof m.data_preview_base64, "string");
      assert.ok(m.data_preview_base64.length > 0);
      assert.equal(m.data_size_bytes, buf.length);
      assert.ok(m.data_blob_id);

      const onDisk = await readFile(join(blobDir, m.data_blob_id!));
      assert.equal(onDisk.length, buf.length);
      assert.equal(onDisk[0], 0x41);
    });

    it("returns empty for nonexistent session", () => {
      assert.equal(mgr.peekMessages("nonexistent").length, 0);
      assert.equal(mgr.clearMessages("nonexistent"), 0);
      assert.equal(mgr.clearMessageRange("nonexistent", 0, 10), 0);
    });

    it("ignores push for nonexistent session", () => {
      // Should not throw
      mgr.pushMessage("nonexistent", { type: "send", timestamp: Date.now() });
    });
  });
});
