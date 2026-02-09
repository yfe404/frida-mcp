import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { existsSync } from "node:fs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const distIndex = join(__dirname, "..", "..", "dist", "index.js");

function sendJsonRpc(child: ReturnType<typeof spawn>, obj: object): void {
  const body = JSON.stringify(obj);
  // MCP stdio transport expects raw JSON lines (no Content-Length header)
  child.stdin!.write(body + "\n");
}

describe("stdio smoke test", () => {
  it("responds to JSON-RPC initialize", async () => {
    if (!existsSync(distIndex)) return;

    const result = await new Promise<string>((resolve, reject) => {
      const child = spawn("node", [distIndex], {
        stdio: ["pipe", "pipe", "pipe"],
      });

      let stdout = "";
      const timer = setTimeout(() => {
        child.kill();
        reject(new Error("Timeout waiting for initialize response"));
      }, 10000);

      child.stdout!.on("data", (chunk: Buffer) => {
        stdout += chunk.toString();
        if (stdout.includes('"result"')) {
          clearTimeout(timer);
          child.kill();
          resolve(stdout);
        }
      });

      child.on("error", (err) => {
        clearTimeout(timer);
        reject(err);
      });

      sendJsonRpc(child, {
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: { name: "test", version: "1.0.0" },
        },
      });
    });

    assert.ok(result.includes('"result"'));
    assert.ok(result.includes("frida"));
  });

  it("lists tools via JSON-RPC", async () => {
    if (!existsSync(distIndex)) return;

    const result = await new Promise<string>((resolve, reject) => {
      const child = spawn("node", [distIndex], {
        stdio: ["pipe", "pipe", "pipe"],
      });

      let stdout = "";
      const timer = setTimeout(() => {
        child.kill();
        reject(new Error("Timeout waiting for tools/list response"));
      }, 10000);

      child.stdout!.on("data", (chunk: Buffer) => {
        stdout += chunk.toString();
        // Wait for both init response and tools response
        const matches = stdout.match(/"id":\s*2/);
        if (matches) {
          clearTimeout(timer);
          child.kill();
          resolve(stdout);
        }
      });

      child.on("error", (err) => {
        clearTimeout(timer);
        reject(err);
      });

      // Send initialize
      sendJsonRpc(child, {
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: { name: "test", version: "1.0.0" },
        },
      });

      // Send initialized notification + tools/list after small delay
      setTimeout(() => {
        sendJsonRpc(child, {
          jsonrpc: "2.0",
          method: "notifications/initialized",
        });
        sendJsonRpc(child, {
          jsonrpc: "2.0",
          id: 2,
          method: "tools/list",
          params: {},
        });
      }, 500);
    });

    assert.ok(result.includes("tools"));
  });
});
