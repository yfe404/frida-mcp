/**
 * Utility functions for device resolution and transient script execution.
 *
 * Key improvement over Python: executeTransientScript uses Promise-based
 * message collection instead of time.sleep(0.2).
 */

import frida from "frida";
import type { Session, Script } from "frida";
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile, access } from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

/**
 * Resolve a Frida device by optional ID, defaulting to USB.
 */
export async function resolveDevice(deviceId?: string): Promise<frida.Device> {
  if (deviceId) {
    return frida.getDevice(deviceId);
  }
  return frida.getUsbDevice();
}

/**
 * Parse an address string that may be absolute ("0x13c7e8") or
 * module-relative ("libnative.so+0x1234").
 * Returns injected JS expression evaluating to a NativePointer.
 */
export function resolveAddressJS(address: string): string {
  if (address.includes("+")) {
    const [mod, offset] = address.split("+", 2);
    return `Process.getModuleByName(${JSON.stringify(mod.trim())}).base.add(${offset.trim()})`;
  }
  return `ptr(${JSON.stringify(address)})`;
}

/**
 * Wrap user JS code in an IIFE that captures the result and sends it back.
 * console.log calls are intercepted and included in the result.
 */
export function wrapForExecution(code: string): string {
  return `(function() {
  var __logs = [];
  var __origLog = console.log;
  console.log = function() {
    var args = Array.prototype.slice.call(arguments);
    var msg = args.map(function(a) {
      return typeof a === "object" ? JSON.stringify(a) : String(a);
    }).join(" ");
    __logs.push(msg);
    __origLog.apply(console, arguments);
  };
  var __result;
  var __error;
  try {
    __result = (function() { ${code} })();
  } catch(e) {
    __error = { message: e.toString(), stack: e.stack };
  }
  console.log = __origLog;
  send({
    type: "execution_receipt",
    result: __error ? undefined : (__result !== undefined ? JSON.stringify(__result) : "undefined"),
    error: __error,
    logs: __logs
  });
})();`;
}

/**
 * Maximum characters for tool output to stay within MCP token limits.
 * MCP hard limit is ~30K chars; we use 24K for a safe margin.
 */
const MAX_RESULT_CHARS = 24000;

/**
 * Serialize data to JSON, truncating if it exceeds MCP limits.
 * For arrays: binary-search for max items that fit, append truncation notice.
 * For other values: slice the JSON string and append a notice.
 */
export function truncateResult(data: unknown, indent?: number): string {
  const full = JSON.stringify(data, null, indent);
  if (full.length <= MAX_RESULT_CHARS) return full;

  if (Array.isArray(data)) {
    let lo = 0;
    let hi = data.length;
    while (lo < hi) {
      const mid = (lo + hi + 1) >>> 1;
      if (JSON.stringify(data.slice(0, mid), null, indent).length <= MAX_RESULT_CHARS - 200) {
        lo = mid;
      } else {
        hi = mid - 1;
      }
    }
    const truncated = data.slice(0, lo);
    return JSON.stringify({
      items: truncated,
      truncated: true,
      showing: lo,
      total: data.length,
      message: `Showing ${lo} of ${data.length} items. Use filter/limit params to narrow results.`,
    }, null, indent);
  }

  return full.slice(0, MAX_RESULT_CHARS - 100) + "\n... [truncated, total " + full.length + " chars]";
}

export interface TransientResult {
  status: "success" | "error";
  result?: string;
  error?: string;
  stack?: string;
  logs: string[];
}

/**
 * Frida 17 scripts run on V8 for parity with modern Frida tooling.
 */
export async function createV8Script(session: Session, source: string): Promise<Script> {
  return session.createScript(source, { runtime: frida.ScriptRuntime.V8 });
}

const javaBridgeEntrypoint = fileURLToPath(
  new URL("../node_modules/frida-java-bridge/index.js", import.meta.url),
);
const compiler = new frida.Compiler();
const javaBundleCache = new Map<string, Promise<string>>();
const javaSymbolPattern = /(^|[^\w$])Java([^\w$]|$)/;

/**
 * Heuristic: source references the Frida Java runtime bridge global.
 */
export function sourceUsesJavaBridge(source: string): boolean {
  return javaSymbolPattern.test(source);
}

async function ensureJavaBridgeInstalled(): Promise<void> {
  try {
    await access(javaBridgeEntrypoint, fsConstants.R_OK);
  } catch {
    throw new Error(
      "frida-java-bridge is not installed. Run: npm install frida-java-bridge",
    );
  }
}

/**
 * Compile source as an ES module that imports frida-java-bridge and exposes
 * it as global Java, compatible with Frida 17 raw createScript workflows.
 */
async function compileJavaBridgeBundle(source: string): Promise<string> {
  const hash = createHash("sha256").update(source).digest("hex");
  const cached = javaBundleCache.get(hash);
  if (cached) {
    return cached;
  }

  const pending = (async () => {
    await ensureJavaBridgeInstalled();

    const dir = await mkdtemp(join(tmpdir(), "frida-mcp-java-bridge-"));
    const entryPath = join(dir, `agent-${hash}.mjs`);
    const entrySource = [
      `import Java from ${JSON.stringify(javaBridgeEntrypoint)};`,
      "globalThis.Java = Java;",
      source,
      "",
    ].join("\n");

    await writeFile(entryPath, entrySource, "utf8");

    try {
      return await compiler.build(entryPath);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  })();

  javaBundleCache.set(hash, pending);
  try {
    return await pending;
  } catch (e) {
    javaBundleCache.delete(hash);
    throw e;
  }
}

/**
 * Create a Frida script with Java bridge preloaded for Frida 17.
 */
export async function createJavaBridgeScript(session: Session, source: string): Promise<Script> {
  const bundle = await compileJavaBridgeBundle(source);
  return createV8Script(session, bundle);
}

/**
 * Execute JS in a Frida session, collect result via Promise (not sleep),
 * then unload the script. Timeout defaults to 5s.
 */
export async function executeTransientScript(
  session: Session,
  code: string,
  timeoutMs = 5000,
): Promise<TransientResult> {
  return executeTransientScriptInternal(session, code, timeoutMs, false);
}

/**
 * Execute JS in a Frida session with the Java bridge preloaded.
 */
export async function executeTransientJavaScript(
  session: Session,
  code: string,
  timeoutMs = 5000,
): Promise<TransientResult> {
  return executeTransientScriptInternal(session, code, timeoutMs, true);
}

async function executeTransientScriptInternal(
  session: Session,
  code: string,
  timeoutMs: number,
  useJavaBridge: boolean,
): Promise<TransientResult> {
  const wrapped = wrapForExecution(code);
  const script: Script = useJavaBridge
    ? await createJavaBridgeScript(session, wrapped)
    : await createV8Script(session, wrapped);

  return new Promise<TransientResult>((resolve) => {
    let settled = false;

    const timer = setTimeout(async () => {
      if (!settled) {
        settled = true;
        try { await script.unload(); } catch {}
        resolve({ status: "error", error: `Timeout after ${timeoutMs}ms`, logs: [] });
      }
    }, timeoutMs);

    script.message.connect(async (message, _data) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);

      try { await script.unload(); } catch {}

      if (message.type === "send") {
        const payload = message.payload as {
          type: string;
          result?: string;
          error?: { message: string; stack?: string };
          logs: string[];
        };

        if (payload.error) {
          resolve({
            status: "error",
            error: payload.error.message,
            stack: payload.error.stack,
            logs: payload.logs || [],
          });
        } else {
          resolve({
            status: "success",
            result: payload.result,
            logs: payload.logs || [],
          });
        }
      } else if (message.type === "error") {
        resolve({
          status: "error",
          error: (message as { description?: string }).description || "Unknown script error",
          logs: [],
        });
      }
    });

    script.load().catch((err) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        resolve({ status: "error", error: String(err), logs: [] });
      }
    });
  });
}
