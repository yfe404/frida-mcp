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
 *
 * The wrapper:
 *   - Intercepts `console.log` so the host receives any traces alongside the result.
 *   - Awaits a Promise return value before emitting the receipt — necessary
 *     because frida-java-bridge 7.x APIs like Java.enumerateLoadedClasses are
 *     object-callback based and the natural pattern in injected JS is to
 *     return a Promise that resolves in onComplete.
 *   - Reports thrown / rejected errors with stack on the same channel.
 *
 * Two public entry points reflect the two valid code shapes:
 *   - `wrapForExecution(code)`     — statement-form. The caller's `code` may
 *                                    use `var x = …; return x;`. This is the
 *                                    public contract for `execute_in_session`.
 *   - `wrapExpressionForExecution(expr)` — expression-form. The wrapper
 *                                    propagates the expression value. Used by
 *                                    internal builders that emit IIFEs.
 *
 * Both share the same outer wrapper; only the "inner body" differs.
 */
function makeExecutionWrapper(innerBody: string): string {
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
  function __sendReceipt(payload) {
    console.log = __origLog;
    send({
      type: "execution_receipt",
      result: payload.result,
      error: payload.error,
      logs: __logs
    });
  }
  function __serialize(v) {
    return v !== undefined ? JSON.stringify(v) : "undefined";
  }
  try {
    var __result = (function() { ${innerBody} })();
    if (__result && typeof __result.then === "function") {
      __result.then(function(v) {
        __sendReceipt({ result: __serialize(v) });
      }, function(e) {
        __sendReceipt({ error: { message: e && e.toString ? e.toString() : String(e), stack: e && e.stack } });
      });
    } else {
      __sendReceipt({ result: __serialize(__result) });
    }
  } catch(e) {
    __sendReceipt({ error: { message: e.toString(), stack: e.stack } });
  }
})();`;
}

/**
 * Statement-form wrapper. The caller is expected to provide one or more JS
 * statements; surface a value by ending with `return X;`. An empty body
 * resolves to `undefined`.
 */
export function wrapForExecution(code: string): string {
  const trimmed = code.trim();
  const innerBody = trimmed.length === 0 ? "return undefined;" : code;
  return makeExecutionWrapper(innerBody);
}

/**
 * Expression-form wrapper. The caller provides a single JS expression — most
 * often an IIFE like `(function(){...})()`. The expression's value
 * (including any returned Promise) is propagated to the receipt. Trailing
 * semicolons are stripped so `(X)();` survives the `return (…)` interpolation.
 */
export function wrapExpressionForExecution(expr: string): string {
  const trimmed = expr.trim();
  if (trimmed.length === 0) {
    return makeExecutionWrapper("return undefined;");
  }
  const exprBody = trimmed.replace(/;\s*$/, "");
  return makeExecutionWrapper(`return (${exprBody});`);
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
const javaBridgePackageJson = fileURLToPath(
  new URL("../node_modules/frida-java-bridge/package.json", import.meta.url),
);

/**
 * Resolve the installed frida-java-bridge version once at module-load and
 * prefix it onto bundle cache keys. Without this, a `npm install` that bumps
 * the bridge would silently serve a stale compiled bundle from the in-memory
 * cache for the lifetime of the MCP server process.
 */
function readJavaBridgeVersion(): string {
  try {
    // Use sync `readFileSync` via the already-imported `readFileSync` helper —
    // we're at module init, an extra sync read is fine and avoids racing the
    // first compile call.
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { readFileSync } = require("node:fs") as typeof import("node:fs");
    const text = readFileSync(javaBridgePackageJson, "utf8");
    const parsed = JSON.parse(text) as { version?: unknown };
    return typeof parsed.version === "string" ? parsed.version : "unknown";
  } catch {
    return "unknown";
  }
}
const javaBridgeVersion = readJavaBridgeVersion();

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
  // Cache key includes the bridge version so a dep bump cannot serve a stale
  // bundle. Same `source` against bridge 7.0.12 vs 7.0.13 must compile twice.
  const hash = createHash("sha256")
    .update(`v=${javaBridgeVersion}\n`)
    .update(source)
    .digest("hex");
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
 * Execute statement-style JS in a Frida session, collect result via Promise
 * (not sleep), then unload the script. Timeout defaults to 5s.
 *
 * "Statement-style" means the caller's `code` is a sequence of statements
 * surfaced via `return X;` — the public `execute_in_session` contract.
 * For builder JS (which is naturally an IIFE expression), use
 * `executeTransientExpression` / `executeTransientExpressionJava` instead.
 */
export async function executeTransientScript(
  session: Session,
  code: string,
  timeoutMs = 5000,
): Promise<TransientResult> {
  return executeTransientScriptInternal(session, wrapForExecution(code), timeoutMs, false);
}

/**
 * Statement-style execution with the Java bridge preloaded.
 */
export async function executeTransientJavaScript(
  session: Session,
  code: string,
  timeoutMs = 5000,
): Promise<TransientResult> {
  return executeTransientScriptInternal(session, wrapForExecution(code), timeoutMs, true);
}

/**
 * Expression-style execution. Caller provides a single JS expression — most
 * builders emit `(function () { … })()`. The expression's value (a value or
 * a Promise) is returned via the receipt.
 */
export async function executeTransientExpression(
  session: Session,
  expr: string,
  timeoutMs = 5000,
): Promise<TransientResult> {
  return executeTransientScriptInternal(session, wrapExpressionForExecution(expr), timeoutMs, false);
}

/**
 * Expression-style execution with the Java bridge preloaded — the form most
 * `*JS` builders in `src/injected/` should target.
 */
export async function executeTransientExpressionJava(
  session: Session,
  expr: string,
  timeoutMs = 5000,
): Promise<TransientResult> {
  return executeTransientScriptInternal(session, wrapExpressionForExecution(expr), timeoutMs, true);
}

async function executeTransientScriptInternal(
  session: Session,
  wrapped: string,
  timeoutMs: number,
  useJavaBridge: boolean,
): Promise<TransientResult> {
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
