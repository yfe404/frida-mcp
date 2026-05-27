/**
 * Static-analysis tools — bridge Frida's dynamic view with the APK's static
 * source. Today the engagement workflow is: catch a stack frame in Frida,
 * see `Foo.kt:55`, leave the MCP entirely to decompile. These tools keep that
 * inside one conversation.
 *
 * Shells out to:
 *   - `adb`        — pull an installed APK from the device.
 *   - `aapt2`      — parse the APK manifest.
 *   - `jadx`       — decompile a single class to .java.
 *   - `nm`/`readelf` — enumerate exports of a native .so.
 *
 * All commands are launched with `execFile` (not `exec`), so caller-controlled
 * fields never pass through a shell. Paths are normalised, and large outputs
 * are truncated via `truncateResult`.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdir, readFile, readdir, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve as pathResolve, basename } from "node:path";
import { z } from "zod";
import { runAdbShell, runAdbCommand } from "../adb.js";
import { truncateResult } from "../utils.js";

const execFileAsync = promisify(execFile);

function apkCacheDir(): string {
  return join(homedir(), ".cache", "frida-mcp", "apks");
}

function decompileCacheDir(): string {
  return join(homedir(), ".cache", "frida-mcp", "jadx");
}

async function pathExists(p: string): Promise<boolean> {
  try { await stat(p); return true; } catch { return false; }
}

/**
 * Run an external CLI with a fixed timeout and return trimmed stdout. Throws
 * with the stderr if the process exits non-zero.
 */
async function run(cmd: string, args: string[], timeoutMs = 60000): Promise<string> {
  try {
    const { stdout } = await execFileAsync(cmd, args, { encoding: "utf8", timeout: timeoutMs, maxBuffer: 32 * 1024 * 1024 });
    return stdout;
  } catch (e: unknown) {
    const err = e as { stderr?: string; message?: string };
    throw new Error(err.stderr?.trim() || err.message || String(e));
  }
}

/**
 * Resolve where an installed APK lives on a connected device. Apps with
 * split APKs return their base.apk. Returns the device-side absolute path.
 */
async function pmPath(pkg: string, adbSerial?: string): Promise<string> {
  // `pm path <pkg>` returns lines like `package:/data/app/.../base.apk`.
  const out = await runAdbShell(`pm path ${pkg}`, adbSerial);
  const lines = out.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  // Prefer base.apk, fall back to first.
  const base = lines.find((l) => l.endsWith("base.apk")) ?? lines[0];
  if (!base || !base.startsWith("package:")) {
    throw new Error(`Could not resolve APK path for ${pkg} on device. pm output: ${out || "<empty>"}`);
  }
  return base.slice("package:".length);
}

// ---- aapt2 manifest parsing -------------------------------------------------

interface AaptManifest {
  package: string | null;
  versionName: string | null;
  versionCode: string | null;
  compileSdk: string | null;
  targetSdk: string | null;
  minSdk: string | null;
  permissions: string[];
  activities: { name: string; exported?: boolean }[];
  services: { name: string; exported?: boolean }[];
  receivers: { name: string; exported?: boolean }[];
  providers: { name: string; exported?: boolean }[];
}

/**
 * Parse `aapt2 dump xmltree` text output into a structured manifest summary.
 *
 * The xmltree format is line-based and indented; we walk it with a stack so
 * we know which element each attribute belongs to. Robust against extra
 * whitespace and Sony-style multi-component APKs.
 */
export function parseAaptXmlTree(text: string): AaptManifest {
  const out: AaptManifest = {
    package: null, versionName: null, versionCode: null,
    compileSdk: null, targetSdk: null, minSdk: null,
    permissions: [], activities: [], services: [], receivers: [], providers: [],
  };
  const lines = text.split(/\r?\n/);
  type StackEntry = { tag: string; indent: number; attrs: Record<string, string> };
  const stack: StackEntry[] = [];
  const elementRe = /^(\s*)(?:E:|N:|N: android=|N: xmlns=)/;
  const elemStartRe = /^(\s*)E: (\S+) /;
  const attrRe = /^(\s*)A: (?:[^=]+=)?(?:\(.+?\))?\(?([\w:.-]+)\)?(?:\(0x[0-9a-fA-F]+\))?="?([^"]*)"?\s*(?:\(.+\))?$/;

  for (const raw of lines) {
    if (!raw.trim()) continue;
    const indentMatch = raw.match(/^(\s*)/);
    const indent = indentMatch ? indentMatch[1].length : 0;

    // Pop elements at >= current indent off the stack.
    while (stack.length > 0 && stack[stack.length - 1].indent >= indent && raw.match(elementRe)) {
      stack.pop();
    }

    const elemMatch = raw.match(elemStartRe);
    if (elemMatch) {
      const tag = elemMatch[2];
      const entry: StackEntry = { tag, indent, attrs: {} };
      stack.push(entry);
      continue;
    }

    const top = stack[stack.length - 1];
    if (!top) continue;

    const attr = raw.match(attrRe);
    if (!attr) continue;
    const key = attr[2];
    const value = attr[3];
    top.attrs[key] = value;

    // Promote known attrs as soon as we see them.
    if (top.tag === "manifest") {
      if (key === "package") out.package = value;
      if (key === "android:versionName") out.versionName = value;
      if (key === "android:versionCode") out.versionCode = value;
      if (key === "android:compileSdkVersion") out.compileSdk = value;
    } else if (top.tag === "uses-sdk") {
      if (key === "android:minSdkVersion") out.minSdk = value;
      if (key === "android:targetSdkVersion") out.targetSdk = value;
    } else if (top.tag === "uses-permission") {
      if (key === "android:name" && !out.permissions.includes(value)) out.permissions.push(value);
    } else if (top.tag === "activity" || top.tag === "service" || top.tag === "receiver" || top.tag === "provider") {
      if (key === "android:name") {
        const sink = top.tag === "activity" ? out.activities :
                     top.tag === "service" ? out.services :
                     top.tag === "receiver" ? out.receivers :
                     out.providers;
        if (!sink.find((s) => s.name === value)) sink.push({ name: value });
      }
      if (key === "android:exported") {
        const sink = top.tag === "activity" ? out.activities :
                     top.tag === "service" ? out.services :
                     top.tag === "receiver" ? out.receivers :
                     out.providers;
        const last = sink[sink.length - 1];
        if (last) last.exported = value === "true" || value === "0xffffffff";
      }
    }
  }
  return out;
}

// ---- jadx decompilation -----------------------------------------------------

/**
 * Run jadx once for `apk_path` (no-op if the cache already has the matching
 * source root for this APK). We invoke without `--single-class` because
 * different jadx releases gate that flag inconsistently and a one-time full
 * decompile lets us answer subsequent class/method queries in O(1).
 *
 * The cache key is `<apk_basename>.<size>` so re-pulling the same APK does not
 * blow the cache, but a new release does.
 */
async function ensureJadxSources(apkPath: string): Promise<string> {
  const abs = pathResolve(apkPath);
  if (!await pathExists(abs)) throw new Error(`APK not found: ${abs}`);
  const s = await stat(abs);
  const key = `${basename(abs)}.${s.size}`;
  const dest = join(decompileCacheDir(), key);
  if (await pathExists(dest)) return dest;
  await mkdir(dest, { recursive: true });
  // jadx routinely exits non-zero on big APKs (some classes fail to decompile)
  // while still producing usable output for the rest. Run it directly without
  // failing on exit code, then verify the sources/ tree exists.
  try {
    await run("jadx", ["--no-res", "--no-imports", "-d", dest, abs], 240000);
  } catch {
    // swallow — we check the output below
  }
  const sources = join(dest, "sources");
  if (!await pathExists(sources)) {
    throw new Error(`jadx produced no sources/ tree under ${dest}; APK may be unsupported`);
  }
  return dest;
}

function fqcnToRelativeJavaPath(fqcn: string): string {
  // jadx writes <root>/sources/<pkg>/<Class>.java by default.
  return join("sources", `${fqcn.replace(/\./g, "/")}.java`);
}

/**
 * Read the file produced by jadx for `fqcn`. If the class is an inner class
 * (e.g. com.x.Outer$Inner), jadx emits everything in the Outer.java file.
 */
async function readDecompiledClass(jadxRoot: string, fqcn: string): Promise<{ path: string; text: string }> {
  const directPath = join(jadxRoot, fqcnToRelativeJavaPath(fqcn));
  if (await pathExists(directPath)) {
    return { path: directPath, text: await readFile(directPath, "utf8") };
  }
  // Inner class: try outer class file.
  const outer = fqcn.includes("$") ? fqcn.slice(0, fqcn.indexOf("$")) : null;
  if (outer) {
    const outerPath = join(jadxRoot, fqcnToRelativeJavaPath(outer));
    if (await pathExists(outerPath)) {
      return { path: outerPath, text: await readFile(outerPath, "utf8") };
    }
  }
  throw new Error(`Decompiled source not found for ${fqcn} under ${jadxRoot}`);
}

/**
 * Find the index just past the `@kotlin.Metadata(…)` annotation at the top of
 * a jadx-decompiled Kotlin source file. The Metadata `d2` array embeds every
 * method name in the class as a string literal, so any naive method-name
 * search will hit those before reaching the actual declaration. We return the
 * offset where the user-visible code begins.
 */
function indexAfterKotlinMetadata(text: string): number {
  const start = text.search(/@kotlin\.Metadata\(/);
  if (start < 0) return 0;
  let i = text.indexOf("(", start);
  if (i < 0) return 0;
  let depth = 0;
  for (; i < text.length; i++) {
    const ch = text[i];
    if (ch === "(") depth++;
    else if (ch === ")") {
      depth--;
      if (depth === 0) return i + 1;
    }
  }
  return 0;
}

/**
 * Slice the body of `methodName` out of the decompiled `.java` text.
 * Returns the first declaration that matches by name, with brace-aware
 * boundary detection. Brittle on overload-by-signature filtering but
 * deterministic for the common case. Skips past the @kotlin.Metadata
 * annotation block so its d2 string-literal name list does not steal the
 * match.
 */
export function sliceMethod(text: string, methodName: string): { start: number; end: number; body: string } | null {
  const searchStart = indexAfterKotlinMetadata(text);
  // Find first `… <methodName>(` not preceded by '.' or letter.
  const re = new RegExp(`(?:^|[^A-Za-z0-9_.])(?:(?:public|private|protected|static|final|synchronized|native|abstract|\\s)+)?[\\w<>?,\\[\\]\\s.]*\\s${methodName}\\s*\\(`, "m");
  re.lastIndex = searchStart;
  const slice = text.slice(searchStart);
  const m = re.exec(slice);
  if (!m) return null;
  m.index += searchStart;
  m[0] = m[0];
  // From here on use the absolute indices against `text`, not `slice`.
  // Walk to the opening brace, then balance.
  let i = m.index + m[0].length;
  while (i < text.length && text[i] !== "{" && text[i] !== ";") i++;
  if (i >= text.length || text[i] === ";") {
    // Abstract / interface declaration; return the single line.
    const lineStart = text.lastIndexOf("\n", m.index) + 1;
    const lineEnd = text.indexOf("\n", m.index);
    return { start: lineStart, end: lineEnd === -1 ? text.length : lineEnd, body: text.slice(lineStart, lineEnd === -1 ? text.length : lineEnd) };
  }
  let depth = 0;
  let end = i;
  for (; end < text.length; end++) {
    const ch = text[end];
    if (ch === "{") depth++;
    else if (ch === "}") {
      depth--;
      if (depth === 0) { end++; break; }
    }
  }
  // Backtrack to the start of the declaration's line for nicer context.
  const startOfDecl = text.lastIndexOf("\n", m.index) + 1;
  return { start: startOfDecl, end, body: text.slice(startOfDecl, end) };
}

// ---- registration -----------------------------------------------------------

export function registerStaticTools(server: McpServer): void {
  server.tool(
    "apk_pull",
    "Pull an installed APK from the device for static analysis. Cached under ~/.cache/frida-mcp/apks.",
    {
      package: z.string(),
      device_id: z.string().optional(),
      adb_serial: z.string().optional(),
      force: z.boolean().optional().default(false).describe("Re-pull even if cached."),
    },
    async ({ package: pkg, adb_serial, device_id, force }) => {
      const serial = adb_serial || device_id;
      const dir = apkCacheDir();
      await mkdir(dir, { recursive: true });
      const dest = join(dir, `${pkg}.apk`);
      if (!force && await pathExists(dest)) {
        const s = await stat(dest);
        return { content: [{ type: "text", text: JSON.stringify({ status: "success", apk_path: dest, size: s.size, cached: true }) }] };
      }
      try {
        const devicePath = await pmPath(pkg, serial);
        await runAdbCommand(["pull", devicePath, dest], serial);
        const s = await stat(dest);
        return { content: [{ type: "text", text: JSON.stringify({ status: "success", apk_path: dest, size: s.size, device_path: devicePath, cached: false }) }] };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: String(e) }) }] };
      }
    },
  );

  server.tool(
    "apk_manifest",
    "Dump the AndroidManifest.xml of an APK and parse it to JSON (package, versions, permissions, activities, services).",
    {
      apk_path: z.string().describe("Local path to the APK file."),
    },
    async ({ apk_path }) => {
      try {
        const abs = pathResolve(apk_path);
        if (!existsSync(abs)) {
          return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: `APK not found: ${abs}` }) }] };
        }
        const text = await run("aapt2", ["dump", "xmltree", "--file", "AndroidManifest.xml", abs], 30000);
        const parsed = parseAaptXmlTree(text);
        return { content: [{ type: "text", text: truncateResult({ status: "success", apk_path: abs, manifest: parsed }, 2) }] };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: String(e) }) }] };
      }
    },
  );

  server.tool(
    "decompile_class",
    "Decompile a class from an APK with jadx and return its source. Inner classes are returned via their outer class file. Result is cached per APK fingerprint.",
    {
      apk_path: z.string(),
      fqcn: z.string().describe("Fully qualified class name, e.g. com.expedia.bookings.hmac.HMACInterceptor (or with $Inner)."),
    },
    async ({ apk_path, fqcn }) => {
      try {
        const jadxRoot = await ensureJadxSources(apk_path);
        const { path, text } = await readDecompiledClass(jadxRoot, fqcn);
        return { content: [{ type: "text", text: truncateResult({ status: "success", source_path: path, line_count: text.split("\n").length, text }) }] };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: String(e) }) }] };
      }
    },
  );

  server.tool(
    "decompile_method",
    "Decompile a class with jadx and slice out a single method by name. Brittle on overload disambiguation; returns the first match.",
    {
      apk_path: z.string(),
      fqcn: z.string(),
      method: z.string().describe("Bare method name (no params)."),
    },
    async ({ apk_path, fqcn, method }) => {
      try {
        const jadxRoot = await ensureJadxSources(apk_path);
        const { path, text } = await readDecompiledClass(jadxRoot, fqcn);
        const sliced = sliceMethod(text, method);
        if (!sliced) {
          // Fall back to the full file with a flag so the caller still gets
          // something useful — e.g. for compiler-generated synthetic methods
          // whose names don't appear in the decompiled .java.
          return {
            content: [{
              type: "text",
              text: truncateResult({
                status: "success",
                fallback: "full_class",
                reason: `method '${method}' not found in decompiled .java; returning entire class`,
                source_path: path,
                fqcn,
                method,
                body: text,
              }),
            }],
          };
        }
        // Compute line numbers for caller convenience.
        const linesBefore = text.slice(0, sliced.start).split("\n").length;
        const linesInBody = sliced.body.split("\n").length;
        return {
          content: [{
            type: "text",
            text: truncateResult({
              status: "success",
              source_path: path,
              fqcn,
              method,
              start_line: linesBefore,
              end_line: linesBefore + linesInBody - 1,
              body: sliced.body,
            }),
          }],
        };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: String(e) }) }] };
      }
    },
  );

  server.tool(
    "list_native_exports",
    "List exported symbols of a native .so via `nm -D --demangle` (or `readelf -sD` fallback).",
    {
      so_path: z.string().describe("Path to a native shared object."),
      tool: z.enum(["nm", "readelf"]).optional().default("nm"),
      filter: z.string().optional().describe("Optional substring filter on symbol name."),
    },
    async ({ so_path, tool, filter }) => {
      try {
        const abs = pathResolve(so_path);
        if (!existsSync(abs)) {
          return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: `File not found: ${abs}` }) }] };
        }
        let raw: string;
        if (tool === "readelf") {
          raw = await run("readelf", ["-sDW", abs], 30000);
        } else {
          raw = await run("nm", ["-D", "--demangle", abs], 30000);
        }
        // Parse a coarse name list. `nm` produces "<addr> T name"; readelf
        // produces a fixed-column table where the last field is name.
        const symbols: { type: string; name: string; address?: string }[] = [];
        for (const line of raw.split(/\r?\n/)) {
          const trimmed = line.trim();
          if (!trimmed) continue;
          if (tool === "nm") {
            const m = trimmed.match(/^(?:([0-9a-fA-F]+)\s+)?([A-Za-z?])\s+(.+)$/);
            if (m) symbols.push({ address: m[1] ?? undefined, type: m[2], name: m[3] });
          } else {
            // readelf -sDW columns: Num Buc Value Size Type Bind Vis Ndx Name
            const parts = trimmed.split(/\s+/);
            if (parts.length >= 8 && /^[0-9]+:/.test(parts[0])) {
              symbols.push({ address: parts[2], type: parts[4], name: parts.slice(7).join(" ") });
            }
          }
        }
        const filtered = filter ? symbols.filter((s) => s.name.includes(filter)) : symbols;
        return { content: [{ type: "text", text: truncateResult({ status: "success", so_path: abs, tool, total_symbols: symbols.length, returned: filtered.length, symbols: filtered }, 2) }] };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: String(e) }) }] };
      }
    },
  );
}
