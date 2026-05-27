/**
 * source_jump — turn a Java stack trace into source snippets.
 *
 * Input: stack trace text (the same one we capture in recipes) + an APK.
 * Output: for the top-most user frames, a `±context_lines` window from the
 * decompiled `.java` around the frame's reported line. This is what closes
 * the gap between the "okhttp3.Request$Builder.build / DeepLinkInterceptor:55"
 * stack we capture at runtime and the source we'd otherwise jadx by hand.
 *
 * The frame-line numbers reported by Frida come from the original Kotlin/Java
 * source via dex2jar's debug info; jadx's decompiled output is .java with
 * different line numbers. We therefore use the frame line as a *hint*: we
 * find the nearest occurrence of the frame's method name in the decompiled
 * file and centre on that. Imperfect but useful in practice — the alternative
 * (mapping dex line numbers to .java line numbers) requires DEX parsing that
 * adds substantial weight for marginal precision.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { readFile, stat } from "node:fs/promises";
import { mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve as pathResolve, basename } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { truncateResult } from "../utils.js";

const execFileAsync = promisify(execFile);

function decompileCacheDir(): string {
  return join(homedir(), ".cache", "frida-mcp", "jadx");
}

async function pathExists(p: string): Promise<boolean> {
  try { await stat(p); return true; } catch { return false; }
}

async function ensureJadxSources(apkPath: string): Promise<string> {
  const abs = pathResolve(apkPath);
  if (!await pathExists(abs)) throw new Error(`APK not found: ${abs}`);
  const s = await stat(abs);
  const key = `${basename(abs)}.${s.size}`;
  const dest = join(decompileCacheDir(), key);
  if (await pathExists(dest)) return dest;
  await mkdir(dest, { recursive: true });
  // jadx often exits non-zero on partial decompile while still producing
  // usable sources/. Tolerate non-zero, verify output exists.
  try {
    await execFileAsync("jadx", ["--no-res", "--no-imports", "-d", dest, abs], { maxBuffer: 32 * 1024 * 1024, timeout: 240000 });
  } catch {
    // swallow
  }
  const sources = join(dest, "sources");
  if (!await pathExists(sources)) {
    throw new Error(`jadx produced no sources/ tree under ${dest}; APK may be unsupported`);
  }
  return dest;
}

/**
 * Parse `at com.x.y.Z.method(File.kt:NN)` frames out of a stack trace.
 * Skips synthetic / framework frames the user usually wants filtered.
 */
export interface ParsedFrame {
  fqcn: string;
  method: string;
  file: string;
  line: number;
  isUserCode: boolean;
}

const FRAME_RE = /at\s+([A-Za-z_$][A-Za-z0-9_.$]*)\.([A-Za-z_$<][A-Za-z0-9_$<>]*)\s*\(([^)]+):(\d+)\)/g;
const FRAMEWORK_RE = /^(android|androidx|com\.android|kotlin|kotlinx|java|javax|sun\.|com\.google\.android|okhttp3\.internal|okio\.)/;

export function parseStackTrace(text: string, includeFramework = false): ParsedFrame[] {
  const out: ParsedFrame[] = [];
  for (const m of text.matchAll(FRAME_RE)) {
    const fqcn = m[1];
    const method = m[2];
    const file = m[3];
    const line = Number.parseInt(m[4], 10);
    const isUserCode = !FRAMEWORK_RE.test(fqcn);
    if (!includeFramework && !isUserCode) continue;
    out.push({ fqcn, method, file, line, isUserCode });
  }
  return out;
}

export function registerSourceJumpTool(server: McpServer): void {
  server.tool(
    "source_jump",
    "Parse a Java stack trace and return source snippets around each user frame. Decompiles the APK with jadx (cached). " +
    "Uses the frame method name as the centring hint inside the decompiled .java (line numbers don't translate 1:1 from .kt → .java).",
    {
      stack_trace: z.string().describe("Stack trace text as captured by a recipe (e.g. from include_stack=true)."),
      apk_path: z.string().describe("Local path to the APK."),
      context_lines: z.number().int().nonnegative().optional().default(6).describe("Lines of context on either side of the centred line."),
      include_framework_frames: z.boolean().optional().default(false),
      max_frames: z.number().int().positive().optional().default(8),
    },
    async ({ stack_trace, apk_path, context_lines, include_framework_frames, max_frames }) => {
      try {
        const frames = parseStackTrace(stack_trace, include_framework_frames).slice(0, max_frames);
        if (frames.length === 0) {
          return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: "No matching frames in stack trace.", parsed_frame_count: 0 }) }] };
        }
        const jadxRoot = await ensureJadxSources(apk_path);
        const out: unknown[] = [];

        for (const f of frames) {
          const owner = f.fqcn.includes("$") ? f.fqcn.slice(0, f.fqcn.indexOf("$")) : f.fqcn;
          const candidate = join(jadxRoot, "sources", `${owner.replace(/\./g, "/")}.java`);
          if (!existsSync(candidate)) {
            out.push({ frame: f, status: "no_source", searched: candidate });
            continue;
          }
          const text = await readFile(candidate, "utf8");
          const lines = text.split("\n");
          // Find the nearest line that contains the method name as a token.
          // Skip lines inside the @kotlin.Metadata(...) block at the top of
          // jadx-decompiled Kotlin files — the d2 array embeds every method
          // name as a string literal and would otherwise win the search.
          const tokenRe = new RegExp(`\\b${f.method.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\$&")}\\b`);
          let inMetadata = false;
          let metaDepth = 0;
          let centre = -1;
          for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            if (!inMetadata && /@kotlin\.Metadata\(/.test(line)) {
              inMetadata = true;
              metaDepth = 0;
            }
            if (inMetadata) {
              for (const ch of line) {
                if (ch === "(") metaDepth++;
                else if (ch === ")") {
                  metaDepth--;
                  if (metaDepth === 0) { inMetadata = false; break; }
                }
              }
              continue;
            }
            if (tokenRe.test(line)) { centre = i; break; }
          }
          if (centre < 0) {
            // Fall back to centring on the `class <Name>` declaration which
            // is always present even if the method name was inlined or
            // compiler-generated. Strip the leading package from the FQCN to
            // get the simple class name.
            const simpleName = f.fqcn.slice(f.fqcn.lastIndexOf(".") + 1).split("$")[0];
            const classRe = new RegExp(`\\bclass\\s+${simpleName.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\$&")}\\b`);
            let classLine = -1;
            for (let i = 0; i < lines.length; i++) {
              if (classRe.test(lines[i])) { classLine = i; break; }
            }
            if (classLine >= 0) {
              const start = Math.max(0, classLine - context_lines);
              const end = Math.min(lines.length, classLine + context_lines + 1);
              out.push({
                frame: f,
                status: "ok",
                fallback: "class_declaration",
                source_path: candidate,
                centred_line: classLine + 1,
                snippet_start_line: start + 1,
                snippet_end_line: end,
                snippet: lines.slice(start, end).join("\n"),
              });
            } else {
              out.push({ frame: f, status: "method_not_found_in_decompiled", source_path: candidate });
            }
            continue;
          }
          const start = Math.max(0, centre - context_lines);
          const end = Math.min(lines.length, centre + context_lines + 1);
          out.push({
            frame: f,
            status: "ok",
            source_path: candidate,
            centred_line: centre + 1,
            snippet_start_line: start + 1,
            snippet_end_line: end,
            snippet: lines.slice(start, end).join("\n"),
          });
        }
        return { content: [{ type: "text", text: truncateResult({ status: "success", frames: out }, 2) }] };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ status: "error", error: String(e) }) }] };
      }
    },
  );
}
