/**
 * Bootstrap tools — collapse multi-step setup into single MCP calls.
 *
 *  - `ensure_frida_server`: arch-detect, download (opt-in), push, kill old,
 *    launch detached, verify reachability. Replaces ~6 ad-hoc adb commands.
 *  - `spawn_and_instrument`: spawn → attach → load script → resume in one
 *    atomic tool invocation so Android's ActivityManagerService ~10 s
 *    "failed to attach" timeout cannot fire between MCP round-trips.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { Session, Script } from "frida";
import { execFile, spawn } from "node:child_process";
import { readFile, mkdir, stat, unlink, copyFile } from "node:fs/promises";
import { createWriteStream } from "node:fs";
import { Readable } from "node:stream";
import { homedir } from "node:os";
import { join, resolve as pathResolve } from "node:path";
import { z } from "zod";
import {
  runAdbShell,
  runAdbCommand,
  shellQuote,
  getHostFridaVersion,
  fridaArchToReleaseArch,
} from "../adb.js";
import { resolveDevice, createJavaBridgeScript, createV8Script, sourceUsesJavaBridge } from "../utils.js";
import { sessionManager } from "../state.js";
import { parseFridaServerPsOutput } from "./android.js";

// ---- ensure_frida_server ----------------------------------------------------

const DEFAULT_BINARY_PATH = "/data/local/tmp/frida-server";
const RELEASE_BASE = "https://github.com/frida/frida/releases/download";

function cacheDir(): string {
  return join(homedir(), ".cache", "frida-mcp");
}

async function pathExists(p: string): Promise<boolean> {
  try { await stat(p); return true; } catch { return false; }
}

/**
 * Download `<url>` to `<dest>`. Streams via Node's global fetch and respects
 * redirects automatically. Throws with the HTTP status if not 2xx.
 */
async function downloadFile(url: string, dest: string): Promise<void> {
  const res = await fetch(url, { redirect: "follow" });
  if (!res.ok || !res.body) {
    throw new Error(`Download failed: ${res.status} ${res.statusText} (${url})`);
  }
  await mkdir(join(dest, ".."), { recursive: true });
  const tmpDest = `${dest}.part`;
  const out = createWriteStream(tmpDest);
  await new Promise<void>((resolve, reject) => {
    Readable.fromWeb(res.body as never).pipe(out).on("finish", resolve).on("error", reject);
  });
  await copyFile(tmpDest, dest);
  await unlink(tmpDest).catch(() => undefined);
}

/**
 * Decompress an `.xz` file. Prefers system `xz -d -k -f` (POSIX coreutils),
 * which is present on every reasonable Linux developer host. We deliberately
 * avoid pulling a native `lzma` Node addon for one decompress per device per
 * version (the result is then cached).
 */
async function xzDecompress(src: string, dest: string): Promise<void> {
  // Stream xz stdout straight to disk. execFile's 1 MB stdout buffer would
  // kill the 50+ MB frida-server stream with code null, so use spawn.
  const child = spawn("xz", ["-d", "-c", src], { stdio: ["ignore", "pipe", "pipe"] });
  let stderr = "";
  child.stderr.on("data", (chunk) => { stderr += chunk.toString("utf8"); });

  await new Promise<void>((resolve, reject) => {
    const out = createWriteStream(dest);
    let exitCode: number | null = null;
    let exitSignal: NodeJS.Signals | null = null;
    let outDone = false;
    let processDone = false;

    function maybeResolve() {
      if (!outDone || !processDone) return;
      if (exitCode === 0) {
        resolve();
      } else {
        reject(new Error(`xz exited code=${exitCode} signal=${exitSignal} stderr=${stderr.trim() || "<empty>"}`));
      }
    }

    // pipe() auto-ends `out` when child.stdout ends; we wait for `finish`.
    child.stdout.pipe(out);
    out.on("finish", () => { outDone = true; maybeResolve(); });
    out.on("error", reject);
    child.on("error", reject);
    child.on("close", (code, signal) => {
      exitCode = code;
      exitSignal = signal;
      processDone = true;
      maybeResolve();
    });
  });

  const s = await stat(dest);
  if (s.size === 0) throw new Error("xz produced empty file");
}

async function ensureLocalBinary(
  version: string,
  releaseArch: string,
  allowNetwork: boolean,
  forceRedownload: boolean,
): Promise<{ path: string; was_downloaded: boolean; cache_path: string }> {
  const dir = join(cacheDir(), version);
  const decompressed = join(dir, `frida-server-${version}-android-${releaseArch}`);
  const archive = `${decompressed}.xz`;

  if (!forceRedownload && await pathExists(decompressed)) {
    return { path: decompressed, was_downloaded: false, cache_path: decompressed };
  }

  if (!allowNetwork) {
    throw new Error(
      `frida-server binary for ${version}/${releaseArch} not cached at ${decompressed}. ` +
      `Re-invoke with allow_network=true to download from github.com/frida/frida/releases.`,
    );
  }

  const url = `${RELEASE_BASE}/${version}/frida-server-${version}-android-${releaseArch}.xz`;
  await downloadFile(url, archive);
  await xzDecompress(archive, decompressed);
  // Keep the .xz around for redownload-free re-extraction.
  return { path: decompressed, was_downloaded: true, cache_path: decompressed };
}

async function detectArch(deviceId: string | undefined, adbSerial?: string): Promise<string> {
  // Prefer Frida's own view; fall back to `adb shell getprop`.
  try {
    const device = await resolveDevice(deviceId);
    const system = await device.querySystemParameters();
    if (system?.arch) return system.arch as string;
  } catch {
    // ignore, fall through to adb
  }
  const abi = await runAdbShell("getprop ro.product.cpu.abi", adbSerial);
  switch (abi) {
    case "arm64-v8a": return "arm64";
    case "armeabi-v7a":
    case "armeabi":   return "arm";
    case "x86_64":    return "x64";
    case "x86":       return "ia32";
    default:          return abi || "unknown";
  }
}

async function killExistingServers(adbSerial?: string): Promise<number> {
  // Kill anything matching frida-server (incl. arch-versioned filenames).
  const psOutput = await runAdbShell("ps -A 2>/dev/null || ps 2>/dev/null || true", adbSerial);
  const running = parseFridaServerPsOutput(psOutput);
  for (const p of running) {
    if (p.pid !== null) {
      try {
        await runAdbShell(`su -c 'kill -9 ${p.pid}'`, adbSerial);
      } catch {
        // best-effort
      }
    }
  }
  return running.length;
}

async function waitForFridaServer(deviceId: string | undefined, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const device = await resolveDevice(deviceId);
      await device.enumerateApplications();
      return true;
    } catch {
      await new Promise((r) => setTimeout(r, 300));
    }
  }
  return false;
}

export function registerBootstrapTools(server: McpServer): void {
  server.tool(
    "ensure_frida_server",
    "Bootstrap a version-matched frida-server on an Android device: detect arch, " +
    "download (only if allow_network=true), push to device, kill prior instances, " +
    "launch detached via setsid, and verify reachability. Subsumes the usual " +
    "adb push/chmod/kill/launch sequence into one call.",
    {
      device_id: z.string().optional().describe("Frida device ID (default: USB)"),
      adb_serial: z.string().optional().describe("Optional adb serial override. Defaults to device_id."),
      target_version: z.string().optional().describe("Frida version to install. Default: host Frida binding version."),
      binary_path: z.string().optional().default(DEFAULT_BINARY_PATH).describe("Where to land the binary on device."),
      allow_network: z.boolean().optional().default(false).describe("Permit downloading from github.com/frida/frida/releases (opt-in)."),
      force_redownload: z.boolean().optional().default(false).describe("Re-download even if cached."),
      verify_timeout_ms: z.number().int().positive().optional().default(5000).describe("How long to wait for the device to answer enumerate_applications after launch."),
    },
    async ({ device_id, adb_serial, target_version, binary_path, allow_network, force_redownload, verify_timeout_ms }) => {
      const serial = adb_serial || device_id;
      const hostVersion = getHostFridaVersion();
      const version = target_version || (hostVersion !== "unknown" ? hostVersion : null);
      if (!version) {
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              status: "error",
              error: "Could not infer target_version (host Frida version unknown). Pass target_version explicitly.",
            }),
          }],
        };
      }

      try {
        const arch = await detectArch(device_id, serial);
        const releaseArch = fridaArchToReleaseArch(arch);
        if (!releaseArch) {
          return {
            content: [{
              type: "text",
              text: JSON.stringify({
                status: "error",
                error: `Unsupported / unknown device arch '${arch}'. Pass adb_serial and ensure the device is online.`,
              }),
            }],
          };
        }

        const binary = await ensureLocalBinary(version, releaseArch, allow_network, force_redownload);

        // Push.
        await runAdbCommand(["push", binary.path, binary_path], serial);
        await runAdbShell(`chmod 755 ${shellQuote(binary_path)}`, serial);

        // Stop any running instances.
        const killedCount = await killExistingServers(serial);
        // Brief settle so kernel reaps the slots.
        if (killedCount > 0) await new Promise((r) => setTimeout(r, 400));

        // Launch detached. setsid + redirected stdio so adb shell does not hang.
        await runAdbShell(
          `su -c 'setsid ${shellQuote(binary_path)} </dev/null >/dev/null 2>&1 &'`,
          serial,
        );

        // Verify by asking Frida itself.
        const reachable = await waitForFridaServer(device_id, verify_timeout_ms);

        // Grab the new PID for the response.
        let serverPid: number | null = null;
        try {
          const psOutput = await runAdbShell("ps -A 2>/dev/null || ps 2>/dev/null || true", serial);
          serverPid = parseFridaServerPsOutput(psOutput).find((p) => p.pid !== null)?.pid ?? null;
        } catch {
          /* ignore */
        }

        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              status: reachable ? "success" : "warning",
              version,
              arch,
              release_arch: releaseArch,
              binary_path,
              server_pid: serverPid,
              killed_prior_instances: killedCount,
              was_downloaded: binary.was_downloaded,
              cache_path: binary.cache_path,
              reachable,
              message: reachable
                ? `frida-server ${version} (${releaseArch}) is up at ${binary_path}.`
                : `Pushed and launched, but Frida could not enumerate applications within ${verify_timeout_ms}ms. ` +
                  `Check root permissions, SELinux, and that the device is unlocked.`,
            }),
          }],
        };
      } catch (e) {
        return {
          content: [{
            type: "text",
            text: JSON.stringify({ status: "error", error: String(e) }),
          }],
        };
      }
    },
  );

  // ---- spawn_and_instrument ------------------------------------------------

  server.tool(
    "spawn_and_instrument",
    "Atomically spawn an Android package, attach Frida, optionally load a script, " +
    "and resume — all inside a single MCP call so the ~10s ActivityManagerService " +
    "'failed to attach' timeout cannot fire between calls. Returns the session and " +
    "(optional) script id you can keep using from the next call onwards.",
    {
      package: z.string().describe("Android package identifier to spawn (e.g. 'com.expedia.bookings')."),
      device_id: z.string().optional().describe("Device ID (default: USB)"),
      script_path: z.string().optional().describe("Optional path to a Frida JS script to load before resume."),
      argv: z.array(z.string()).optional().describe("Optional argv to pass to spawn."),
      resume: z.boolean().optional().default(true).describe("Resume the suspended process after attach+load. Default: true."),
    },
    async ({ package: pkg, device_id, script_path, argv, resume }) => {
      const device = await resolveDevice(device_id);

      let pid: number | undefined;
      let fridaSession: Session | undefined;
      let scriptId: string | undefined;
      let rpcExports: string[] = [];

      try {
        pid = await device.spawn(pkg, { argv });
        fridaSession = await device.attach(pid);

        // Best-effort verification: enumerate apps and abort ONLY if a pid
        // match exists AND its identifier disagrees with our target. A
        // spawn-suspended process may not have an `app.pid` yet (it has not
        // run any code), so "no match found" must not be treated as a
        // mismatch — only "match found, wrong package" is.
        try {
          const apps = await device.enumerateApplications();
          const match = apps.find((a) => a.pid === pid);
          if (match && match.identifier !== pkg) {
            throw new Error(
              `Spawned PID ${pid} resolves to '${match.identifier}', not '${pkg}'. ` +
              `Aborting before script load to avoid instrumenting the wrong process.`,
            );
          }
        } catch (verifyError) {
          // Surface explicit identifier mismatch; swallow enumerate failures
          // (some device types don't implement enumerateApplications).
          if (verifyError instanceof Error && verifyError.message.includes("Aborting")) {
            throw verifyError;
          }
        }

        const sessionId = sessionManager.generateSessionId(pid);
        sessionManager.addSession(sessionId, fridaSession, device, pid);

        if (script_path) {
          const absPath = pathResolve(script_path);
          const source = await readFile(absPath, "utf-8");
          const script: Script = sourceUsesJavaBridge(source)
            ? await createJavaBridgeScript(fridaSession, source)
            : await createV8Script(fridaSession, source);

          script.message.connect((message, data: Buffer | null) => {
            sessionManager.pushMessage(sessionId, {
              type: message.type,
              payload: message.type === "send" ? message.payload : undefined,
              description: message.type === "error" ? (message as { description?: string }).description : undefined,
              stack: message.type === "error" ? (message as { stack?: string }).stack : undefined,
              data: data,
              timestamp: Date.now(),
            });
          });

          await script.load();

          // RPC detection mirrors load_script.
          const rpcMatch = source.match(/rpc\.exports\s*=\s*\{([^}]+)\}/s);
          if (rpcMatch) {
            const body = rpcMatch[1];
            const methodMatches = body.matchAll(/(\w+)\s*:\s*function/g);
            for (const m of methodMatches) rpcExports.push(m[1]);
          }

          scriptId = sessionManager.generateScriptId();
          sessionManager.addScript(sessionId, scriptId, script, source, true, rpcExports);
        }

        if (resume) {
          await device.resume(pid);
        }

        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              status: "success",
              pid,
              session_id: sessionId,
              script_id: scriptId ?? null,
              rpc_exports: rpcExports,
              resumed: resume,
              package: pkg,
              message: scriptId
                ? `Spawned '${pkg}' (pid ${pid}), attached session ${sessionId}, loaded ${scriptId}` +
                  (resume ? " and resumed." : " (suspended — call resume_process to start).")
                : `Spawned '${pkg}' (pid ${pid}), attached session ${sessionId}` +
                  (resume ? ", resumed." : " (suspended)."),
            }),
          }],
        };
      } catch (e) {
        // Best-effort cleanup if we partly succeeded.
        if (pid !== undefined) {
          try { await device.kill(pid); } catch { /* ignore */ }
        }
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              status: "error",
              error: String(e),
              hint: "If attach failed: ensure frida-server is running (ensure_frida_server) and that the package id is correct (list_apps).",
            }),
          }],
        };
      }
    },
  );
}
