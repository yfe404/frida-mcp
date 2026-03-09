/**
 * Android-specific tools — SSL pinning bypass, activity introspection,
 * app enumeration, and file operations on target device.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execFile } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { z } from "zod";
import { sessionManager } from "../state.js";
import { resolveDevice, executeTransientJavaScript, truncateResult, createJavaBridgeScript } from "../utils.js";
import {
  sslPinningDisableJS,
  getCurrentActivityJS,
  fileLsJS,
  fileReadJS,
} from "../injected/java-helpers.js";

const execFileAsync = promisify(execFile);

export interface FridaServerProcessInfo {
  pid: number | null;
  line: string;
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\"'\"'`)}'`;
}

function getHostFridaVersion(): string {
  try {
    const __dirname = dirname(fileURLToPath(import.meta.url));
    const pkgPath = join(__dirname, "..", "..", "node_modules", "frida", "package.json");
    const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
    return typeof pkg.version === "string" ? pkg.version : "unknown";
  } catch {
    return "unknown";
  }
}

export function parseFridaServerPsOutput(output: string): FridaServerProcessInfo[] {
  return output
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => /(^|[\/\s])frida-server(\s|$)/.test(line))
    .filter((line) => !line.includes("grep frida-server"))
    .map((line) => {
      const fields = line.split(/\s+/);
      const pidField = fields.find((field) => /^\d+$/.test(field)) ?? null;
      return {
        pid: pidField ? Number.parseInt(pidField, 10) : null,
        line,
      };
    });
}

export function buildFridaServerWarnings(details: {
  runningCount: number;
  hostVersion: string;
  detectedVersion?: string | null;
  adbError?: string;
}): string[] {
  const warnings: string[] = [];
  if (details.adbError) {
    warnings.push(`ADB probe failed: ${details.adbError}`);
  }
  if (details.runningCount === 0) {
    warnings.push("No frida-server process detected on the device.");
  } else if (details.runningCount > 1) {
    warnings.push(`Multiple frida-server processes detected (${details.runningCount}).`);
  }
  if (details.detectedVersion && details.hostVersion !== "unknown" && details.detectedVersion !== details.hostVersion) {
    warnings.push(`Host Frida ${details.hostVersion} does not match device frida-server ${details.detectedVersion}.`);
  }
  if (!details.detectedVersion) {
    warnings.push("Unable to determine device frida-server version automatically.");
  }
  return warnings;
}

async function runAdbShell(command: string, adbSerial?: string): Promise<string> {
  const args = [
    ...(adbSerial ? ["-s", adbSerial] : []),
    "shell",
    "sh",
    "-c",
    command,
  ];
  const { stdout } = await execFileAsync("adb", args, { encoding: "utf8" });
  return stdout.trim();
}

export function registerAndroidTools(server: McpServer): void {
  server.tool(
    "android_ssl_pinning_disable",
    "Bypass SSL certificate pinning by installing a custom TrustManager that accepts all certificates. Hooks SSLContext.init, HttpsURLConnection, OkHttp3 CertificatePinner, and TrustManagerImpl.",
    {
      session_id: z.string().describe("Session ID"),
      script_id: z.string().optional().describe("Custom script ID"),
    },
    async ({ session_id, script_id }) => {
      const session = sessionManager.requireSession(session_id);
      const id = script_id || `ssl_bypass_${Date.now()}`;
      const code = sslPinningDisableJS();

      const script = await createJavaBridgeScript(session.fridaSession, code);
      script.message.connect((message, data: Buffer | null) => {
        sessionManager.pushMessage(session_id, {
          type: message.type,
          payload: message.type === "send" ? message.payload : undefined,
          description: message.type === "error" ? (message as { description?: string }).description : undefined,
          data: data,
          timestamp: Date.now(),
        });
      });
      await script.load();
      sessionManager.addScript(session_id, id, script, code, true);

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            status: "success",
            script_id: id,
            message: `SSL pinning bypass installed. Check get_session_messages for details on what was hooked. Unload with unload_script('${id}').`,
          }),
        }],
      };
    },
  );

  server.tool(
    "android_get_current_activity",
    "Get the current foreground Android activity name and package via ActivityThread reflection",
    {
      session_id: z.string().describe("Session ID"),
    },
    async ({ session_id }) => {
      const session = sessionManager.requireSession(session_id);
      const result = await executeTransientJavaScript(
        session.fridaSession,
        getCurrentActivityJS(),
        5000,
      );
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    },
  );

  server.tool(
    "list_apps",
    "List installed applications on the device (identifier, name, running PID)",
    {
      device_id: z.string().optional().describe("Device ID (default: USB)"),
    },
    async ({ device_id }) => {
      const device = await resolveDevice(device_id);
      const apps = await device.enumerateApplications();
      const result = apps.map((a) => ({
        identifier: a.identifier,
        name: a.name,
        pid: a.pid,
      }));
      return { content: [{ type: "text", text: truncateResult(result, 2) }] };
    },
  );

  server.tool(
    "android_check_frida_server",
    "Inspect Android frida-server health using Frida device metadata plus adb shell. Warns about missing or multiple frida-server processes and version mismatches.",
    {
      device_id: z.string().optional().describe("Frida device ID (default: USB)"),
      adb_serial: z.string().optional().describe("Optional adb serial override. Defaults to device_id when provided."),
    },
    async ({ device_id, adb_serial }) => {
      const device = await resolveDevice(device_id);
      const serial = adb_serial || device_id;
      const hostVersion = getHostFridaVersion();

      let system: Awaited<ReturnType<typeof device.querySystemParameters>> | null = null;
      let systemError: string | undefined;
      try {
        system = await device.querySystemParameters();
      } catch (e) {
        systemError = String(e);
      }

      let processes: FridaServerProcessInfo[] = [];
      let serverVersion: string | null = null;
      let adbError: string | undefined;
      const versionProbePaths: string[] = [];

      try {
        const psOutput = await runAdbShell("ps -A 2>/dev/null || ps 2>/dev/null || true", serial);
        processes = parseFridaServerPsOutput(psOutput);

        for (const processInfo of processes) {
          if (processInfo.pid === null) continue;

          const exePath = await runAdbShell(`readlink /proc/${processInfo.pid}/exe 2>/dev/null || true`, serial);
          if (exePath) {
            versionProbePaths.push(exePath);
          }
        }

        for (const candidate of versionProbePaths) {
          const versionOutput = await runAdbShell(`${shellQuote(candidate)} --version 2>/dev/null || true`, serial);
          const match = versionOutput.match(/\b\d+\.\d+\.\d+\b/);
          if (match) {
            serverVersion = match[0];
            break;
          }
        }
      } catch (e) {
        adbError = String(e);
      }

      const warnings = buildFridaServerWarnings({
        runningCount: processes.length,
        hostVersion,
        detectedVersion: serverVersion,
        adbError,
      });
      if (systemError) {
        warnings.push(`Failed to query device system parameters: ${systemError}`);
      }

      const status = warnings.length > 0 ? "warning" : "success";

      return {
        content: [{
          type: "text",
          text: truncateResult({
            status,
            host_frida_version: hostVersion,
            adb_serial_used: serial ?? null,
            device: {
              id: device.id,
              name: device.name,
              type: device.type,
              arch: system?.arch ?? null,
              platform: system?.platform ?? null,
              os: system?.os ?? null,
            },
            frida_server: {
              running: processes.length > 0,
              process_count: processes.length,
              version: serverVersion,
              processes,
              version_probe_paths: versionProbePaths,
            },
            warnings,
            recommendations: [
              "Use a frida-server binary that matches both the device architecture and the host Frida version.",
              "If multiple frida-server processes appear, stop the extra instances before attaching.",
              "If version detection fails, run the device-side frida-server binary with --version over adb shell and compare it to the host package version.",
            ],
          }, 2),
        }],
      };
    },
  );

  server.tool(
    "file_ls",
    "List directory contents on the target device (uses Java File API, requires Java runtime)",
    {
      session_id: z.string().describe("Session ID"),
      path: z.string().describe("Directory path on the target device"),
    },
    async ({ session_id, path }) => {
      const session = sessionManager.requireSession(session_id);
      const result = await executeTransientJavaScript(
        session.fridaSession,
        fileLsJS(path),
        10000,
      );
      return { content: [{ type: "text", text: truncateResult(result, 2) }] };
    },
  );

  server.tool(
    "file_read",
    "Read a text file from the target device (uses Java Scanner, requires Java runtime)",
    {
      session_id: z.string().describe("Session ID"),
      path: z.string().describe("File path on the target device"),
      max_size: z.number().optional().default(65536).describe("Maximum file size in bytes (default: 64KB)"),
    },
    async ({ session_id, path, max_size }) => {
      const session = sessionManager.requireSession(session_id);
      const result = await executeTransientJavaScript(
        session.fridaSession,
        fileReadJS(path, max_size),
        10000,
      );
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    },
  );
}
