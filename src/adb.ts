/**
 * Thin adb + host-Frida helpers shared across Android-targeting tools.
 *
 * Kept deliberately small: just enough for `android.ts` and `bootstrap.ts` to
 * agree on how they call `adb shell` and how they discover the host Frida
 * binding version.
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const execFileAsync = promisify(execFile);

export function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'"'"'`)}'`;
}

/**
 * Run a shell command on a connected Android device.
 *
 * adb's argv-to-shell forwarding is treacherous: it joins extra args with
 * spaces but does NOT preserve quoting boundaries, so `adb shell sh -c "chmod
 * 755 'X'"` ends up as `sh -c chmod 755 'X'` on the device, which `sh -c`
 * reads as command="chmod" with positional params $1=755 $2='X' — chmod sees
 * zero args.
 *
 * Workaround: pass the entire command as one already-joined string. `adb
 * shell <cmd>` invokes the device's default shell, which parses the joined
 * line correctly. The caller is responsible for quoting (use `shellQuote`).
 */
export async function runAdbShell(command: string, adbSerial?: string): Promise<string> {
  const args = [
    ...(adbSerial ? ["-s", adbSerial] : []),
    "shell",
    command,
  ];
  const { stdout } = await execFileAsync("adb", args, { encoding: "utf8" });
  return stdout.trim();
}

/**
 * Invoke `adb` directly (push, pull, devices, ...). Returns trimmed stdout.
 */
export async function runAdbCommand(args: string[], adbSerial?: string): Promise<string> {
  const fullArgs = adbSerial ? ["-s", adbSerial, ...args] : args;
  const { stdout } = await execFileAsync("adb", fullArgs, { encoding: "utf8" });
  return stdout.trim();
}

/**
 * Best-effort lookup of the host Frida binding version from the installed
 * `frida` npm package metadata. Falls back to `"unknown"` so callers can still
 * proceed (e.g. with a user-supplied target version).
 */
export function getHostFridaVersion(): string {
  try {
    const __dirname = dirname(fileURLToPath(import.meta.url));
    const pkgPath = join(__dirname, "..", "node_modules", "frida", "package.json");
    const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
    return typeof pkg.version === "string" ? pkg.version : "unknown";
  } catch {
    return "unknown";
  }
}

/**
 * Map a Frida `Device.querySystemParameters().arch` value to the architecture
 * suffix used in Frida's GitHub release asset names
 * (`frida-server-<v>-android-<arch>.xz`).
 */
export function fridaArchToReleaseArch(arch: string): string | null {
  switch (arch) {
    case "arm64": return "arm64";
    case "arm":   return "arm";
    case "x64":   return "x86_64";
    case "ia32":  return "x86";
    default:      return null;
  }
}
