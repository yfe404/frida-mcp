import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { buildFridaServerWarnings, parseFridaServerPsOutput } from "../../src/tools/android.js";

describe("parseFridaServerPsOutput", () => {
  it("detects frida-server processes from ps output", () => {
    const output = [
      "USER       PID   PPID  VSZ      RSS   WCHAN            ADDR S NAME",
      "root       1234  1     12345    678   0                0    S /data/local/tmp/frida-server",
      "root       2222  1     12345    678   0                0    S frida-server",
    ].join("\n");

    const parsed = parseFridaServerPsOutput(output);
    assert.equal(parsed.length, 2);
    assert.equal(parsed[0].pid, 1234);
    assert.equal(parsed[1].pid, 2222);
  });

  it("ignores grep lines and unrelated processes", () => {
    const output = [
      "shell 9999 1 grep frida-server",
      "shell 1111 1 toybox ps",
      "root 2222 1 /system/bin/app_process",
    ].join("\n");

    const parsed = parseFridaServerPsOutput(output);
    assert.deepEqual(parsed, []);
  });
});

describe("buildFridaServerWarnings", () => {
  it("warns when multiple servers are running", () => {
    const warnings = buildFridaServerWarnings({
      runningCount: 2,
      hostVersion: "17.7.3",
      detectedVersion: "17.7.3",
    });

    assert.ok(warnings.some((warning) => warning.includes("Multiple frida-server processes detected")));
  });

  it("warns on version mismatch and missing version detection details", () => {
    const mismatchWarnings = buildFridaServerWarnings({
      runningCount: 1,
      hostVersion: "17.7.3",
      detectedVersion: "17.6.2",
    });
    assert.ok(mismatchWarnings.some((warning) => warning.includes("does not match")));

    const unknownWarnings = buildFridaServerWarnings({
      runningCount: 1,
      hostVersion: "17.7.3",
      detectedVersion: null,
    });
    assert.ok(unknownWarnings.some((warning) => warning.includes("Unable to determine")));
  });
});
