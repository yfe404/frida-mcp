import { describe, it, before } from "node:test";
import assert from "node:assert/strict";

// Attempt to import frida — skip entire suite if no device available
let frida: typeof import("frida");
let hasDevice = false;

try {
  frida = await import("frida");
  const device = await frida.default.getUsbDevice({ timeout: 2000 });
  hasDevice = true;
} catch {
  hasDevice = false;
}

describe("Device smoke tests", { skip: !hasDevice ? "No USB device available" : false }, () => {
  it("enumerates USB device", async () => {
    const device = await frida.default.getUsbDevice();
    assert.ok(device);
    assert.ok(device.id);
    assert.ok(device.name);
  });

  it("enumerates processes", async () => {
    const device = await frida.default.getUsbDevice();
    const procs = await device.enumerateProcesses();
    assert.ok(procs.length > 0);
  });

  it("finds init process (PID 1)", async () => {
    const device = await frida.default.getUsbDevice();
    const procs = await device.enumerateProcesses();
    const init = procs.find((p) => p.pid === 1);
    assert.ok(init, "PID 1 should exist on any device");
  });

  it("creates and detaches a session", async () => {
    const device = await frida.default.getUsbDevice();
    const procs = await device.enumerateProcesses();
    // Attach to a safe system process
    const target = procs.find((p) => p.name === "init") || procs[0];
    const session = await device.attach(target.pid);
    assert.ok(session);

    // Execute simple code
    const script = await session.createScript("send(Process.arch);");
    const result = await new Promise<string>((resolve) => {
      script.message.connect((msg) => {
        if (msg.type === "send") resolve(msg.payload as string);
      });
      script.load();
    });
    assert.ok(["arm64", "arm", "x64", "ia32"].includes(result));

    await script.unload();
    await session.detach();
  });

  it("lists modules in a session", async () => {
    const device = await frida.default.getUsbDevice();
    const procs = await device.enumerateProcesses();
    const target = procs.find((p) => p.name === "init") || procs[0];
    const session = await device.attach(target.pid);

    const script = await session.createScript(`
      (function() {
        var mods = Process.enumerateModules();
        var names = [];
        for (var i = 0; i < mods.length; i++) names.push(mods[i].name);
        send(names);
      })();
    `);
    const result = await new Promise<string[]>((resolve) => {
      script.message.connect((msg) => {
        if (msg.type === "send") resolve(msg.payload as string[]);
      });
      script.load();
    });

    assert.ok(Array.isArray(result));
    assert.ok(result.length > 0);
    // libc should be present on any Android/Linux device
    assert.ok(
      result.some((n) => n.includes("libc")),
      "Expected libc in module list",
    );

    await script.unload();
    await session.detach();
  });
});
