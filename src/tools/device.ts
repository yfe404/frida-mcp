/**
 * Device tools — enumerate and resolve Frida devices.
 * Ported from Python cli.py with identical semantics.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import frida from "frida";
import { z } from "zod";

export function registerDeviceTools(server: McpServer): void {
  server.tool(
    "enumerate_devices",
    "List all Frida-visible devices (local, USB, remote)",
    {},
    async () => {
      const devices = await frida.enumerateDevices();
      const result = devices.map((d) => ({
        id: d.id,
        name: d.name,
        type: d.type,
      }));
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    },
  );

  server.tool(
    "get_device",
    "Get a specific device by its ID",
    { device_id: z.string().describe("The device ID to look up") },
    async ({ device_id }) => {
      const device = await frida.getDevice(device_id);
      const result = { id: device.id, name: device.name, type: device.type };
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    },
  );

  server.tool(
    "get_usb_device",
    "Get the USB-connected device (typically an Android phone)",
    {},
    async () => {
      const device = await frida.getUsbDevice();
      const result = { id: device.id, name: device.name, type: device.type };
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    },
  );

  server.tool(
    "get_local_device",
    "Get the local (host) device",
    {},
    async () => {
      const device = await frida.getLocalDevice();
      const result = { id: device.id, name: device.name, type: device.type };
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    },
  );
}
