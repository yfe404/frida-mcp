/**
 * Java tools — enumerate loaded classes, find live instances on heap.
 *
 * Key pattern: find_instances uses Java.choose() + reflection to find
 * live object instances on the heap with full field introspection.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { sessionManager } from "../state.js";
import { executeTransientJavaScript, truncateResult, createJavaBridgeScript } from "../utils.js";
import {
  listClassesJS,
  findInstancesJS,
  listMethodsJS,
  dumpClassJS,
  runJavaJS,
  hookJavaMethodJS,
} from "../injected/java-helpers.js";

export function registerJavaTools(server: McpServer): void {
  server.tool(
    "list_classes",
    "List loaded Java classes, optionally filtered by substring (max 500 results). Wraps Java.enumerateLoadedClasses().",
    {
      session_id: z.string().describe("Session ID"),
      filter: z.string().optional().describe("Substring filter (case-insensitive)"),
    },
    async ({ session_id, filter }) => {
      const session = sessionManager.requireSession(session_id);
      const result = await executeTransientJavaScript(
        session.fridaSession,
        listClassesJS(filter),
        10000, // class enumeration can be slow
      );
      return { content: [{ type: "text", text: truncateResult(result, 2) }] };
    },
  );

  server.tool(
    "find_instances",
    "Find live Java object instances on the heap using Java.choose(). Reads all fields via reflection, handling primitive types (long, int, boolean) via type-specific getters.",
    {
      session_id: z.string().describe("Session ID"),
      class_name: z.string().describe("Fully qualified class name (e.g., 'com.example.MyClass')"),
      max_instances: z.number().optional().default(5).describe("Max instances to return (default: 5)"),
    },
    async ({ session_id, class_name, max_instances }) => {
      const session = sessionManager.requireSession(session_id);
      const result = await executeTransientJavaScript(
        session.fridaSession,
        findInstancesJS(class_name, max_instances ?? 5),
        15000, // heap scanning can be slow
      );
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    },
  );

  server.tool(
    "list_methods",
    "List all methods of a Java class with parameter types, return type, and modifiers",
    {
      session_id: z.string().describe("Session ID"),
      class_name: z.string().describe("Fully qualified Java class name (e.g., 'android.app.Activity')"),
    },
    async ({ session_id, class_name }) => {
      const session = sessionManager.requireSession(session_id);
      const result = await executeTransientJavaScript(
        session.fridaSession,
        listMethodsJS(class_name),
        10000,
      );
      return { content: [{ type: "text", text: truncateResult(result, 2) }] };
    },
  );

  server.tool(
    "dump_class",
    "Full introspection of a Java class: methods, fields, constructors, interfaces, and superclass",
    {
      session_id: z.string().describe("Session ID"),
      class_name: z.string().describe("Fully qualified Java class name"),
    },
    async ({ session_id, class_name }) => {
      const session = sessionManager.requireSession(session_id);
      const result = await executeTransientJavaScript(
        session.fridaSession,
        dumpClassJS(class_name),
        10000,
      );
      return { content: [{ type: "text", text: truncateResult(result, 2) }] };
    },
  );

  server.tool(
    "run_java",
    "Execute arbitrary Java code inside Java.perform(). Has access to Java.use(), Java.choose(), etc. Return a value to see it in the result.",
    {
      session_id: z.string().describe("Session ID"),
      code: z.string().describe("Java/Frida code to execute (runs inside Java.perform)"),
    },
    async ({ session_id, code }) => {
      const session = sessionManager.requireSession(session_id);
      const result = await executeTransientJavaScript(
        session.fridaSession,
        runJavaJS(code),
        15000,
      );
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    },
  );

  server.tool(
    "android_hook_method",
    "Hook a Java method by class and method name. Hooks all overloads. Logs arguments and/or return values as messages retrievable via get_session_messages.",
    {
      session_id: z.string().describe("Session ID"),
      class_name: z.string().describe("Fully qualified Java class name"),
      method_name: z.string().describe("Method name to hook"),
      log_args: z.boolean().optional().default(true).describe("Log method arguments (default: true)"),
      log_retval: z.boolean().optional().default(true).describe("Log return value (default: true)"),
      log_backtrace: z.boolean().optional().default(false).describe("Log Java stack trace (default: false)"),
      script_id: z.string().optional().describe("Custom script ID for this hook"),
    },
    async ({ session_id, class_name, method_name, log_args, log_retval, log_backtrace, script_id }) => {
      const session = sessionManager.requireSession(session_id);
      const hookId = script_id || `java_hook_${Date.now()}`;
      const code = hookJavaMethodJS(class_name, method_name, hookId, log_args, log_retval, log_backtrace);

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
      sessionManager.addScript(session_id, hookId, script, code, true);

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            status: "success",
            hook_id: hookId,
            class_name,
            method_name,
            message: `Java hook installed on ${class_name}.${method_name}. Use get_session_messages to retrieve logs. Unload with unload_script('${hookId}').`,
          }),
        }],
      };
    },
  );
}
