/**
 * Shared installation path for recipe-style persistent scripts.
 *
 * Both `tools/recipes.ts` and `tools/anti-detection.ts` need the same
 * sequence: build a Java-bridge script from a template, wire `script.message`
 * into the session message queue, await `script.load()` with a watchdog, and
 * register the script under a collision-safe id.
 *
 * The id is generated via `crypto.randomUUID()` so two concurrent installs of
 * the same template (which used to race on `Date.now()` granularity) cannot
 * collide. The watchdog ensures a slow agent-side install does not leave the
 * tool call hanging past the MCP client's timeout — we still register the
 * script object so the caller can unload it later, but the tool returns with
 * `installing` status if `script.load()` exceeds `install_timeout_ms`.
 */

import { randomUUID } from "node:crypto";
import type { Session, Script } from "frida";
import { sessionManager } from "../state.js";
import { createJavaBridgeScript } from "../utils.js";

export interface InstallRecipeResult {
  script_id: string;
  installed: boolean;
  install_timed_out: boolean;
}

export async function installRecipe(
  sessionId: string,
  fridaSession: Session,
  scriptIdHint: string,
  source: string,
  installTimeoutMs = 10000,
): Promise<InstallRecipeResult> {
  const scriptId = `${scriptIdHint}_${randomUUID()}`;
  const script: Script = await createJavaBridgeScript(fridaSession, source);

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

  // Race script.load() against a watchdog so the MCP tool call cannot block
  // past the install_timeout_ms cap. If load wins, we record `installed: true`.
  // If the timeout wins, we still register the script so the caller can
  // unload it; the agent may still be busy installing hooks asynchronously
  // and emit `recipe.installed` later (R2.2 async-install pattern).
  let installTimedOut = false;
  const loadPromise = script.load().then(() => false, (e) => { throw e; });
  const timeoutPromise = new Promise<true>((resolve) => {
    setTimeout(() => { installTimedOut = true; resolve(true); }, installTimeoutMs);
  });
  await Promise.race([loadPromise, timeoutPromise]);

  sessionManager.addScript(sessionId, scriptId, script, source, true);

  return {
    script_id: scriptId,
    installed: !installTimedOut,
    install_timed_out: installTimedOut,
  };
}
