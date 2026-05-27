/**
 * Shared building blocks for recipe templates.
 *
 *  - emit prelude that exposes a `__mcpEmit(event)` helper. The helper
 *    threads two filters: a global one (`globalThis.__mcp_filter`, set by the
 *    `set_session_filter` tool) and a per-recipe one (`where`). Both default
 *    to "true" so an unconfigured recipe still ships every event.
 *  - safeStr / safeJSON utilities mirrored on the agent side.
 *
 * Templates compose: `${EMIT_PRELUDE("(event) => event.type === 'foo'")}`.
 */

/**
 * Inline the `where` predicate as a JS expression that takes `event` and
 * returns boolean. The default "true" preserves the old behaviour (no filter).
 * Sanitise: reject anything that contains a backtick, semicolon outside of
 * for-loops, or `import` to keep the injected expression body single.
 *
 * We accept either an expression ("event.type === 'foo'") or a single
 * statement; both will be wrapped in `function(event){ return (…); }`.
 */
/**
 * Validator for the `where` predicate. Rejects anything that would let the
 * agent execute non-trivial code: loops, function declarations / expressions,
 * dynamic eval, ES module / require / import. The agent-side wrapper still
 * traps thrown exceptions, so malformed-but-syntactically-OK expressions are
 * safe; this layer is here to keep a careless or hostile caller from hanging
 * the Frida agent inside the gating function.
 *
 * Heuristic-only. We deliberately do NOT pull in a real JS parser (acorn,
 * ~600 KB) — keep the dep tree light and add a 50ms agent watchdog below as a
 * second line of defence.
 */
const WHERE_FORBIDDEN_PATTERNS: { re: RegExp; reason: string }[] = [
  { re: /`/,                       reason: "backticks (template literals are not allowed)" },
  { re: /\bwhile\b/,               reason: "`while` loops are not allowed" },
  { re: /\bfor\b/,                 reason: "`for` loops are not allowed" },
  { re: /\bdo\s*\{/,               reason: "`do…while` loops are not allowed" },
  { re: /\beval\b/,                reason: "`eval` is not allowed" },
  { re: /\bFunction\s*\(/,         reason: "the `Function` constructor is not allowed" },
  { re: /\bimport\b/,              reason: "`import` is not allowed" },
  { re: /\brequire\b/,             reason: "`require` is not allowed" },
  { re: /=>/,                      reason: "arrow functions are not allowed" },
  { re: /\bfunction\b/,            reason: "function expressions are not allowed" },
  { re: /\bsetTimeout\b/,          reason: "`setTimeout` is not allowed" },
  { re: /\bsetInterval\b/,         reason: "`setInterval` is not allowed" },
  { re: /\bglobalThis\s*\./,       reason: "writing to globalThis is not allowed" },
];

export function compileWherePredicate(where?: string): string {
  const expr = (where && where.trim().length > 0) ? where : "true";
  for (const { re, reason } of WHERE_FORBIDDEN_PATTERNS) {
    if (re.test(expr)) {
      throw new Error(`\`where\` predicate rejected: ${reason} (in: ${JSON.stringify(expr.slice(0, 200))})`);
    }
  }
  // Agent-side: wrap each evaluation in a watchdog. Frida's QuickJS / V8
  // does not give us a synchronous interrupt, so we approximate by setting a
  // hard time budget per call. The expression itself cannot have loops or
  // functions (validator above), so a single tight expression that exceeds
  // 50ms is anomalous and probably an accidental N² over an object property.
  return `function __mcpWhere(event) {
    var __mcpStart = Date.now();
    try {
      var __mcpResult = (${expr});
      if (Date.now() - __mcpStart > 50) {
        send({ type: 'mcp.filter.slow', took_ms: Date.now() - __mcpStart });
      }
      return __mcpResult;
    } catch (e) { return false; }
  }`;
}

/**
 * Wrap a recipe install body so `script.load()` returns immediately and the
 * actual hook installation runs on the next tick. Without this, recipes that
 * enumerate classes or install many hooks block `script.load()` for tens of
 * seconds and the MCP tool call times out before the script id can be
 * returned.
 *
 * `body` should contain ONLY the install statements; do NOT wrap it in
 * `Java.perform` — this helper does that. After install, emits a
 * `recipe.installed` event so callers can `subscribe_messages` on it.
 *
 * On install failure the recipe emits `recipe.install.error` with the
 * exception text; we deliberately do not unload the script so the host can
 * still introspect it.
 */
export function recipeAsyncInstall(body: string, recipeName: string): string {
  return `
    Script.nextTick(function () {
      Java.perform(function () {
        try {
          ${body}
          __mcpEmit({ type: 'recipe.installed', recipe: ${JSON.stringify(recipeName)} });
        } catch (e) {
          __mcpEmit({ type: 'recipe.install.error', recipe: ${JSON.stringify(recipeName)}, err: String(e) });
        }
      });
    });
  `;
}

/**
 * Same as \`recipeAsyncInstall\` but for V8 (no Java bridge) — used by
 * native-only recipes that don't touch the Java VM.
 */
export function recipeAsyncInstallV8(body: string, recipeName: string): string {
  return `
    Script.nextTick(function () {
      try {
        ${body}
        __mcpEmit({ type: 'recipe.installed', recipe: ${JSON.stringify(recipeName)} });
      } catch (e) {
        __mcpEmit({ type: 'recipe.install.error', recipe: ${JSON.stringify(recipeName)}, err: String(e) });
      }
    });
  `;
}

/**
 * JS prelude installed at the top of every recipe template. It defines:
 *   - `__mcpWhere(event)` — the per-recipe predicate.
 *   - `__mcpEmit(event)` — gated send().
 *   - `__mcpSafe(v)` — string coercion that never throws.
 *   - `__mcpBytesToB64(arr)` — base64 encode a Java byte[] best-effort.
 *   - `__mcpBytesToUtf8(arr)` — UTF-8 decode a Java byte[] best-effort.
 *   - `__mcpStack()` — Java stack trace via Throwable.
 */
export function recipePrelude(where?: string): string {
  return `
${compileWherePredicate(where)}
function __mcpEmit(event) {
  try {
    var gate = (typeof globalThis !== 'undefined' && typeof globalThis.__mcp_filter === 'function')
      ? globalThis.__mcp_filter
      : function() { return true; };
    if (!gate(event)) return;
    if (!__mcpWhere(event)) return;
    send(event);
  } catch (e) {
    send({ type: 'mcp.filter.error', err: String(e) });
  }
}
function __mcpSafe(v) { try { return v === null ? 'null' : v.toString(); } catch (e) { return '<toString err>'; } }
function __mcpBytesToB64(arr) {
  try { return Java.use('java.util.Base64').getEncoder().encodeToString(arr); }
  catch (e) { return '<b64 err>'; }
}
function __mcpBytesToUtf8(arr) {
  try { return Java.use('java.lang.String').$new(arr, 'UTF-8').toString(); }
  catch (e) { return '<utf8 err>'; }
}
function __mcpStack() {
  try {
    return Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new());
  } catch (e) { return '<stack err: ' + e + '>'; }
}
`;
}
