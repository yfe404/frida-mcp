# Changelog

All notable changes to `frida-mcp` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] — 2026-05-27

A focused round of audit-driven fixes plus a substantial expansion of the
tool surface. No breaking changes against the 1.0 schema: every existing
tool keeps its parameters and result shape. Two tools that were broken on
Frida 17.9.x (`list_classes`, `dump_class`) now return data again.

### Added

#### Bootstrap

- `ensure_frida_server` — detect device arch, download (opt-in
  `allow_network`) the matching `frida-server-<v>-android-<arch>.xz` from
  GitHub releases, decompress, push to device, kill old instances, launch
  detached via `setsid`, and verify reachability. Caches the binary under
  `~/.cache/frida-mcp/<version>/`.
- `spawn_and_instrument` — atomically `device.spawn` → `device.attach` →
  optional `script.load` → `device.resume` inside one MCP call so the
  Android `ActivityManagerService` ~10s "failed to attach" window cannot
  fire between steps.

#### Recipes (parameterised hook templates)

- `hook_okhttp_requests` — snoop every finalized OkHttp request across
  all clients, optional Java stack and body capture.
- `hook_java_method_recipe` — hook all overloads with `where` predicate,
  `max_emits` cap, per-string `truncate_at`.
- `hook_native_export` — `Interceptor.attach` via
  `Process.getModuleByName().getExportByName()` (Frida 17 form).
- `trace_class_methods` — frida-trace equivalent. Skips native /
  synthetic / bridge / abstract methods and `$$Lambda` classes to keep
  the agent stable on broad filters.
- `dump_mac_doFinal` — generic `javax.crypto.Mac.doFinal` observer.
- `bypass_ssl_pinning` — TrustAllCerts + OkHttp3 `CertificatePinner` +
  Conscrypt `TrustManagerImpl` bypass.
- `bypass_root_detection` — opt-in `File.exists` / `Runtime.exec("su")` /
  `Build.TAGS` patch derived from `@dzonerzy/fridantiroot` and objection.

#### Filter + subscription

- `where` predicate on every recipe — JS expression evaluated in the
  agent before `send()`. Host-side blocklist rejects loops, `eval`,
  `Function`, arrow / function expressions, `setTimeout`, `globalThis`
  writes. Agent wraps each evaluation in a 50ms watchdog and emits
  `mcp.filter.slow` when exceeded.
- `set_session_filter` — install / clear a global predicate that gates
  every recipe's `send()` before its per-recipe `where` runs.
- `subscribe_messages` — long-poll for new session messages on a fresh
  EventEmitter. Resolves on `min_count` matches or `timeout_ms` with
  optional source-side `where` and `consume=true` semantics.

#### Static analysis bridge

- `apk_pull` — `pm path` + `adb pull` an installed APK into
  `~/.cache/frida-mcp/apks/`. Cached.
- `apk_manifest` — `aapt2 dump xmltree` → JSON manifest (package,
  versions, permissions, exported components).
- `decompile_class` — jadx full-class decompile (cached per APK
  fingerprint).
- `decompile_method` — slice one method out of the decompiled class;
  skips the `@kotlin.Metadata` annotation block; falls back to the full
  class body if the method name was inlined / compiler-generated.
- `list_native_exports` — `nm -D --demangle` (or `readelf -sDW`) parser
  for `.so` exports.
- `process_inventory` — one-shot loaded modules + user-namespace classes
  + detected networking stack(s) + anti-detection-lib hits.
- `source_jump` — parse a Java stack trace and return a snippet around
  each user frame in the decompiled source. Falls back to `class <Name>`
  declaration when the method name is not found.

#### Discoverability + safety

- `check_frida_detection` — enumerate against RootBeer, SafetyNet,
  Play Integrity, Xposed, plus keyword classes containing
  `Frida` / `Magisk` / `Substrate`; recommends matching bypass slugs.
- `search_recipes` / `describe_recipe` — registry over the recipe
  library with free-text search and per-recipe parameter / event schema.

### Fixed

- **`list_classes` / `dump_class` actually return data** on Frida 17.9.x.
  Root cause: the injected JS used `Java.enumerateLoadedClasses()` with
  no arguments, which `frida-java-bridge` 7.x rejects with
  `TypeError: Cannot read properties of undefined (reading 'onMatch')`.
  Both builders now use the object-callback form and resolve a Promise
  from `onComplete`.
- **`wrapForExecution` propagates IIFE values**. Round 1's wrapper
  re-IIFE'd user code without a surrounding `return`, so any expression
  body surfaced as `result: "undefined"`. The wrapper is now split into
  `wrapForExecution(code)` (statement form, the `execute_in_session`
  contract) and `wrapExpressionForExecution(expr)` for internal IIFE
  builders. Both are Promise-aware.
- **`trace_class_methods` no longer crashes the agent**. The previous
  build called `this[methodName].apply(this, arguments)` from inside the
  hook to invoke the original, which re-entered the dispatcher and
  recursed until SIGSEGV. The canonical frida-java-bridge pattern is
  `m.apply(this, arguments)` on the closure-captured overload — Frida
  re-points `.apply` at the original implementation. The recipe also now
  skips native / synthetic / bridge / abstract methods and `$$Lambda`
  classes that are not safely hookable.
- **Recipe install no longer blocks `script.load()`**. Every recipe now
  defers its `Java.perform` install via `Script.nextTick` and emits
  `recipe.installed` (or `recipe.install.error`) on completion. The MCP
  tool returns in <100ms regardless of install size.
- **Bundle cache keys include `frida-java-bridge` version**. A dep bump
  cannot serve a stale compiled bundle from the in-memory cache.
- **Session detach unloads scripts**. `SessionManager.addSession`'s
  detach handler now iterates persistent scripts and calls `unload()`
  before deleting the session map entry.
- **`subscribe_messages` cannot leak listeners**. The long-poll wraps
  its event handler and timeout callback in `try/finally` so a throwing
  predicate cannot leave a registered listener on the EventEmitter.
- **`findModuleJS` migrates to Frida 17 form**.
  `Process.findModuleByName` is being phased out; the helper now uses
  `Process.getModuleByName` with a `try/catch` that returns `null` on
  missing modules.

### Changed

- Bumped `frida` to `^17.9.11` and `frida-java-bridge` to `^7.0.13`.
- `src/adb.ts` extracts `runAdbShell` / `runAdbCommand` / `shellQuote` /
  `getHostFridaVersion` / `fridaArchToReleaseArch` shared between
  `android.ts` and the new bootstrap module.
- `runAdbShell` no longer wraps commands in `sh -c` — adb's own argv
  forwarding mangles the boundary. Callers pass a single shell-quoted
  command string instead.

### Tests

- 34 new tests in `test/unit/injected-recipes.test.ts` snapshot recipe
  shape (Script.nextTick wrap, `recipe.installed` emit, no recursive
  `this[mn].apply`, no dead `"stop"` sentinel from
  `Java.enumerateLoadedClasses`) and exercise the `where` validator.
- New tests in `test/unit/utils.test.ts` cover
  `wrapExpressionForExecution` (IIFE propagation, trailing-`;` strip,
  empty input, Promise propagation).
- Test count: 169 → 203 (unit).

## [1.0.0] — 2026-04-XX

Initial public release. 41 tools, 15 resources.
