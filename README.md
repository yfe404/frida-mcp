# frida-mcp

TypeScript MCP server for Frida 17 dynamic instrumentation. Provides ~62 tools and 15 resources for attaching to processes, executing scripts, hooking native and Java methods, bypassing SSL pinning and root detection, reading/writing memory, inspecting Java heaps, exporting large captures to disk, pulling APKs and decompiling them with jadx, and searching Frida 17 API documentation — all through the Model Context Protocol.

## What's new in 1.1.0

- **Bootstrap**: one-call `ensure_frida_server` (arch-detect + download + push + launch) and `spawn_and_instrument` (atomic spawn → attach → load → resume) that beats the Android `ActivityManagerService` 10s timeout.
- **Recipe library**: parameterised hook templates for OkHttp, Java method, native export, class trace, `Mac.doFinal`, SSL pinning bypass and root-detection bypass. Recipes install asynchronously so `script.load()` returns in <100ms; subscribe on `recipe.installed` via `subscribe_messages`.
- **Source-side filter**: every recipe accepts a `where` predicate evaluated in the agent (host-side blocklist against loops/eval/Function + 50ms agent watchdog), plus a global `set_session_filter`.
- **Static analysis bridge**: `apk_pull`, `apk_manifest`, `decompile_class`, `decompile_method`, `list_native_exports`, `process_inventory`, `source_jump` close the loop between a captured runtime stack frame and the decompiled `.java`.
- **Anti-detection helpers**: `check_frida_detection` enumerates against RootBeer / SafetyNet / Play Integrity / Xposed; `bypass_root_detection` is opt-in.
- **Real fixes** to existing tools: `list_classes` and `dump_class` now return data on Frida 17.9.x (object-callback `Java.enumerateLoadedClasses` + Promise-aware execution wrapper); `trace_class_methods` no longer infinite-recurses (closure-captured overload pattern); session detach now unloads scripts; `subscribe_messages` long-poll cannot leak listeners.

See [CHANGELOG.md](CHANGELOG.md) for the full list.

## Setup

### Quick install (Claude Code)

```bash
claude mcp add frida-mcp -- npx -y frida-mcp@latest
```

Installs frida-mcp as an MCP server over stdio. Auto-updates on every Claude Code restart.

**Scopes:**

```bash
# Per-user (available in all projects)
claude mcp add --scope user frida-mcp -- npx -y frida-mcp@latest

# Per-project (shared via .mcp.json, commit to repo)
claude mcp add --scope project frida-mcp -- npx -y frida-mcp@latest
```

### Manual `.mcp.json` config

```json
{
  "mcpServers": {
    "frida": {
      "command": "npx",
      "args": ["-y", "frida-mcp@latest"]
    }
  }
}
```

### From source (development)

```bash
npm install
npm run fetch-docs   # build docs index (optional but recommended)
npm run build
npm start
```

Then point `.mcp.json` at the local build:

```json
{
  "mcpServers": {
    "frida": {
      "command": "node",
      "args": ["/path/to/frida-mcp/dist/index.js"]
    }
  }
}
```

Restart Claude Code to pick up the new server.

### Prerequisites

- Node.js 20+
- Frida 17 (`npm install frida@17`)
- A USB-connected device (Android phone) for on-device operations
- `frida-server` running on the target device

## Tool Reference

### Device Tools (4)

| Tool | Description | Key Params |
|------|-------------|------------|
| `enumerate_devices` | List all Frida-visible devices (local, USB, remote) | — |
| `get_device` | Get a specific device by ID | `device_id` |
| `get_usb_device` | Get the USB-connected device | — |
| `get_local_device` | Get the local (host) device | — |

### Process Tools (6)

| Tool | Description | Key Params |
|------|-------------|------------|
| `enumerate_processes` | List all running processes | `device_id?` |
| `get_process_by_name` | Find process by name (case-insensitive substring) | `name`, `device_id?` |
| `attach_to_process` | Lightweight attach check | `pid`, `device_id?` |
| `spawn_process` | Spawn a new process | `program`, `args?`, `device_id?` |
| `resume_process` | Resume a spawned/suspended process | `pid`, `device_id?` |
| `kill_process` | Kill a process | `pid`, `device_id?` |

### Session Tools (5)

| Tool | Description | Key Params |
|------|-------------|------------|
| `create_interactive_session` | Attach and create a managed session (spawn fallback is opt-in) | `process_id`, `device_id?`, `spawn_fallback?`, `app_identifier?`, `auto_resume_spawned?` |
| `execute_in_session` | Execute JS in session (transient or persistent) | `session_id`, `javascript_code`, `keep_alive?` |
| `get_session_messages` | Retrieve queued messages with pagination (previews; blobs for large fields) | `session_id`, `limit?`, `offset?`, `clear_mode?` |
| `read_session_message_blob` | Read an offloaded message blob (payload/data) in bounded chunks | `session_id`, `blob_id`, `offset?`, `limit?`, `encoding?` |
| `get_archived_session_messages` | List archived messages that were cleared/evicted from memory | `session_id`, `limit?`, `offset?` |

### Script Management Tools (4)

| Tool | Description | Key Params |
|------|-------------|------------|
| `load_script` | Load JS file from disk, auto-detect RPC exports | `session_id`, `file_path`, `script_id?` |
| `list_scripts` | List loaded scripts with metadata | `session_id` |
| `unload_script` | Unload a script | `session_id`, `script_id` |
| `call_rpc_export` | Call an RPC-exported method | `session_id`, `script_id`, `method`, `args?` |

#### Beginner: `load_script` vs `call_rpc_export`

If you are new to Frida, think about this in two layers:

- `load_script`: put your agent code inside the target app and keep it running.
- `call_rpc_export`: call one function from that already-loaded agent.

Simple rule:

- You usually call `load_script` once.
- You can call `call_rpc_export` many times after that.
- When finished, call `unload_script`.
- Use `export_capture_bundle` instead when the result size is unknown or you want a host-side file for later analysis.

Minimal flow:

```text
1) create_interactive_session(...)  -> session_id
2) load_script(session_id, "agent.js") -> script_id
3) call_rpc_export(session_id, script_id, "methodName", [...args]) -> result
4) unload_script(session_id, script_id)
```

### Export Tools (1)

| Tool | Description | Key Params |
|------|-------------|------------|
| `export_capture_bundle` | Export RPC output and captured messages to a disk JSONL bundle (token-safe summary response) | `session_id`, `rpc?`, `include_messages?`, `include_archived_messages?`, `clear_mode?`, `output_path?`, `format?`, `response_detail?` |

`export_capture_bundle` is the preferred path for large or unbounded output. By default it returns a slim `path_only` response and writes the full capture to disk on the host machine.

### Memory Tools (6)

| Tool | Description | Key Params |
|------|-------------|------------|
| `list_modules` | List loaded native modules | `session_id` |
| `find_module` | Find module by name | `session_id`, `name` |
| `list_exports` | List exported symbols from a module | `session_id`, `module_name` |
| `read_memory` | Hex dump at address (supports `module+0xoffset`) | `session_id`, `address`, `size?` |
| `write_memory` | Write bytes to address (auto memory protection) | `session_id`, `address`, `hex_bytes` |
| `search_memory` | Search readable memory for hex/string patterns | `session_id`, `pattern`, `pattern_type?`, `max_results?` |

### Java Tools (6)

| Tool | Description | Key Params |
|------|-------------|------------|
| `list_classes` | Enumerate loaded Java classes (max 500) | `session_id`, `filter?` |
| `find_instances` | Find live heap instances via `Java.choose()` | `session_id`, `class_name`, `max_instances?` |
| `list_methods` | List all methods of a Java class with types/modifiers | `session_id`, `class_name` |
| `dump_class` | Full class introspection (methods, fields, constructors, interfaces, superclass) | `session_id`, `class_name` |
| `run_java` | Execute arbitrary code inside `Java.perform()` | `session_id`, `code` |
| `android_hook_method` | Hook a Java method (all overloads), log args/retval/backtrace | `session_id`, `class_name`, `method_name`, `log_args?`, `log_retval?`, `log_backtrace?` |

### Native Hook Tools (2)

| Tool | Description | Key Params |
|------|-------------|------------|
| `hook_function` | Install persistent `Interceptor.attach` hook | `session_id`, `address`, `log_args?`, `log_retval?`, `num_args?` |
| `get_backtrace` | One-shot backtrace capture (self-detaches) | `session_id`, `address`, `style?` |

### Android Tools (6)

| Tool | Description | Key Params |
|------|-------------|------------|
| `android_ssl_pinning_disable` | Bypass SSL pinning (TrustManager, SSLContext, OkHttp, TrustManagerImpl) | `session_id`, `script_id?` |
| `android_get_current_activity` | Get foreground activity via ActivityThread reflection | `session_id` |
| `list_apps` | List installed applications (identifier, name, PID) | `device_id?` |
| `android_check_frida_server` | Check Android frida-server health (running instances, version mismatch warnings) | `device_id?`, `adb_serial?` |
| `file_ls` | List directory contents on target device (Java File API) | `session_id`, `path` |
| `file_read` | Read a text file from target device | `session_id`, `path`, `max_size?` |

### Documentation Tools (1)

| Tool | Description | Key Params |
|------|-------------|------------|
| `search_frida_docs` | Full-text search Frida 17 API docs (size-safe paginated snippets) | `query`, `limit?`, `offset?`, `snippet_chars?` |

### Bootstrap Tools (2)

| Tool | Description | Key Params |
|------|-------------|------------|
| `ensure_frida_server` | Detect device arch, download (opt-in) matching `frida-server` from GitHub releases, push to device, kill old instances, launch detached, verify reachable. Subsumes the 6-command manual install. | `device_id?`, `target_version?`, `binary_path?`, `allow_network?` (default false), `force_redownload?`, `verify_timeout_ms?` |
| `spawn_and_instrument` | Atomically `device.spawn` → `device.attach` → optional `script.load` → `device.resume` inside a single MCP call so AMS's ~10s "failed to attach" window cannot fire between steps. | `package`, `device_id?`, `script_path?`, `argv?`, `resume?` |

### Recipe Tools (8)

Vetted, parameterised hook templates so you do not have to write 100+ lines of Frida JS for every common task. All recipes defer their hook installation via `Script.nextTick` so `script.load()` returns immediately; long-poll `subscribe_messages` on the `recipe.installed` event to wait for hooks to be live. All recipes accept a `where` predicate that gates `send()` in the agent.

| Tool | Description | Key Params |
|------|-------------|------------|
| `hook_okhttp_requests` | Snoop every finalized `okhttp3.Request$Builder.build` across all OkHttp clients. | `session_id`, `url_includes?`, `include_stack?`, `include_body?`, `max_body_bytes?`, `where?` |
| `hook_java_method_recipe` | Hook all overloads of a Java method with source-side `where`, `max_emits` cap, and per-string truncation. | `session_id`, `class_name`, `method_name`, `log_args?`, `log_retval?`, `log_backtrace?`, `max_emits?`, `truncate_at?`, `where?` |
| `hook_native_export` | `Interceptor.attach` to a single exported symbol via `Process.getModuleByName().getExportByName()`. | `session_id`, `module`, `symbol`, `num_args?`, `decode_ret_as_cstring?`, `where?` |
| `trace_class_methods` | `frida-trace -j 'pkg.*!*'` equivalent: enumerate matching classes, install lightweight call-tracers. Skips native / synthetic / `$$Lambda` to avoid agent crashes. | `session_id`, `class_filter`, `method_filter?`, `max_methods?`, `where?` |
| `dump_mac_doFinal` | Hook both overloads of `javax.crypto.Mac.doFinal`. Generic crypto observer — cracks HMAC algorithms in seconds. | `session_id`, `include_input?`, `where?` |
| `bypass_ssl_pinning` | TrustAllCerts + null hostname verifier + OkHttp3 `CertificatePinner` + Conscrypt `TrustManagerImpl`. | `session_id` |
| `search_recipes` | Free-text search the local recipe registry. | `query` |
| `describe_recipe` | Return parameter schema + emitted event types for a recipe by slug. | `slug` |

Plus two helpers wired through the same machinery:

| Tool | Description | Key Params |
|------|-------------|------------|
| `set_session_filter` | Install / clear a global JS predicate that gates every recipe's `send()` before its per-recipe `where` runs. | `session_id`, `predicate_js` |
| `subscribe_messages` | Long-poll for new session messages. Resolves as soon as N matching messages exist or after `timeout_ms`. Optional `where` is a JS predicate over the stored message; `consume=true` removes returned messages from the queue. | `session_id`, `where?`, `min_count?`, `timeout_ms?`, `consume?`, `since_seq?` |

### Static Analysis Tools (7)

Bridge between Frida's runtime view and the APK's static source. Shell out to `adb`, `aapt2`, `jadx`, `nm` / `readelf`.

| Tool | Description | Key Params |
|------|-------------|------------|
| `apk_pull` | `pm path` + `adb pull` an installed APK into `~/.cache/frida-mcp/apks/`. Cached. | `package`, `device_id?`, `force?` |
| `apk_manifest` | `aapt2 dump xmltree` → JSON (package, versions, permissions, exported components). | `apk_path` |
| `decompile_class` | jadx full-class decompile (cached per APK fingerprint). Inner classes via outer file. | `apk_path`, `fqcn` |
| `decompile_method` | Slice one method out of the decompiled class. Skips `@kotlin.Metadata` block; falls back to `full_class` if name is inlined. | `apk_path`, `fqcn`, `method` |
| `list_native_exports` | `nm -D --demangle` (or `readelf -sDW`) parser for a `.so`'s exported symbols. | `so_path`, `tool?`, `filter?` |
| `process_inventory` | One-shot: loaded native modules + user-namespace Java classes + detected networking stack(s) + anti-detection-lib hits. | `session_id` |
| `source_jump` | Parse a Java stack trace and return a `±context_lines` snippet around each user frame in the decompiled source. Falls back to `class <Name>` declaration when method name not found. | `stack_trace`, `apk_path`, `context_lines?`, `include_framework_frames?`, `max_frames?` |

### Anti-Detection Tools (2)

| Tool | Description | Key Params |
|------|-------------|------------|
| `check_frida_detection` | Enumerate loaded classes against known detection-lib patterns (RootBeer, SafetyNet, Play Integrity, Xposed, plus keyword `Frida`/`Magisk`/`Substrate`). Recommends matching bypass recipe slugs. | `session_id` |
| `bypass_root_detection` | Opt-in: patch `File.exists` for su paths, `Runtime.exec("su")`, `Build.TAGS` test-keys. Derivative of `@dzonerzy/fridantiroot` + objection's root-bypass agent. | `session_id`, `where?` |

## Resources

| URI | Description |
|-----|-------------|
| `frida://version` | Installed Frida version |
| `frida://processes` | USB device process list |
| `frida://devices` | All available devices |
| `frida://docs/index` | Documentation section listing |
| `frida://docs/{section_id}` | Individual doc section (11 sections) |

## Architecture

```
src/
├── index.ts                  # Entry point — McpServer + StdioServerTransport
├── state.ts                  # SessionManager singleton (sessions, scripts, messages)
├── utils.ts                  # resolveDevice, resolveAddressJS, wrapForExecution,
│                             #   executeTransientScript, truncateResult
├── resources.ts              # MCP resources (runtime + docs)
├── docs/
│   ├── index.ts              # DocStore — search/scoring over frida-api.json
│   └── frida-api.json        # Pre-parsed Frida 17 API documentation
├── injected/
│   ├── helpers.ts            # Frida 17-safe JS generators (modules, memory read/write/search)
│   ├── java-helpers.ts       # Java introspection, hooking, SSL bypass, file ops JS generators
│   └── hook-templates.ts     # Native hook JS generators
└── tools/
    ├── device.ts             # Device enumeration (4 tools)
    ├── process.ts            # Process management (6 tools)
    ├── session.ts            # Session management (5 tools)
    ├── script-mgmt.ts        # Script loading/RPC (4 tools)
    ├── export.ts             # One-shot RPC + capture export (1 tool)
    ├── memory.ts             # Module/memory operations (6 tools)
    ├── java.ts               # Java introspection & hooking (6 tools)
    ├── native-hooks.ts       # Native hooking (2 tools)
    ├── android.ts            # Android pentesting & file ops (5 tools)
    └── docs.ts               # Doc search (1 tool)
```

### Key Patterns

**SessionManager** — Unified state for all sessions, scripts, and messages. Replaces the Python server's 4 separate global dicts. Message queue is capped at 1000 to prevent unbounded memory growth; cleared/evicted messages are archived to disk as lightweight summaries, and large payload/data fields are offloaded to disk with blob references to keep tool output token-safe.

**Injected JS generators** — Template functions that produce Frida 17-compliant JavaScript. Rules: `var` (not `const`/`let`), no arrow functions, instance methods on `NativePointer` (not `Memory.readX`), `Process.getModuleByName` (not `Module.*`).

**Promise-based execution** — `executeTransientScript` uses Promise-based message collection instead of `time.sleep()`. Scripts send an `execution_receipt` message and are auto-unloaded after.

**Output truncation** — `truncateResult()` binary-searches for the max array items that fit within 24KB to stay under MCP's token limit. Applied to `enumerate_processes`, `list_modules`, `list_exports`, `list_classes`, `get_session_messages`, and `read_session_message_blob`.

## Usage Examples

### Attach and execute code

```
1. enumerate_processes → find target PID
2. create_interactive_session(pid) → get session_id
3. execute_in_session(session_id, "Process.arch") → "arm64"
```

### Load a script and call RPC

```
1. create_interactive_session(pid) → session_id
2. load_script(session_id, "my_script.js") → detects rpc.exports: ["doStuff"]
3. call_rpc_export(session_id, script_id, "doStuff", [arg1, arg2]) → result
```

### Hook a native function

```
1. create_interactive_session(pid) → session_id
2. hook_function(session_id, "libnative.so+0x1234", log_args=true, num_args=4) → hook_id
3. (trigger the function on device)
4. get_session_messages(session_id) → hook arg/retval logs
```

### One-step RPC + capture export to disk

```
1. create_interactive_session(pid) → session_id
2. load_script(session_id, "/path/hook.js") → script_id
3. export_capture_bundle(
     session_id,
     rpc={script_id, method:"getSignings"},
     include_messages=true,
     clear_mode="returned",
     response_detail="path_only"
   ) → output_path + slim summaries
```

### Hook a Java method

```
1. create_interactive_session(pid) → session_id
2. list_classes(session_id, filter="com.example") → find target class
3. list_methods(session_id, "com.example.ApiClient") → find target method
4. android_hook_method(session_id, "com.example.ApiClient", "sendRequest") → hook_id
5. (trigger the method on device)
6. get_session_messages(session_id) → method args/retval logs
```

### Bypass SSL pinning

```
1. create_interactive_session(pid) → session_id
2. android_ssl_pinning_disable(session_id) → script_id
3. get_session_messages(session_id) → list of bypassed targets
```

### Search and patch memory

```
1. create_interactive_session(pid) → session_id
2. search_memory(session_id, pattern="secret_key", pattern_type="string") → addresses
3. read_memory(session_id, "0x7f1234") → hex dump
4. write_memory(session_id, "0x7f1234", "00 00 00 00") → bytes written
```

### Browse files on target device

```
1. create_interactive_session(pid) → session_id
2. file_ls(session_id, "/data/data/com.example.app") → directory listing
3. file_read(session_id, "/data/data/com.example.app/shared_prefs/config.xml") → file content
```

### Search Frida 17 docs

```
1. search_frida_docs("Module.findExportByName") → migration guide ranked first
2. search_frida_docs("Interceptor.attach") → instrumentation section with examples
3. search_frida_docs("Java.perform", limit=3, offset=3) → next page of snippet results
```

## Frida 17 Notes

This server is built for Frida 17 compatibility. Key differences from older Frida versions:

- **No `Module.findExportByName()`** — Use `Process.getModuleByName(name).findExportByName(sym)` instead
- **No `Memory.readX()` static methods** — Use `NativePointer` instance methods: `ptr(addr).readU32()`
- **No `enumerateXSync()` methods** — Use `Process.enumerateModules()`, `module.enumerateExports()`
- **`var` instead of `const`/`let`** in injected scripts — Avoids issues with Frida's V8 runtime in some contexts
- **Java bridge moved in Frida 17** — Java-capable tools compile scripts with `frida-java-bridge` and inject `globalThis.Java` before running user code

The `search_frida_docs` tool automatically boosts the migration guide when you query deprecated API names.

## Operational Skill (Recommended)

For reliable Frida MCP operation (Frida 17), use the companion skills repository: `https://github.com/yfe404/frida-mcp-skills`.

The `frida-mcp-workflow` skill enforces a strict workflow: `Idea -> Scripting -> Execution -> Notes`. It also enforces docs-first usage, file-based scripts over large inline payloads, and script lifecycle hygiene (track/unload scripts to avoid duplicate hooks on the same target).

## Development

```bash
# Build
npm run build

# Run all tests (unit + integration)
npm test

# Run only unit tests
npm run test:unit

# Run only integration tests
npm run test:integration

# Run device tests (requires USB device with frida-server)
npm run test:device

# Fetch/update Frida API docs
npm run fetch-docs
```

### Test Structure

```
test/
├── unit/              # 137 tests — pure logic, no device needed
│   ├── utils.test.ts
│   ├── injected-helpers.test.ts
│   ├── injected-java.test.ts
│   ├── injected-hooks.test.ts
│   ├── session-manager.test.ts
│   └── doc-store.test.ts
├── integration/       # 12 tests — MCP server via InMemoryTransport + stdio
│   ├── mcp-server.test.ts
│   └── stdio-smoke.test.ts
├── device/            # 5 tests — auto-skip when no USB device
│   └── device-smoke.test.ts
└── fixtures/
    └── frida-api-fixture.json
```

## License

MIT
