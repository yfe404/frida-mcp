# frida-mcp-ts

TypeScript MCP server for Frida 17 dynamic instrumentation. Provides 37 tools and 15 resources for attaching to processes, executing scripts, hooking native and Java methods, bypassing SSL pinning, reading/writing memory, inspecting Java heaps, and searching Frida 17 API documentation — all through the Model Context Protocol.

## Quick Start

```bash
# Install dependencies
npm install

# Build the docs index (optional but recommended)
npm run fetch-docs

# Build
npm run build

# Run
npm start
```

### Configure for Claude Code

Add to your `.mcp.json`:

```json
{
  "mcpServers": {
    "frida": {
      "command": "node",
      "args": ["/path/to/frida-mcp-ts/dist/index.js"]
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

### Session Tools (3)

| Tool | Description | Key Params |
|------|-------------|------------|
| `create_interactive_session` | Attach and create a managed session | `process_id`, `device_id?` |
| `execute_in_session` | Execute JS in session (transient or persistent) | `session_id`, `javascript_code`, `keep_alive?` |
| `get_session_messages` | Retrieve queued messages with pagination | `session_id`, `limit?`, `offset?` |

### Script Management Tools (4)

| Tool | Description | Key Params |
|------|-------------|------------|
| `load_script` | Load JS file from disk, auto-detect RPC exports | `session_id`, `file_path`, `script_id?` |
| `list_scripts` | List loaded scripts with metadata | `session_id` |
| `unload_script` | Unload a script | `session_id`, `script_id` |
| `call_rpc_export` | Call an RPC-exported method | `session_id`, `script_id`, `method`, `args?` |

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

### Android Tools (5)

| Tool | Description | Key Params |
|------|-------------|------------|
| `android_ssl_pinning_disable` | Bypass SSL pinning (TrustManager, SSLContext, OkHttp, TrustManagerImpl) | `session_id`, `script_id?` |
| `android_get_current_activity` | Get foreground activity via ActivityThread reflection | `session_id` |
| `list_apps` | List installed applications (identifier, name, PID) | `device_id?` |
| `file_ls` | List directory contents on target device (Java File API) | `session_id`, `path` |
| `file_read` | Read a text file from target device | `session_id`, `path`, `max_size?` |

### Documentation Tools (1)

| Tool | Description | Key Params |
|------|-------------|------------|
| `search_frida_docs` | Full-text search Frida 17 API docs | `query`, `limit?` |

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
    ├── session.ts            # Session management (3 tools)
    ├── script-mgmt.ts        # Script loading/RPC (4 tools)
    ├── memory.ts             # Module/memory operations (6 tools)
    ├── java.ts               # Java introspection & hooking (6 tools)
    ├── native-hooks.ts       # Native hooking (2 tools)
    ├── android.ts            # Android pentesting & file ops (5 tools)
    └── docs.ts               # Doc search (1 tool)
```

### Key Patterns

**SessionManager** — Unified state for all sessions, scripts, and messages. Replaces the Python server's 4 separate global dicts. Message queue is capped at 1000 to prevent unbounded memory growth.

**Injected JS generators** — Template functions that produce Frida 17-compliant JavaScript. Rules: `var` (not `const`/`let`), no arrow functions, instance methods on `NativePointer` (not `Memory.readX`), `Process.getModuleByName` (not `Module.*`).

**Promise-based execution** — `executeTransientScript` uses Promise-based message collection instead of `time.sleep()`. Scripts send an `execution_receipt` message and are auto-unloaded after.

**Output truncation** — `truncateResult()` binary-searches for the max array items that fit within 24KB to stay under MCP's token limit. Applied to `enumerate_processes`, `list_modules`, `list_exports`, `list_classes`, and `get_session_messages`.

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
```

## Frida 17 Notes

This server is built for Frida 17 compatibility. Key differences from older Frida versions:

- **No `Module.findExportByName()`** — Use `Process.getModuleByName(name).findExportByName(sym)` instead
- **No `Memory.readX()` static methods** — Use `NativePointer` instance methods: `ptr(addr).readU32()`
- **No `enumerateXSync()` methods** — Use `Process.enumerateModules()`, `module.enumerateExports()`
- **`var` instead of `const`/`let`** in injected scripts — Avoids issues with Frida's V8 runtime in some contexts

The `search_frida_docs` tool automatically boosts the migration guide when you query deprecated API names.

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
