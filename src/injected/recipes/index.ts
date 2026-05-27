/**
 * Recipe registry: name → metadata. Used by recipe-search and describe_recipe
 * tools. Templates themselves live in sibling files.
 */

export interface RecipeMetadata {
  slug: string;
  description: string;
  parameters: { name: string; required: boolean; description: string }[];
  emits: { type: string; meaning: string }[];
}

export const RECIPES: RecipeMetadata[] = [
  {
    slug: "hook_okhttp_requests",
    description:
      "Snoop every finalized OkHttp Request. Catches all clients regardless of which Interceptor chain they use. Emits URL, method, headers, optional body, optional Java stack.",
    parameters: [
      { name: "session_id", required: true, description: "Frida session id." },
      { name: "url_includes", required: false, description: "Skip emit unless URL contains this substring." },
      { name: "where", required: false, description: "JS predicate on event object; default 'true'." },
      { name: "include_stack", required: false, description: "Attach Java stack trace to each event." },
      { name: "include_body", required: false, description: "Read request body via okio.Buffer (will buffer the body)." },
      { name: "max_body_bytes", required: false, description: "Cap on body bytes when include_body=true." },
    ],
    emits: [
      { type: "okhttp.request", meaning: "Finalized Request: url, method, headers, [body, stack]." },
      { type: "okhttp.installed", meaning: "Hook installation receipt." },
      { type: "okhttp.error", meaning: "Per-request hook fault, non-fatal." },
    ],
  },
  {
    slug: "hook_java_method",
    description:
      "Hook all overloads of a Java method. Emits args on enter, retval on leave, optional stack. Source-side filter (`where`), per-string truncate, optional emit cap.",
    parameters: [
      { name: "session_id", required: true, description: "Frida session id." },
      { name: "class_name", required: true, description: "Fully qualified Java class." },
      { name: "method_name", required: true, description: "Method to hook (all overloads)." },
      { name: "where", required: false, description: "JS predicate on event object." },
      { name: "log_args", required: false, description: "Default true." },
      { name: "log_retval", required: false, description: "Default true." },
      { name: "log_backtrace", required: false, description: "Default false." },
      { name: "max_emits", required: false, description: "Cap on emitted events. 0 = unlimited." },
      { name: "truncate_at", required: false, description: "Truncate any single string arg/retval at this many chars." },
    ],
    emits: [
      { type: "java.enter", meaning: "Method entry: cls, method, overload, tid, [args, stack]." },
      { type: "java.leave", meaning: "Method exit: retval." },
      { type: "java.installed", meaning: "Hook installation receipt: total overloads hooked." },
    ],
  },
  {
    slug: "hook_native_export",
    description:
      "Attach to a single exported symbol of a native module. Captures the first N register-width args and the retval. Uses Frida 17 Process.getModuleByName().getExportByName().",
    parameters: [
      { name: "session_id", required: true, description: "Frida session id." },
      { name: "module", required: true, description: "Module name, e.g. 'libnative.so'." },
      { name: "symbol", required: true, description: "Exported symbol name." },
      { name: "where", required: false, description: "JS predicate on event object." },
      { name: "num_args", required: false, description: "How many register-width args to capture; default 4." },
      { name: "decode_ret_as_cstring", required: false, description: "Read retval as a UTF-8 C string." },
    ],
    emits: [
      { type: "native.call", meaning: "One invocation: module, symbol, args, retval." },
      { type: "native.installed", meaning: "Hook installed at address." },
      { type: "native.error", meaning: "Symbol not found or other hook failure." },
    ],
  },
  {
    slug: "trace_class_methods",
    description:
      "Lightweight method-call tracer over a class name pattern. Emits one event per call (no args/retval). Use to discover what fires; then promote interesting methods to hook_java_method.",
    parameters: [
      { name: "session_id", required: true, description: "Frida session id." },
      { name: "class_filter", required: true, description: "Substring or '/regex/'. Matched against loaded class FQCN." },
      { name: "method_filter", required: false, description: "Optional substring on method name." },
      { name: "where", required: false, description: "JS predicate on event object." },
      { name: "max_methods", required: false, description: "Hard cap on # of hooks (default 200) to keep install time bounded." },
    ],
    emits: [
      { type: "trace.call", meaning: "Method call: cls, method, overload, tid." },
      { type: "trace.installed", meaning: "Number of overloads actually hooked." },
    ],
  },
  {
    slug: "dump_mac_doFinal",
    description:
      "Hooks both overloads of javax.crypto.Mac.doFinal. Emits algorithm, input UTF-8/base64, and output base64. Generic crypto observer — exactly what cracked Expedia's HMAC.",
    parameters: [
      { name: "session_id", required: true, description: "Frida session id." },
      { name: "where", required: false, description: "JS predicate on event object." },
      { name: "include_input", required: false, description: "Include input bytes; default true." },
    ],
    emits: [
      { type: "mac.doFinal", meaning: "One HMAC/CMAC operation: algorithm, input, output." },
      { type: "mac.installed", meaning: "Hook installation receipt." },
      { type: "mac.error", meaning: "Per-call hook fault." },
    ],
  },
  {
    slug: "bypass_root_detection",
    description:
      "Patches File.exists for su paths, Runtime.exec('su'), Build.TAGS test-keys. Derivative of @dzonerzy/fridantiroot + objection.",
    parameters: [
      { name: "session_id", required: true, description: "Frida session id." },
      { name: "where", required: false, description: "JS predicate on event object." },
    ],
    emits: [
      { type: "root_bypass.installed", meaning: "Hook installation receipt." },
      { type: "root_bypass.file.exists", meaning: "Reports each su-path File.exists short-circuit." },
      { type: "root_bypass.runtime.exec.blocked", meaning: "Reports each blocked Runtime.exec call." },
      { type: "root_bypass.error", meaning: "Per-hook fault, non-fatal." },
    ],
  },
  {
    slug: "bypass_ssl_pinning",
    description:
      "Install TrustAllCerts + null hostname verifier + OkHttp3 CertificatePinner + Conscrypt TrustManagerImpl bypass. Same template as android_ssl_pinning_disable.",
    parameters: [
      { name: "session_id", required: true, description: "Frida session id." },
    ],
    emits: [
      { type: "ssl_pinning_disabled", meaning: "Receipt listing which hook variants succeeded." },
    ],
  },
];
