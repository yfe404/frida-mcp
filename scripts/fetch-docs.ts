/**
 * fetch-docs.ts — fetches Frida JS API markdown from GitHub, parses into
 * sections, adds hand-curated frida17-migration section, writes frida-api.json.
 *
 * Run: npx tsx scripts/fetch-docs.ts
 */

import { writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUTPUT = join(__dirname, "..", "src", "docs", "frida-api.json");

const DOCS_URL =
  "https://raw.githubusercontent.com/frida/frida-website/main/_i18n/en/_docs/javascript-api.md";

interface DocSection {
  id: string;
  title: string;
  category: string;
  content: string;
  keywords: string[];
  examples: string[];
}

function slugify(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function extractKeywords(title: string, content: string): string[] {
  const kws = new Set<string>();

  // Method signatures: word.word( or word(
  const methodRe = /\b(\w+(?:\.\w+)*)\s*\(/g;
  let m;
  while ((m = methodRe.exec(content)) !== null) {
    kws.add(m[1]);
  }

  // Class/module names from title
  for (const w of title.split(/[\s,]+/)) {
    if (w.length > 1) kws.add(w);
  }

  return [...kws].slice(0, 50);
}

function extractExamples(content: string): string[] {
  const examples: string[] = [];
  const codeRe = /```(?:js|javascript)?\n([\s\S]*?)```/g;
  let m;
  while ((m = codeRe.exec(content)) !== null) {
    examples.push(m[1].trim());
  }
  return examples;
}

function inferCategory(title: string, content: string): string {
  const lower = title.toLowerCase();
  if (/process|thread|module|memory/.test(lower)) return "Process, Thread, Module and Memory";
  if (/interceptor|stalker/.test(lower)) return "Code Instrumentation";
  if (/java/.test(lower)) return "Java Bridge";
  if (/objc/.test(lower)) return "ObjC Bridge";
  if (/nativepointer|nativefunction|nativecallback/.test(lower)) return "Native Types";
  if (/socket|iostream|file/.test(lower)) return "I/O";
  if (/console|hexdump/.test(lower)) return "Console";
  if (/frida|runtime/.test(lower)) return "Runtime";
  return "Other";
}

async function main() {
  console.log(`Fetching Frida JS API docs from GitHub...`);
  const resp = await fetch(DOCS_URL);
  if (!resp.ok) {
    console.error(`Failed to fetch: ${resp.status} ${resp.statusText}`);
    console.log("Generating docs from hand-curated content only...");
    writeFallback();
    return;
  }

  const markdown = await resp.text();
  console.log(`Fetched ${(markdown.length / 1024).toFixed(1)}KB of markdown`);

  // Split on ## headings (top-level API classes)
  const h2Parts = markdown.split(/^## /m).filter((p) => p.trim().length > 0);

  const sections: DocSection[] = [];

  for (const part of h2Parts) {
    const nlIdx = part.indexOf("\n");
    if (nlIdx === -1) continue;

    const title = part.substring(0, nlIdx).trim();
    if (!title || title.startsWith("Table of") || title.startsWith("---")) continue;

    const content = part.substring(nlIdx + 1).trim();
    const id = slugify(title);
    if (!id) continue;

    sections.push({
      id,
      title,
      category: inferCategory(title, content),
      content: `## ${title}\n\n${content}`,
      keywords: extractKeywords(title, content),
      examples: extractExamples(content),
    });
  }

  // Add hand-curated Frida 17 migration section
  sections.push(createMigrationSection());

  const data = {
    version: "17.6.2",
    sections,
  };

  writeFileSync(OUTPUT, JSON.stringify(data, null, 2));
  console.log(`Wrote ${sections.length} sections to ${OUTPUT}`);
}

function createMigrationSection(): DocSection {
  return {
    id: "frida17-migration",
    title: "Frida 17 Migration Guide",
    category: "Migration",
    content: `## Frida 17 Migration Guide

### Breaking Changes in Frida 17

#### Module static methods removed
\`Module.findExportByName(module, name)\` → \`Process.getModuleByName(module).getExportByName(name)\`
\`Module.enumerateExports(module)\` → \`Process.getModuleByName(module).enumerateExports()\`
\`Module.findBaseAddress(module)\` → \`Process.getModuleByName(module).base\`
\`Module.getBaseAddress(module)\` → \`Process.getModuleByName(module).base\`

#### Memory static read/write methods removed
\`Memory.readU8(ptr)\` → \`ptr.readU8()\`
\`Memory.readU16(ptr)\` → \`ptr.readU16()\`
\`Memory.readU32(ptr)\` → \`ptr.readU32()\`
\`Memory.readU64(ptr)\` → \`ptr.readU64()\`
\`Memory.readPointer(ptr)\` → \`ptr.readPointer()\`
\`Memory.readByteArray(ptr, len)\` → \`ptr.readByteArray(len)\`
\`Memory.readUtf8String(ptr)\` → \`ptr.readUtf8String()\`
\`Memory.readUtf16String(ptr)\` → \`ptr.readUtf16String()\`
\`Memory.writeU8(ptr, val)\` → \`ptr.writeU8(val)\`
\`Memory.writeU16(ptr, val)\` → \`ptr.writeU16(val)\`
\`Memory.writeU32(ptr, val)\` → \`ptr.writeU32(val)\`
\`Memory.writeU64(ptr, val)\` → \`ptr.writeU64(val)\`
\`Memory.writePointer(ptr, val)\` → \`ptr.writePointer(val)\`
\`Memory.writeByteArray(ptr, arr)\` → \`ptr.writeByteArray(arr)\`
\`Memory.writeUtf8String(ptr, str)\` → \`ptr.writeUtf8String(str)\`
\`Memory.writeUtf16String(ptr, str)\` → \`ptr.writeUtf16String(str)\`

#### Callback-style enumeration removed
\`Process.enumerateModules({ onMatch, onComplete })\` → \`Process.enumerateModules()\` (returns array)
\`Module.enumerateExports({ onMatch, onComplete })\` → \`mod.enumerateExports()\` (returns array)
\`Module.enumerateRanges({ onMatch, onComplete })\` → \`mod.enumerateRanges(prot)\` (returns array)
The \`*Sync\` variants are also removed — the non-Sync versions now return arrays directly.

#### Module.findExportByName instance method
Use \`Process.findModuleByName(name)\` first, then call \`.getExportByName(sym)\` on the result:
\`\`\`js
var mod = Process.getModuleByName("libc.so");
var addr = mod.getExportByName("open");
\`\`\`

#### hexdump is a global built-in
Do NOT define your own \`function hexdump()\` — it shadows the built-in Frida \`hexdump(target, options)\`.
Use a different name like \`dumpHex()\` if you need a custom implementation.

### Project-Specific Pitfalls (TikTok X-Argus)
- \`g2.LIZ.value\` returns \`undefined\` for primitive \`long\` — use reflection: \`f.getLong(instance)\`
- \`DmtSec.frameSign\` is an INSTANCE method on a Kotlin singleton — \`Java.use()\` can't call it as static
- Use \`Java.choose('ms.bd.o.g2')\` to find live instances (bypasses Kotlin wrapper issues)
- Hook base64 at \`0x13c7e8\` only when \`insideFrameSign=true\` to avoid crashes during init
- The base64 encoder at \`0x13c7e8\` takes 5 args (x0-x4), returns int, NOT pointer
`,
    keywords: [
      "Module.findExportByName", "Memory.readU32", "Memory.readPointer",
      "Memory.writeU32", "enumerateModulesSync", "enumerateExportsSync",
      "deprecated", "migration", "breaking", "removed", "frida17",
      "hexdump", "getLong", "DmtSec", "g2",
    ],
    examples: [
      `// Old (Frida 16):\nvar addr = Module.findExportByName("libc.so", "open");\n\n// New (Frida 17):\nvar mod = Process.getModuleByName("libc.so");\nvar addr = mod.getExportByName("open");`,
      `// Old (Frida 16):\nvar val = Memory.readU32(ptr("0x1234"));\n\n// New (Frida 17):\nvar val = ptr("0x1234").readU32();`,
    ],
  };
}

function writeFallback() {
  const data = {
    version: "17.6.2",
    sections: [createMigrationSection()],
  };
  writeFileSync(OUTPUT, JSON.stringify(data, null, 2));
  console.log(`Wrote fallback (1 section) to ${OUTPUT}`);
}

main().catch((e) => {
  console.error("Fatal:", e);
  process.exit(1);
});
