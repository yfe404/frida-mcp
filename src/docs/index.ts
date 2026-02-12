/**
 * DocStore — loads and searches pre-parsed Frida 17 API docs.
 *
 * Scoring: title match × 3, keyword match × 2, content match × 1.
 * The frida17-migration section is boosted when the query mentions
 * deprecated method names.
 */

import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

export interface DocSection {
  id: string;
  title: string;
  category: string;
  content: string;
  keywords: string[];
  examples: string[];
}

export interface DocData {
  version: string;
  sections: DocSection[];
}

export interface DocSearchResult {
  items: DocSection[];
  totalMatches: number;
}

// Known deprecated identifiers that should boost the migration section
const DEPRECATED_NAMES = [
  "Module.findExportByName",
  "Module.enumerateExports",
  "Module.getBaseAddress",
  "Memory.readU8", "Memory.readU16", "Memory.readU32", "Memory.readU64",
  "Memory.readS8", "Memory.readS16", "Memory.readS32", "Memory.readS64",
  "Memory.readFloat", "Memory.readDouble",
  "Memory.readByteArray", "Memory.readUtf8String", "Memory.readUtf16String",
  "Memory.writeU8", "Memory.writeU16", "Memory.writeU32", "Memory.writeU64",
  "Memory.writeFloat", "Memory.writeDouble",
  "Memory.writeByteArray", "Memory.writeUtf8String", "Memory.writeUtf16String",
  "Memory.readPointer", "Memory.writePointer",
  "enumerateModulesSync", "enumerateExportsSync", "enumerateRangesSync",
];

export class DocStore {
  private sections: DocSection[] = [];
  private version = "unknown";

  constructor(data?: DocData) {
    if (data) {
      this.sections = data.sections;
      this.version = data.version;
    } else {
      this.load();
    }
  }

  static fromData(data: DocData): DocStore {
    return new DocStore(data);
  }

  private load(): void {
    try {
      const __dirname = dirname(fileURLToPath(import.meta.url));
      const jsonPath = join(__dirname, "frida-api.json");
      const raw = readFileSync(jsonPath, "utf-8");
      const data: DocData = JSON.parse(raw);
      this.sections = data.sections;
      this.version = data.version;
    } catch {
      // If docs aren't built yet, degrade gracefully
      this.sections = [];
    }
  }

  search(query: string, limit = 5): DocSection[] {
    return this.searchWithMeta(query, limit, 0).items;
  }

  searchWithMeta(query: string, limit = 5, offset = 0): DocSearchResult {
    if (this.sections.length === 0) {
      return { items: [], totalMatches: 0 };
    }

    const normalizedLimit = Math.max(0, Math.trunc(limit));
    const normalizedOffset = Math.max(0, Math.trunc(offset));
    const scored = this.scoreSections(query);
    const totalMatches = scored.length;
    if (normalizedLimit === 0) {
      return { items: [], totalMatches };
    }
    const items = scored
      .slice(normalizedOffset, normalizedOffset + normalizedLimit)
      .map((s) => s.section);

    return { items, totalMatches };
  }

  private scoreSections(query: string): Array<{ section: DocSection; score: number }> {
    const tokens = query
      .toLowerCase()
      .split(/[\s.,:;()+]+/)
      .filter((t) => t.length > 1);

    if (tokens.length === 0) {
      return this.sections.map((section) => ({ section, score: 1 }));
    }

    // Check if query references deprecated APIs
    const mentionsDeprecated = DEPRECATED_NAMES.some(
      (d) => query.includes(d) || tokens.some((t) => d.toLowerCase().includes(t)),
    );

    const scored = this.sections.map((section) => {
      let score = 0;
      const titleLower = section.title.toLowerCase();
      const keywordsLower = section.keywords.map((k) => k.toLowerCase());
      const contentLower = section.content.toLowerCase();

      for (const token of tokens) {
        if (titleLower.includes(token)) score += 3;
        if (keywordsLower.some((k) => k.includes(token))) score += 2;
        if (contentLower.includes(token)) score += 1;
      }

      // Boost migration section for deprecated API queries
      if (mentionsDeprecated && section.id === "frida17-migration") {
        score += 5;
      }

      return { section, score };
    });

    return scored
      .filter((s) => s.score > 0)
      .sort((a, b) => b.score - a.score);
  }

  getSection(id: string): DocSection | undefined {
    return this.sections.find((s) => s.id === id);
  }

  listSections(): { id: string; title: string; category: string }[] {
    return this.sections.map((s) => ({
      id: s.id,
      title: s.title,
      category: s.category,
    }));
  }

  getVersion(): string {
    return this.version;
  }

  isEmpty(): boolean {
    return this.sections.length === 0;
  }
}

// Singleton
export const docStore = new DocStore();
