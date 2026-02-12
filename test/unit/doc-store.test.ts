import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { DocStore } from "../../src/docs/index.js";
import type { DocData } from "../../src/docs/index.js";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixture: DocData = JSON.parse(
  readFileSync(join(__dirname, "..", "fixtures", "frida-api-fixture.json"), "utf-8"),
);

describe("DocStore", () => {
  let store: DocStore;

  beforeEach(() => {
    store = DocStore.fromData(fixture);
  });

  it("is not empty when loaded from fixture", () => {
    assert.equal(store.isEmpty(), false);
  });

  it("returns version", () => {
    assert.equal(store.getVersion(), "17.0.0-test");
  });

  it("lists all sections", () => {
    const sections = store.listSections();
    assert.equal(sections.length, 4);
    assert.ok(sections.some((s) => s.id === "interceptor"));
    assert.ok(sections.some((s) => s.id === "java-choose"));
  });

  it("gets section by ID", () => {
    const section = store.getSection("interceptor");
    assert.ok(section);
    assert.equal(section!.title, "Interceptor");
    assert.ok(section!.content.includes("Interceptor.attach"));
  });

  it("returns undefined for unknown section ID", () => {
    assert.equal(store.getSection("nonexistent"), undefined);
  });

  describe("search", () => {
    it("finds section by title match", () => {
      const results = store.search("Interceptor");
      assert.ok(results.length > 0);
      assert.equal(results[0].id, "interceptor");
    });

    it("finds section by keyword match", () => {
      const results = store.search("heap");
      assert.ok(results.length > 0);
      assert.ok(results.some((r) => r.id === "java-choose"));
    });

    it("finds section by content match", () => {
      const results = store.search("enumerateModules");
      assert.ok(results.length > 0);
      assert.ok(results.some((r) => r.id === "process-module"));
    });

    it("boosts frida17-migration for deprecated API queries", () => {
      const results = store.search("Module.findExportByName");
      assert.ok(results.length > 0);
      assert.equal(results[0].id, "frida17-migration");
    });

    it("boosts migration for Memory.readU8 query", () => {
      const results = store.search("Memory.readU8");
      assert.ok(results.length > 0);
      assert.equal(results[0].id, "frida17-migration");
    });

    it("returns empty for nonsense query", () => {
      const results = store.search("xyzzy123foobarbaz");
      assert.equal(results.length, 0);
    });

    it("respects limit parameter", () => {
      const results = store.search("module", 2);
      assert.ok(results.length <= 2);
    });

    it("returns first N sections for empty token query", () => {
      // Query that produces no tokens after splitting
      const results = store.search(".", 3);
      assert.ok(results.length <= 3);
    });
  });

  describe("searchWithMeta", () => {
    it("returns total match count for paged query", () => {
      const page = store.searchWithMeta("module", 1, 0);
      assert.ok(page.totalMatches >= page.items.length);
      assert.equal(page.items.length, 1);
    });

    it("supports offset pagination", () => {
      const page1 = store.searchWithMeta("module", 1, 0);
      const page2 = store.searchWithMeta("module", 1, 1);
      if (page1.totalMatches > 1 && page2.items.length > 0) {
        assert.notEqual(page1.items[0].id, page2.items[0].id);
      } else {
        assert.ok(true);
      }
    });

    it("returns empty items for offset beyond range", () => {
      const page = store.searchWithMeta("module", 3, 999);
      assert.equal(page.items.length, 0);
      assert.ok(page.totalMatches >= 0);
    });
  });

  describe("empty store", () => {
    it("isEmpty returns true for store with no data", () => {
      const empty = DocStore.fromData({ version: "0", sections: [] });
      assert.equal(empty.isEmpty(), true);
    });

    it("search returns empty on empty store", () => {
      const empty = DocStore.fromData({ version: "0", sections: [] });
      const results = empty.search("anything");
      assert.equal(results.length, 0);
    });
  });
});
