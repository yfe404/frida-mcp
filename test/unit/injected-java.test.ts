import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { listClassesJS, findInstancesJS } from "../../src/injected/java-helpers.js";

describe("listClassesJS", () => {
  it("returns syntactically valid JS", () => {
    const code = listClassesJS();
    new Function(code);
  });

  it("uses Java.perform and enumerateLoadedClasses", () => {
    const code = listClassesJS();
    assert.ok(code.includes("Java.perform"));
    assert.ok(code.includes("Java.enumerateLoadedClasses"));
  });

  it("without filter does not include filter check", () => {
    const code = listClassesJS();
    assert.ok(!code.includes("indexOf"));
  });

  it("with filter includes case-insensitive check", () => {
    const code = listClassesJS("com.example");
    assert.ok(code.includes("toLowerCase"));
    assert.ok(code.includes("com.example"));
  });

  it("caps results at 500", () => {
    const code = listClassesJS();
    assert.ok(code.includes("500"));
  });
});

describe("findInstancesJS", () => {
  it("returns syntactically valid JS", () => {
    const code = findInstancesJS("com.example.MyClass", 5);
    new Function(code);
  });

  it("uses Java.choose with className", () => {
    const code = findInstancesJS("com.example.MyClass", 5);
    assert.ok(code.includes("Java.choose"));
    assert.ok(code.includes("com.example.MyClass"));
  });

  it("includes getLong for primitive long fields", () => {
    const code = findInstancesJS("com.example.MyClass", 5);
    assert.ok(code.includes("getLong"));
  });

  it("includes getInt and getBoolean reflection", () => {
    const code = findInstancesJS("any.Class", 3);
    assert.ok(code.includes("getInt"));
    assert.ok(code.includes("getBoolean"));
  });

  it("respects maxInstances parameter", () => {
    const code = findInstancesJS("Test", 10);
    assert.ok(code.includes(">= 10"));
  });

  it("uses var not const/let", () => {
    const code = findInstancesJS("Test", 5);
    assert.ok(!code.includes("const "));
    assert.ok(!code.includes("let "));
  });
});
