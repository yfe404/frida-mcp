import { appendFileSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

export interface ResolvedExportPath {
  outputPath: string;
  generatedDefault: boolean;
}

export function resolveExportPath(
  baseDir: string,
  sessionId: string,
  outputPath?: string,
  now: Date = new Date(),
): ResolvedExportPath {
  if (outputPath && outputPath.trim().length > 0) {
    return {
      outputPath: resolve(outputPath),
      generatedDefault: false,
    };
  }

  const stamp = now.toISOString().replace(/[:.]/g, "-");
  return {
    outputPath: join(baseDir, sessionId, "exports", `${stamp}-bundle.jsonl`),
    generatedDefault: true,
  };
}

export function ensureParentDirSync(filePath: string): void {
  mkdirSync(dirname(filePath), { recursive: true });
}

export function appendJsonlRecordSync(filePath: string, record: unknown): number {
  const line = `${JSON.stringify(record)}\n`;
  appendFileSync(filePath, line, "utf8");
  return Buffer.byteLength(line, "utf8");
}

export function serializeForExport(value: unknown): string {
  if (typeof value === "string") return value;
  if (value === undefined) return "undefined";
  try {
    const json = JSON.stringify(value);
    return json === undefined ? "undefined" : json;
  } catch (e) {
    const fallback = {
      serialization_error: String(e),
      value_preview: String(value),
    };
    return JSON.stringify(fallback);
  }
}

export function makeSafeFileStem(input: string, fallback: string): string {
  const cleaned = input.replace(/[^a-zA-Z0-9._-]+/g, "_").replace(/^_+|_+$/g, "");
  return (cleaned.length > 0 ? cleaned : fallback).slice(0, 64);
}
