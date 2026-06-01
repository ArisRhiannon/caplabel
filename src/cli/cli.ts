#!/usr/bin/env bun
// caplabel CLI. Reads a file as TEXT (never imports/executes it) and prints a
// capability label (human or --json). Exit code gates CI: 0 ok, 1 review, 2 high risk.

import { readFileSync } from "node:fs";
import { inspect } from "../analyze/analyze";
import { renderHuman, verdict } from "../report/report";

export interface CliResult {
  output: string;
  code: number;
}

export function run(args: string[], read: (f: string) => string): CliResult {
  const json = args.includes("--json");
  const file = args.find((a) => !a.startsWith("-"));
  if (!file) return { output: "usage: caplabel <file> [--json]", code: 1 };

  let source: string;
  try {
    source = read(file);
  } catch {
    return { output: `caplabel: cannot read '${file}'`, code: 1 };
  }

  const result = inspect(source, file);
  const output = json ? JSON.stringify(result, null, 2) : renderHuman(result, file);
  const v = verdict(result);
  const code = v === "HIGH RISK" ? 2 : v === "REVIEW — unverifiable" ? 1 : 0;
  return { output, code };
}

if (import.meta.main) {
  const r = run(process.argv.slice(2), (f) => readFileSync(f, "utf8"));
  console.log(r.output);
  process.exit(r.code);
}
