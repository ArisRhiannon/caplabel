import { test, expect } from "bun:test";
import { resolveImports } from "./imports";
import type { ImportRef } from "./imports";

// Compare refs ignoring source location (asserted separately where it matters).
const strip = (refs: ImportRef[]) =>
  refs.map((r) => {
    const { location, ...rest } = r;
    return rest;
  });

test("require: namespace binding", () => {
  const r = resolveImports(`const fs = require('fs');`);
  expect(strip(r.refs)).toEqual([{ kind: "namespace", module: "fs", local: "fs" }]);
  expect(r.findings).toEqual([]);
});

test("require: destructured named binding", () => {
  const r = resolveImports(`const { exec } = require('child_process');`);
  expect(strip(r.refs)).toEqual([
    { kind: "named", module: "child_process", local: "exec", imported: "exec" },
  ]);
});

test("require: renamed destructured binding", () => {
  const r = resolveImports(`const { exec: run } = require('child_process');`);
  expect(strip(r.refs)).toEqual([
    { kind: "named", module: "child_process", local: "run", imported: "exec" },
  ]);
});

test("require: inline use without a variable binding", () => {
  const r = resolveImports(`require('child_process').exec('id');`);
  expect(strip(r.refs)).toEqual([{ kind: "inline", module: "child_process" }]);
  expect(r.findings).toEqual([]);
});

test("esm: default import", () => {
  const r = resolveImports(`import fs from 'fs';`);
  expect(strip(r.refs)).toEqual([{ kind: "namespace", module: "fs", local: "fs" }]);
});

test("esm: namespace import", () => {
  const r = resolveImports(`import * as cp from 'child_process';`);
  expect(strip(r.refs)).toEqual([{ kind: "namespace", module: "child_process", local: "cp" }]);
});

test("esm: named + aliased import", () => {
  const r = resolveImports(`import { exec, spawn as sp } from 'child_process';`);
  expect(strip(r.refs)).toEqual([
    { kind: "named", module: "child_process", local: "exec", imported: "exec" },
    { kind: "named", module: "child_process", local: "sp", imported: "spawn" },
  ]);
});

test("esm: default + named combo", () => {
  const r = resolveImports(`import fs, { readFile } from 'fs';`);
  expect(strip(r.refs)).toEqual([
    { kind: "namespace", module: "fs", local: "fs" },
    { kind: "named", module: "fs", local: "readFile", imported: "readFile" },
  ]);
});

test("dynamic require specifier -> UNVERIFIABLE, no ref", () => {
  const r = resolveImports(`const m = require(name);`);
  expect(r.refs).toEqual([]);
  expect(r.findings.length).toBe(1);
  expect(r.findings[0]!.capability).toBe("UNVERIFIABLE");
});

test("dynamic import() specifier -> UNVERIFIABLE", () => {
  const r = resolveImports("const m = await import(`${base}/x`);");
  expect(r.findings.length).toBe(1);
  expect(r.findings[0]!.capability).toBe("UNVERIFIABLE");
});

test("require-like text inside strings and comments is ignored", () => {
  const src = [
    `const s = "require('fs')";`,
    `// require('net')`,
    `/* require('dns') */`,
    "const t = `require('http')`;",
  ].join("\n");
  const r = resolveImports(src);
  expect(r.refs).toEqual([]);
  expect(r.findings).toEqual([]);
});

test("multiple bindings in one file, with locations", () => {
  const r = resolveImports(`const fs = require('fs');\nconst { exec } = require('child_process');`);
  expect(strip(r.refs)).toEqual([
    { kind: "namespace", module: "fs", local: "fs" },
    { kind: "named", module: "child_process", local: "exec", imported: "exec" },
  ]);
  expect(r.refs[1]!.location.line).toBe(2);
});

test("P0-1: concatenated specifier -> UNVERIFIABLE, not a bogus module", () => {
  const r = resolveImports(`const m = require('child_' + 'process');`);
  expect(r.refs).toEqual([]);
  expect(r.findings.length).toBe(1);
  expect(r.findings[0]!.capability).toBe("UNVERIFIABLE");
});

test("P0-2: a require hidden in a template substitution is not silently dropped", () => {
  const r = resolveImports("const x = `${require('child_process').execSync('id')}`;");
  expect(r.refs.some((x) => x.module === "child_process")).toBe(true);
});

test("P0-2: benign template interpolation stays quiet (no crying wolf)", () => {
  const r = resolveImports("const greet = `hello ${name} from ${host}`;");
  expect(r.refs).toEqual([]);
  expect(r.findings).toEqual([]);
});

test("P0-3: export ... from re-exports are captured as inline module refs", () => {
  const named = resolveImports(`export { exec } from 'child_process';`);
  expect(strip(named.refs)).toEqual([{ kind: "inline", module: "child_process" }]);
  const star = resolveImports(`export * from 'fs';`);
  expect(strip(star.refs)).toEqual([{ kind: "inline", module: "fs" }]);
});
