import { test, expect } from "bun:test";
import { analyze } from "./analyze";

const caps = (code: string) => new Set(analyze(code).capabilities);

test("require fs -> FILESYSTEM", () => {
  expect(caps(`const fs = require('fs');`)).toEqual(new Set(["FILESYSTEM"]));
});

test("destructured child_process -> EXEC", () => {
  expect(caps(`const { exec } = require('child_process');`)).toEqual(new Set(["EXEC"]));
});

test("esm https -> NETWORK", () => {
  expect(caps(`import https from 'https';`)).toEqual(new Set(["NETWORK"]));
});

test("node: scheme is stripped", () => {
  expect(caps(`const fs = require('node:fs');`)).toEqual(new Set(["FILESYSTEM"]));
});

test("submodule dns/promises -> NETWORK", () => {
  expect(caps(`const dns = require('dns/promises');`)).toEqual(new Set(["NETWORK"]));
});

test("inline require maps too", () => {
  expect(caps(`require('child_process').exec('id');`)).toEqual(new Set(["EXEC"]));
});

test("multiple modules combine", () => {
  const code = `const https = require('https');\nconst { spawn } = require('child_process');`;
  expect(caps(code)).toEqual(new Set(["NETWORK", "EXEC"]));
});

test("dynamic specifier -> no caps but unverifiable", () => {
  const r = analyze(`const m = require(name);`);
  expect(r.capabilities).toEqual([]);
  expect(r.unverifiable).toBe(true);
});

test("benign third-party module -> no core capability, not unverifiable", () => {
  const r = analyze(`const _ = require('lodash');`);
  expect(r.capabilities).toEqual([]);
  expect(r.unverifiable).toBe(false);
});

test("dangerous core modules never map to nothing (false-safe regression)", () => {
  for (const m of ["child_process", "vm", "worker_threads", "cluster", "process", "module"]) {
    expect(analyze(`const x = require('${m}');`).capabilities.length).toBeGreaterThan(0);
  }
});
