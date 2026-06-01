import { test, expect } from "bun:test";
import { detectOpacity } from "./opacity";
import { analyze } from "./analyze";

const unv = (code: string) => analyze(code).unverifiable;

test("eval is opaque", () => expect(unv(`eval(payload);`)).toBe(true));
test("new Function is opaque", () => expect(unv(`const f = new Function('a', 'return a');`)).toBe(true));
test("atob is opaque", () => expect(unv(`const s = atob('aGk=');`)).toBe(true));
test("Buffer.from base64 is opaque", () => expect(unv(`const b = Buffer.from(x, 'base64');`)).toBe(true));
test("module.require indirection is opaque", () => expect(unv(`module.require('fs');`)).toBe(true));
test("comma-operator (0, require) is opaque", () => expect(unv(`const r = (0, require)('fs');`)).toBe(true));
test("computed globalThis access is opaque", () => expect(unv(`globalThis['pr' + 'ocess'];`)).toBe(true));

test("benign code is NOT opaque (precision)", () => {
  const code = `const fs = require('fs');\nfs.readFileSync('a');\nconst y = obj.from(x, 'utf8');`;
  expect(unv(code)).toBe(false);
});

test("require.resolve is not flagged as indirection", () => {
  expect(detectOpacity(`require.resolve('fs');`).length).toBe(0);
});

test("typeof require env-detection is NOT flagged (UMD/CJS precision)", () => {
  expect(unv(`if (typeof require !== "undefined") { doThing(); }`)).toBe(false);
  expect(unv(`const has = typeof require === "function";`)).toBe(false);
});
