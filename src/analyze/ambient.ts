// Capabilities not coming through an import: global network calls
// (fetch/WebSocket), process.env access, and reads of well-known secret paths.
// Emits located findings; reports secret-FILE and startup-file risk signals.

import { tokenize, type Token } from "../parser/lexer";
import type { Finding, Location } from "../corpus/types";

const loc = (t: Token): Location => ({ line: t.line, column: t.col });
const isP = (t: Token | undefined, v: string) => t?.type === "punct" && t.value === v;
const isI = (t: Token | undefined, v: string) => t?.type === "ident" && t.value === v;
const isDot = (t: Token | undefined) => t?.type === "punct" && (t.value === "." || t.value === "?.");
const callAfter = (tokens: Token[], i: number) =>
  isP(tokens[i + 1], "(") || (isP(tokens[i + 1], "?.") && isP(tokens[i + 2], "("));

const NET_GLOBALS = new Set(["fetch", "WebSocket", "XMLHttpRequest", "EventSource"]);

const SECRET_HINTS = [
  ".ssh/", "id_rsa", "id_ed25519", "/.aws/", "aws/credentials",
  "/etc/passwd", "/etc/shadow", ".git-credentials", ".npmrc",
];
const STARTUP_HINTS = [
  ".bashrc", ".zshrc", ".bash_profile", ".profile", "crontab",
  "/etc/cron", "autostart", "launchagents", "systemd/",
];

export interface AmbientResult {
  findings: Finding[];
  secretFile: boolean;
  startupTarget: boolean;
}

export function detectAmbient(src: string): AmbientResult {
  const tokens = tokenize(src);
  const findings: Finding[] = [];
  let secretFile = false;
  let startupTarget = false;
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i]!;
    if (t.type === "ident") {
      const prevDot = isDot(tokens[i - 1]);
      const isDecl = isI(tokens[i - 1], "function");
      if (!prevDot && !isDecl && NET_GLOBALS.has(t.value) && callAfter(tokens, i)) {
        findings.push({ capability: "NETWORK", detail: `global ${t.value}()`, location: loc(t) });
      }
      if (!prevDot && t.value === "process" && isDot(tokens[i + 1]) && isI(tokens[i + 2], "env")) {
        findings.push({ capability: "ENV_SECRETS", detail: "reads process.env", location: loc(t) });
      }
    } else if (t.type === "string") {
      const v = t.value.toLowerCase();
      if (SECRET_HINTS.some((h) => v.includes(h))) {
        findings.push({ capability: "ENV_SECRETS", detail: `secret path '${t.value}'`, location: loc(t) });
        secretFile = true;
      }
      if (STARTUP_HINTS.some((h) => v.includes(h))) startupTarget = true;
    }
  }
  return { findings, secretFile, startupTarget };
}
