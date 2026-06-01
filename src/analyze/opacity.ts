// Detects evasion/opacity: constructs that hide what code does, so the analyzer
// never silently calls such code "clean". Each becomes UNVERIFIABLE.

import { tokenize, type Token } from "../parser/lexer";
import type { Finding, Location } from "../corpus/types";

const loc = (t: Token): Location => ({ line: t.line, column: t.col });
const isP = (t: Token | undefined, v: string) => t?.type === "punct" && t.value === v;
const isI = (t: Token | undefined, v: string) => t?.type === "ident" && t.value === v;
const isDot = (t: Token | undefined) => t?.type === "punct" && (t.value === "." || t.value === "?.");
const callAfter = (tokens: Token[], i: number) =>
  isP(tokens[i + 1], "(") || (isP(tokens[i + 1], "?.") && isP(tokens[i + 2], "("));

const OPAQUE_CALLS = new Set(["eval", "atob", "unescape"]);
const REQUIRE_HOLDERS = new Set(["module", "global", "globalThis", "this", "process", "Module"]);

export function detectOpacity(src: string): Finding[] {
  const tokens = tokenize(src);
  const out: Finding[] = [];
  const flag = (t: Token, detail: string) =>
    out.push({ capability: "UNVERIFIABLE", detail, location: loc(t) });

  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i]!;
    // \u-escaped identifier (e.g. \u0065val) — real name is hidden
    if (t.type === "ident" && t.value.includes("\\")) {
      flag(t, "unicode-escaped identifier hides its name");
      continue;
    }
    if (t.type !== "ident") continue;
    const next = tokens[i + 1];
    const prevDot = isDot(tokens[i - 1]);

    if (!prevDot && OPAQUE_CALLS.has(t.value) && callAfter(tokens, i)) {
      flag(t, `${t.value}() hides its input`);
    } else if (!prevDot && t.value === "Function" && callAfter(tokens, i)) {
      flag(t, "Function() builds code from a string");
    } else if (t.value === "require" && prevDot && callAfter(tokens, i)) {
      const holder = tokens[i - 2];
      if (holder?.type === "ident" && REQUIRE_HOLDERS.has(holder.value)) {
        flag(t, `indirect require via ${holder.value}.require`);
      }
    } else if (t.value === "require" && !prevDot && isP(next, "?.") && isP(tokens[i + 2], "(")) {
      flag(t, "optional-call require indirection");
    } else if (
      t.value === "require" &&
      !prevDot &&
      !isI(tokens[i - 1], "typeof") &&
      next &&
      !isP(next, "(") &&
      !isP(next, ".") &&
      !isP(next, "?.") &&
      !isP(next, ":")
    ) {
      flag(t, "require referenced as a value (indirection)");
    } else if (!prevDot && (t.value === "globalThis" || t.value === "global") && isP(next, "[")) {
      flag(t, `computed property access on ${t.value}`);
    } else if (t.value === "Buffer" && isDot(next) && isI(tokens[i + 2], "from") && isP(tokens[i + 3], "(")) {
      let depth = 0;
      for (let j = i + 3; j < tokens.length; j++) {
        const u = tokens[j]!;
        if (isP(u, "(")) depth++;
        else if (isP(u, ")")) { depth--; if (depth === 0) break; }
        else if (u.type === "string" && (u.value === "base64" || u.value === "hex")) {
          flag(t, "Buffer.from(…, 'base64'/'hex') decodes a payload");
          break;
        }
      }
    }
  }
  return out;
}
