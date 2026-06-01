// Resolves which local names refer to which modules/members, from import and
// require, including destructuring and aliasing. Dynamic specifiers (non-literal
// module names) become UNVERIFIABLE findings — never silently dropped.

import { tokenize, type Token } from "./lexer";
import type { Finding, Location } from "../corpus/types";

export type ImportRef =
  | { kind: "namespace"; module: string; local: string; location: Location }
  | { kind: "named"; module: string; local: string; imported: string; location: Location }
  | { kind: "inline"; module: string; location: Location };

export interface ImportResult {
  refs: ImportRef[];
  findings: Finding[];
}

const KW_DECL = new Set(["const", "let", "var"]);
const loc = (t: Token): Location => ({ line: t.line, column: t.col });
const isPunct = (t: Token | undefined, v: string) => t?.type === "punct" && t.value === v;
const isDot = (t: Token | undefined) => t?.type === "punct" && (t.value === "." || t.value === "?.");
const isIdent = (t: Token | undefined, v?: string) =>
  t?.type === "ident" && (v === undefined || t.value === v);

/** Static module name from a call argument token, or null if dynamic/unknown. */
function staticSpecifier(t: Token | undefined): string | null {
  if (!t) return null;
  if (t.type === "string") return t.value;
  if (t.type === "template" && !t.dynamic) return t.value;
  return null;
}

/** Walk left from a require()/import() call to recover its variable binding. */
type Binding =
  | { kind: "namespace"; local: string }
  | { kind: "named"; entries: { imported: string; local: string }[] }
  | null;

function resolveBinding(tokens: Token[], callIdx: number): Binding {
  let j = callIdx - 1;
  if (isIdent(tokens[j], "await")) j--;
  if (!isPunct(tokens[j], "=")) return null; // not an initializer -> inline
  j--;

  // simple identifier:  const X = require(...)
  if (tokens[j]?.type === "ident" && isDecl(tokens[j - 1])) {
    return { kind: "namespace", local: tokens[j]!.value };
  }

  // destructuring:  const { a, b: c } = require(...)
  if (isPunct(tokens[j], "}")) {
    let depth = 1;
    let k = j - 1;
    const inner: Token[] = [];
    while (k >= 0 && depth > 0) {
      const t = tokens[k]!;
      if (isPunct(t, "}")) depth++;
      else if (isPunct(t, "{")) {
        depth--;
        if (depth === 0) break;
      }
      if (depth > 0) inner.unshift(t);
      k--;
    }
    if (!isDecl(tokens[k - 1])) return null;
    const entries: { imported: string; local: string }[] = [];
    for (let m = 0; m < inner.length; ) {
      const t = inner[m]!;
      if (t.type === "ident") {
        const imported = t.value;
        if (isPunct(inner[m + 1], ":") && inner[m + 2]?.type === "ident") {
          entries.push({ imported, local: inner[m + 2]!.value });
          m += 3;
        } else {
          entries.push({ imported, local: imported });
          m += 1;
        }
      } else m++;
    }
    return { kind: "named", entries };
  }
  return null;
}

function isDecl(t: Token | undefined): boolean {
  return t?.type === "ident" && KW_DECL.has(t.value);
}

/** Parse a static `import ... from 'mod'` statement; returns refs and next index. */
function parseEsmImport(tokens: Token[], start: number): { refs: ImportRef[]; next: number } {
  const at = tokens[start]!;
  let k = start + 1;
  let defaultLocal: string | null = null;
  let namespaceLocal: string | null = null;
  const named: { imported: string; local: string }[] = [];
  let module: string | null = null;

  // side-effect import: import 'mod';
  const spec0 = staticSpecifier(tokens[k]);
  if (spec0 !== null) return { refs: [], next: k + 1 };

  while (k < tokens.length) {
    const t = tokens[k]!;
    if (isIdent(t, "from")) {
      module = staticSpecifier(tokens[k + 1]);
      k += 2;
      break;
    }
    if (isPunct(t, ";")) {
      k++;
      break;
    }
    if (isPunct(t, "*")) {
      if (isIdent(tokens[k + 1], "as") && tokens[k + 2]?.type === "ident") {
        namespaceLocal = tokens[k + 2]!.value;
        k += 3;
        continue;
      }
      k++;
      continue;
    }
    if (isPunct(t, "{")) {
      let m = k + 1;
      while (m < tokens.length && !isPunct(tokens[m], "}")) {
        if (tokens[m]!.type === "ident") {
          const imported = tokens[m]!.value;
          if (isIdent(tokens[m + 1], "as") && tokens[m + 2]?.type === "ident") {
            named.push({ imported, local: tokens[m + 2]!.value });
            m += 3;
          } else {
            named.push({ imported, local: imported });
            m += 1;
          }
        } else m++;
      }
      k = m + 1;
      continue;
    }
    if (t.type === "ident") {
      defaultLocal = t.value;
      k++;
      continue;
    }
    k++;
  }

  const refs: ImportRef[] = [];
  if (module !== null) {
    if (defaultLocal) refs.push({ kind: "namespace", module, local: defaultLocal, location: loc(at) });
    if (namespaceLocal) refs.push({ kind: "namespace", module, local: namespaceLocal, location: loc(at) });
    for (const e of named) refs.push({ kind: "named", module, local: e.local, imported: e.imported, location: loc(at) });
  }
  return { refs, next: k };
}

export function resolveImports(src: string, _filename?: string): ImportResult {
  const tokens = tokenize(src);
  const refs: ImportRef[] = [];
  const findings: Finding[] = [];

  for (let idx = 0; idx < tokens.length; idx++) {
    const t = tokens[idx]!;
    if (t.type !== "ident") continue;
    const prev = tokens[idx - 1];
    if (isDot(prev)) continue; // member access, not a real import/require

    const isCall = isPunct(tokens[idx + 1], "(");

    if (t.value === "require" && isCall) {
      addCall(tokens, idx, "require", refs, findings);
      continue;
    }
    if (t.value === "import") {
      if (isCall) {
        addCall(tokens, idx, "import", refs, findings);
        continue;
      }
      const parsed = parseEsmImport(tokens, idx);
      refs.push(...parsed.refs);
      idx = parsed.next - 1;
      continue;
    }
    if (t.value === "export" && (isPunct(tokens[idx + 1], "*") || isPunct(tokens[idx + 1], "{"))) {
      // re-export: `export * from 'mod'` / `export { x } from 'mod'` pulls mod's API through.
      let k = idx + 1;
      let mod: string | null = null;
      while (k < tokens.length && !isPunct(tokens[k], ";")) {
        if (isIdent(tokens[k], "from")) {
          mod = staticSpecifier(tokens[k + 1]);
          k += 2;
          break;
        }
        k++;
      }
      if (mod !== null) refs.push({ kind: "inline", module: mod, location: loc(t) });
      idx = k - 1;
    }
  }
  return { refs, findings };
}

function addCall(
  tokens: Token[],
  idx: number,
  kw: "require" | "import",
  refs: ImportRef[],
  findings: Finding[],
): void {
  const module = staticSpecifier(tokens[idx + 2]); // token after '('
  // Must be EXACTLY one string literal closed by ')': anything else (concat,
  // ternary, computed) is a dynamic specifier we cannot resolve.
  if (module === null || !isPunct(tokens[idx + 3], ")")) {
    findings.push({
      capability: "UNVERIFIABLE",
      detail: `dynamic module specifier in ${kw}()`,
      location: loc(tokens[idx]!),
    });
    return;
  }
  const binding = resolveBinding(tokens, idx);
  const location = loc(tokens[idx]!);
  if (binding === null) {
    refs.push({ kind: "inline", module, location });
  } else if (binding.kind === "namespace") {
    refs.push({ kind: "namespace", module, local: binding.local, location });
  } else {
    for (const e of binding.entries) {
      refs.push({ kind: "named", module, local: e.local, imported: e.imported, location });
    }
  }
}
