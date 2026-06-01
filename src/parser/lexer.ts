// Minimal JS lexer. Emits identifiers, string values, template literals, and
// punctuators while correctly consuming comments and string/regex contents.
// Template substitutions (`${ ... }`) are lexed as real code. Never executes input.

export interface Token {
  type: "ident" | "string" | "template" | "punct" | "num" | "regex";
  value: string;
  dynamic?: boolean;
  line: number;
  col: number;
}

const ID_START = /[A-Za-z_$]/;
const ID_PART = /[A-Za-z0-9_$]/;

const REGEX_AFTER_PUNCT = new Set([
  "(", ",", "=", ":", "[", "!", "&", "|", "?", "{", "}", ";", "+", "-", "*", "%", "<", ">", "~", "^",
]);
const REGEX_AFTER_KEYWORD = new Set([
  "return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw", "case", "do", "else", "yield", "await",
]);

export function tokenize(src: string): Token[] {
  const tokens: Token[] = [];
  const n = src.length;
  let i = 0;
  let line = 1;
  let col = 1;
  let braceDepth = 0;
  const tmplStack: number[] = [];

  const peek = (k: number) => src[i + k] ?? "";
  function adv(k = 1) {
    while (k-- > 0) {
      if (src[i] === "\n") { line++; col = 1; } else { col++; }
      i++;
    }
  }
  function regexAllowed(): boolean {
    const p = tokens[tokens.length - 1];
    const p2 = tokens[tokens.length - 2];
    if (!p) return true;
    // postfix ++ / -- : the following `/` is division, not a regex
    if (p.type === "punct" && (p.value === "+" || p.value === "-") && p2?.type === "punct" && p2.value === p.value) {
      return false;
    }
    if (p.type === "punct") return REGEX_AFTER_PUNCT.has(p.value);
    if (p.type === "ident") return REGEX_AFTER_KEYWORD.has(p.value);
    return false;
  }
  function scanTemplateChunk() {
    const sl = line, sc = col;
    let val = "";
    while (i < n) {
      if (src[i] === "`") { adv(); tokens.push({ type: "template", value: val, dynamic: false, line: sl, col: sc }); return; }
      if (src[i] === "\\") { val += peek(1); adv(2); continue; }
      if (src[i] === "$" && peek(1) === "{") {
        tokens.push({ type: "template", value: val, dynamic: true, line: sl, col: sc });
        adv(2); tmplStack.push(braceDepth); return;
      }
      val += src[i]; adv();
    }
    tokens.push({ type: "template", value: val, dynamic: false, line: sl, col: sc });
  }

  while (i < n) {
    const c = src[i]!;
    if (c === " " || c === "\t" || c === "\r" || c === "\n") { adv(); continue; }
    if (c === "/" && peek(1) === "/") { while (i < n && src[i] !== "\n") adv(); continue; }
    if (c === "/" && peek(1) === "*") { adv(2); while (i < n && !(src[i] === "*" && peek(1) === "/")) adv(); adv(2); continue; }
    if (c === "'" || c === '"') {
      const sl = line, sc = col, q = c;
      adv();
      let val = "";
      while (i < n && src[i] !== q) {
        if (src[i] === "\\") { val += peek(1); adv(2); continue; }
        if (src[i] === "\n") break;
        val += src[i]; adv();
      }
      adv();
      tokens.push({ type: "string", value: val, line: sl, col: sc });
      continue;
    }
    if (c === "`") { adv(); scanTemplateChunk(); continue; }
    if (c === "{") { const sl = line, sc = col; adv(); braceDepth++; tokens.push({ type: "punct", value: "{", line: sl, col: sc }); continue; }
    if (c === "}") {
      const sl = line, sc = col;
      if (tmplStack.length > 0 && braceDepth === tmplStack[tmplStack.length - 1]) {
        tmplStack.pop(); adv(); scanTemplateChunk(); continue;
      }
      adv(); if (braceDepth > 0) braceDepth--; tokens.push({ type: "punct", value: "}", line: sl, col: sc }); continue;
    }
    if (c === "/" && regexAllowed()) {
      const sl = line, sc = col;
      adv();
      let inClass = false;
      while (i < n) {
        const d = src[i]!;
        if (d === "\\") { adv(2); continue; }
        if (d === "[") inClass = true;
        else if (d === "]") inClass = false;
        else if (d === "/" && !inClass) { adv(); break; }
        else if (d === "\n") break;
        adv();
      }
      while (i < n && ID_PART.test(src[i]!)) adv();
      tokens.push({ type: "regex", value: "", line: sl, col: sc });
      continue;
    }
    // \uXXXX-escaped identifier (e.g. \u0065val === eval) — capture with the backslash
    if (c === "\\" && peek(1) === "u") {
      const sl = line, sc = col;
      let val = "";
      while (i < n && (ID_PART.test(src[i]!) || src[i] === "\\")) { val += src[i]; adv(); }
      tokens.push({ type: "ident", value: val, line: sl, col: sc });
      continue;
    }
    if (ID_START.test(c)) {
      const sl = line, sc = col;
      let val = "";
      while (i < n && ID_PART.test(src[i]!)) { val += src[i]; adv(); }
      tokens.push({ type: "ident", value: val, line: sl, col: sc });
      continue;
    }
    if (c >= "0" && c <= "9") {
      const sl = line, sc = col;
      let val = "";
      while (i < n && /[0-9._a-fA-FxXeEno]/.test(src[i]!)) { val += src[i]; adv(); }
      tokens.push({ type: "num", value: val, line: sl, col: sc });
      continue;
    }
    // optional chaining `?.` as a single token
    if (c === "?" && peek(1) === ".") { const sl = line, sc = col; adv(2); tokens.push({ type: "punct", value: "?.", line: sl, col: sc }); continue; }
    const sl = line, sc = col;
    adv();
    tokens.push({ type: "punct", value: c, line: sl, col: sc });
  }
  return tokens;
}
