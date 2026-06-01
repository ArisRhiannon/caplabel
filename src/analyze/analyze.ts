// Maps resolved imports (M1) to capabilities, folds in opacity (M3) and ambient
// globals (M4), produces a conservative named-risk verdict (M5), and exposes
// located evidence via inspect() (M6). analyze() is the Label-only contract.

import { resolveImports } from "../parser/imports";
import { detectOpacity } from "./opacity";
import { detectAmbient } from "./ambient";
import { assessRisk } from "./risk";
import type { Analyze, Capability, Finding, Inspection, Label } from "../corpus/types";

const MODULE_CAPABILITY: Record<string, Capability> = {
  net: "NETWORK",
  tls: "NETWORK",
  http: "NETWORK",
  https: "NETWORK",
  http2: "NETWORK",
  dgram: "NETWORK",
  dns: "NETWORK",
  inspector: "NETWORK",
  fs: "FILESYSTEM",
  child_process: "EXEC",
  vm: "EXEC",
  worker_threads: "EXEC",
  cluster: "EXEC",
  module: "EXEC",
  process: "ENV_SECRETS",
  crypto: "CRYPTO",
};

/** Capability of a module specifier, or null. Strips `node:` and submodules. */
export function moduleCapability(specifier: string): Capability | null {
  const noScheme = specifier.startsWith("node:") ? specifier.slice(5) : specifier;
  const base = noScheme.split("/")[0]!;
  return MODULE_CAPABILITY[base] ?? null;
}

/** Full inspection with located evidence. */
export function inspect(code: string, _filename?: string): Inspection {
  const { refs, findings: dynamic } = resolveImports(code);
  const findings: Finding[] = [];
  for (const ref of refs) {
    const cap = moduleCapability(ref.module);
    if (cap) findings.push({ capability: cap, detail: `imports '${ref.module}'`, location: ref.location });
  }
  findings.push(...dynamic, ...detectOpacity(code));
  const ambient = detectAmbient(code);
  findings.push(...ambient.findings);

  const capSet = new Set<Capability>();
  for (const f of findings) if (f.capability !== "UNVERIFIABLE") capSet.add(f.capability);
  const unverifiable = findings.some((f) => f.capability === "UNVERIFIABLE");
  const risks = assessRisk(capSet, {
    startupTarget: ambient.startupTarget,
    secretFile: ambient.secretFile,
    unverifiable,
  });
  return { capabilities: [...capSet], unverifiable, risks, findings };
}

export const analyze: Analyze = (code) => {
  const r = inspect(code);
  const label: Label = { capabilities: r.capabilities, unverifiable: r.unverifiable };
  if (r.risks.length) label.risks = r.risks;
  return label;
};
