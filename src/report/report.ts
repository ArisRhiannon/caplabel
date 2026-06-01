// Renders an Inspection as a layperson-readable label. JSON output is just the
// Inspection object itself (locations included), chosen by the CLI in M8.

import type { Capability, Finding, Inspection, RiskPattern } from "../corpus/types";

type Cat = Capability | "UNVERIFIABLE";

const ICON: Record<Cat, string> = {
  NETWORK: "🌐", FILESYSTEM: "📁", EXEC: "⚙", ENV_SECRETS: "🔑",
  CRYPTO: "🔒", NATIVE_FFI: "🧩", UNVERIFIABLE: "⚠",
};
const NAME: Record<Cat, string> = {
  NETWORK: "NETWORK", FILESYSTEM: "FILESYSTEM", EXEC: "EXEC", ENV_SECRETS: "ENV/SECRETS",
  CRYPTO: "CRYPTO", NATIVE_FFI: "NATIVE", UNVERIFIABLE: "UNVERIFIABLE",
};
const ORDER: Cat[] = ["NETWORK", "FILESYSTEM", "EXEC", "ENV_SECRETS", "CRYPTO", "NATIVE_FFI", "UNVERIFIABLE"];

const RISK_DESC: Record<RiskPattern, string> = {
  EXFILTRATION: "reads secrets and sends data out",
  DROPPER: "downloads and runs code",
  STARTUP_PERSISTENCE: "writes a startup file to persist",
};

export function verdict(r: Inspection): string {
  if (r.risks.length) return "HIGH RISK";
  if (r.unverifiable) return "REVIEW — unverifiable";
  if (r.capabilities.some((c) => c === "EXEC" || c === "NETWORK" || c === "ENV_SECRETS")) return "CAUTION";
  if (r.capabilities.length) return "LOW";
  return "LIKELY SAFE";
}

export function renderHuman(r: Inspection, filename: string): string {
  const rule = "─".repeat(44);
  const lines = [`CAPLABEL · ${filename}`, rule];
  const firstByCap = new Map<Cat, Finding>();
  for (const f of r.findings) if (!firstByCap.has(f.capability)) firstByCap.set(f.capability, f);

  let any = false;
  for (const cap of ORDER) {
    const f = firstByCap.get(cap);
    if (!f) continue;
    any = true;
    lines.push(`${ICON[cap]}  ${NAME[cap].padEnd(12)} ${f.detail}  (line ${f.location.line})`);
  }
  if (!any) lines.push("· no capabilities detected");
  lines.push(rule);
  for (const rp of r.risks) lines.push(`RISK: ${rp} — ${RISK_DESC[rp]}`);
  lines.push(`VERDICT: ${verdict(r)}`);
  return lines.join("\n");
}
