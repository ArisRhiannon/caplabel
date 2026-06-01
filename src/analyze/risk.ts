// Conservative risk verdict. Capability co-occurrence alone is NOT a risk
// (env+network is every API client; exec+network is every CLI). A pattern fires
// only with a high-confidence extra signal: reading a real secret FILE, or
// obfuscation present, or writing a startup file.

import type { Capability, RiskPattern } from "../corpus/types";

export interface RiskSignals {
  startupTarget: boolean;
  secretFile: boolean;
  unverifiable: boolean;
}

export function assessRisk(caps: Set<Capability>, s: RiskSignals): RiskPattern[] {
  const risks: RiskPattern[] = [];
  const net = caps.has("NETWORK");
  if (net && ((s.secretFile && caps.has("FILESYSTEM")) || (caps.has("ENV_SECRETS") && s.unverifiable))) {
    risks.push("EXFILTRATION");
  }
  if (caps.has("EXEC") && net && s.unverifiable) risks.push("DROPPER");
  if (caps.has("FILESYSTEM") && s.startupTarget) risks.push("STARTUP_PERSISTENCE");
  return risks;
}
