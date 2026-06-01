// Shared vocabulary for caplabel: what a piece of code is capable of,
// how a labeled corpus fixture is shaped, and the analyzer contract.

/** Real-world capabilities a piece of code can exercise. */
export type Capability =
  | "NETWORK"
  | "FILESYSTEM"
  | "EXEC"
  | "ENV_SECRETS"
  | "CRYPTO"
  | "NATIVE_FFI";

export const CAPABILITIES: readonly Capability[] = [
  "NETWORK",
  "FILESYSTEM",
  "EXEC",
  "ENV_SECRETS",
  "CRYPTO",
  "NATIVE_FFI",
];

/** High-confidence, context-aware risk patterns (named only when the combo is strong). */
export type RiskPattern = "EXFILTRATION" | "DROPPER" | "STARTUP_PERSISTENCE";

/**
 * A capability label: the set of capabilities found/expected, whether any part
 * of the code could NOT be resolved statically (`unverifiable` -> treated as
 * high risk, never a silent "safe"), and any named risk patterns.
 */
export interface Label {
  capabilities: Capability[];
  unverifiable: boolean;
  risks?: RiskPattern[];
}

/** A single labeled corpus entry: source code + its ground-truth label. */
export interface Fixture {
  name: string;
  code: string;
  expected: Label;
  kind?: "synthetic" | "benign" | "malware-pattern" | "evasion";
}

/** The analyzer contract. Implemented from M1 onward; never executes `code`. */
export type Analyze = (code: string, filename?: string) => Label;

/** A source position, 1-based, for `file:line:col` evidence. */
export interface Location {
  line: number;
  column: number;
}

/** A single located piece of evidence the analyzer found. */
export interface Finding {
  capability: Capability | "UNVERIFIABLE";
  detail: string;
  location: Location;
}

/** Full inspection result: the summary label plus located evidence. */
export interface Inspection {
  capabilities: Capability[];
  unverifiable: boolean;
  risks: RiskPattern[];
  findings: Finding[];
}
