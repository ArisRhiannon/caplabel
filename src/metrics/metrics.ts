// Ground-truth evaluation harness. Given labeled fixtures and an analyzer,
// compute per-capability precision/recall, opacity (UNVERIFIABLE) recall, and
// the safety-critical false-safe rate (predicting "clean" on dangerous code).

import { CAPABILITIES } from "../corpus/types";
import type { Capability, Label, Fixture, Analyze } from "../corpus/types";

export interface CategoryMetric {
  tp: number;
  fp: number;
  fn: number;
  precision: number;
  recall: number;
}

export interface Report {
  perCategory: Record<Capability, CategoryMetric>;
  /** Of fixtures whose ground truth is unverifiable, the fraction flagged unverifiable. */
  unverifiableRecall: number;
  /** Fraction of dangerous fixtures the analyzer wrongly reported as clean. */
  falseSafeRate: number;
  /** Names of the false-safe fixtures (the ones that matter most). */
  falseSafe: string[];
  n: number;
}

/** Vacuously perfect (1) when there are no positives to score. */
function ratio(num: number, den: number): number {
  return den === 0 ? 1 : num / den;
}

/** A label is "clean/safe" only if it has no capabilities and nothing unverifiable. */
function isSafe(l: Label): boolean {
  return l.capabilities.length === 0 && !l.unverifiable;
}

export function evaluate(fixtures: Fixture[], analyze: Analyze): Report {
  const per = {} as Record<Capability, CategoryMetric>;
  for (const c of CAPABILITIES) per[c] = { tp: 0, fp: 0, fn: 0, precision: 0, recall: 0 };

  let unverifiableExpected = 0;
  let unverifiableHit = 0;
  let dangerous = 0;
  const falseSafe: string[] = [];

  for (const f of fixtures) {
    const pred = analyze(f.code, f.name);
    const expected = new Set(f.expected.capabilities);
    const got = new Set(pred.capabilities);

    for (const c of CAPABILITIES) {
      const e = expected.has(c);
      const g = got.has(c);
      if (e && g) per[c].tp++;
      else if (!e && g) per[c].fp++;
      else if (e && !g) per[c].fn++;
    }

    if (f.expected.unverifiable) {
      unverifiableExpected++;
      if (pred.unverifiable) unverifiableHit++;
    }

    if (!isSafe(f.expected)) {
      dangerous++;
      if (isSafe(pred)) falseSafe.push(f.name);
    }
  }

  for (const c of CAPABILITIES) {
    const m = per[c];
    m.precision = ratio(m.tp, m.tp + m.fp);
    m.recall = ratio(m.tp, m.tp + m.fn);
  }

  return {
    perCategory: per,
    unverifiableRecall: ratio(unverifiableHit, unverifiableExpected),
    falseSafeRate: dangerous === 0 ? 0 : falseSafe.length / dangerous,
    falseSafe,
    n: fixtures.length,
  };
}
