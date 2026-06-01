import { test, expect } from "bun:test";
import { evaluate } from "../metrics/metrics";
import { analyze } from "../analyze/analyze";
import { FIXTURES, KNOWN_GAPS } from "./fixtures";
import { CAPABILITIES } from "./types";

const report = evaluate(FIXTURES, analyze);

test("HARD GATE: zero false-safe across the IN-SCOPE corpus", () => {
  if (report.falseSafe.length) console.error("FALSE-SAFE fixtures:", report.falseSafe);
  expect(report.falseSafe).toEqual([]);
  expect(report.falseSafeRate).toBe(0);
});

test("all evasion/opacity fixtures are flagged (unverifiable recall = 1)", () => {
  expect(report.unverifiableRecall).toBe(1);
});

test("precision and recall >= 0.9 for every category with positives", () => {
  for (const c of CAPABILITIES) {
    const m = report.perCategory[c];
    if (m.tp + m.fn === 0) continue; // no positives in corpus → skip vacuous metric
    expect(m.recall).toBeGreaterThanOrEqual(0.9);
    expect(m.precision).toBeGreaterThanOrEqual(0.9);
  }
});

test("KNOWN GAPS are tracked, non-gating (documents current false-safes honestly)", () => {
  const gaps = evaluate(KNOWN_GAPS, analyze);
  console.log("\nTRACKED known-gap false-safes (to close in a future opacity pass):", gaps.falseSafe);
  // All known gaps are currently unhandled; this count drops (and the test flips)
  // the moment any gap is fixed, forcing it to be promoted into the in-scope corpus.
  expect(gaps.falseSafe.length).toBe(KNOWN_GAPS.length);
});

test("metrics report (informational)", () => {
  console.log(`\nin-scope n=${report.n}  falseSafeRate=${report.falseSafeRate}  unverifiableRecall=${report.unverifiableRecall}`);
  for (const c of CAPABILITIES) {
    const m = report.perCategory[c];
    console.log(`  ${c.padEnd(12)} tp=${m.tp} fp=${m.fp} fn=${m.fn} P=${m.precision.toFixed(2)} R=${m.recall.toFixed(2)}`);
  }
  expect(report.n).toBeGreaterThanOrEqual(28);
});
