import { test, expect } from "bun:test";
import { evaluate } from "./metrics";
import type { Fixture, Label, Analyze, Capability } from "../corpus/types";

const L = (capabilities: Capability[], unverifiable = false): Label => ({
  capabilities,
  unverifiable,
});

test("a perfect analyzer scores precision/recall 1.0 and zero false-safe", () => {
  const fx: Fixture[] = [
    { name: "net", code: "", expected: L(["NETWORK"]) },
    { name: "fs", code: "", expected: L(["FILESYSTEM"]) },
    { name: "clean", code: "", expected: L([]) },
  ];
  const perfect: Analyze = (_c, name) => fx.find((f) => f.name === name)!.expected;
  const r = evaluate(fx, perfect);
  expect(r.perCategory.NETWORK.precision).toBe(1);
  expect(r.perCategory.NETWORK.recall).toBe(1);
  expect(r.falseSafeRate).toBe(0);
  expect(r.falseSafe).toEqual([]);
});

test("missing one capability is a recall loss, not a false-safe (still flagged)", () => {
  const fx: Fixture[] = [{ name: "a", code: "", expected: L(["NETWORK", "EXEC"]) }];
  const partial: Analyze = () => L(["NETWORK"]);
  const r = evaluate(fx, partial);
  expect(r.perCategory.EXEC.recall).toBe(0);
  expect(r.perCategory.NETWORK.recall).toBe(1);
  expect(r.falseSafeRate).toBe(0);
});

test("predicting clean on a dangerous fixture is a false-safe (the critical metric)", () => {
  const fx: Fixture[] = [{ name: "sneaky", code: "", expected: L(["EXEC"]) }];
  const blind: Analyze = () => L([]);
  const r = evaluate(fx, blind);
  expect(r.falseSafeRate).toBe(1);
  expect(r.falseSafe).toEqual(["sneaky"]);
});

test("unverifiable recall tracks opacity detection; missed opacity is also a false-safe", () => {
  const fx: Fixture[] = [
    { name: "obf1", code: "", expected: L([], true) },
    { name: "obf2", code: "", expected: L([], true) },
  ];
  const half: Analyze = (_c, name) => (name === "obf1" ? L([], true) : L([]));
  const r = evaluate(fx, half);
  expect(r.unverifiableRecall).toBe(0.5);
  expect(r.falseSafe).toEqual(["obf2"]);
  expect(r.falseSafeRate).toBe(0.5);
});

test("a false positive lowers precision", () => {
  const fx: Fixture[] = [{ name: "pure", code: "", expected: L([]) }];
  const overeager: Analyze = () => L(["NETWORK"]);
  const r = evaluate(fx, overeager);
  expect(r.perCategory.NETWORK.precision).toBe(0);
});
