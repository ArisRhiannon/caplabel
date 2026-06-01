#!/usr/bin/env node
// Executable entry for the published package. Reads the file as text and runs
// the analyzer; never executes the input.
import { readFileSync } from "node:fs";
import { run } from "./cli";

const r = run(process.argv.slice(2), (f) => readFileSync(f, "utf8"));
console.log(r.output);
process.exit(r.code);
