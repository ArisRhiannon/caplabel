# caplabel

**See what a script can do before you run it.** Offline, zero-dependency static
capability labeler for JavaScript. It reads code **as text — never executes it** —
and tells you, in plain language, what the code is *capable of*, with `file:line`
evidence, and loudly flags what it *cannot* verify.

For the moment you're about to `curl | bash` an installer, add an npm dependency,
or run an AI-generated snippet you didn't write.

## What it reports

- **Capabilities** (each with evidence): `NETWORK`, `FILESYSTEM`, `EXEC`, `ENV/SECRETS`, `CRYPTO`.
- **`UNVERIFIABLE`** — obfuscation/dynamic constructs it cannot resolve (`eval`, `Function`,
  dynamic/`import(var)`/`require(var)`, concatenated specifiers, `Buffer.from(…,'base64')`,
  indirect/computed access, `\u`-escaped identifiers). It is **never silently "safe"**.
- **Named risks** — only on high-confidence combinations, to avoid crying wolf:
  - `EXFILTRATION` — a secret **file** read (e.g. `~/.ssh/id_rsa`, `/etc/passwd`) together with
    network egress, **or** an obfuscated `process.env` read plus network.
  - `DROPPER` — `EXEC` + `NETWORK` **when obfuscation is present**.
  - `STARTUP_PERSISTENCE` — `FILESYSTEM` + a startup-file path (`.bashrc`, `crontab`, …).

A single capability on its own is reported as a capability, **not** an alarm.

## Usage

```sh
bun src/cli/cli.ts <file> [--json]
```

Exit code (for CI gating): `0` ok/low/caution · `1` review (unverifiable) · `2` high risk.

Real output on a crafted malicious installer:

```
CAPLABEL · install.js
🌐  NETWORK      imports 'https'         (line 2)
📁  FILESYSTEM   imports 'fs'            (line 3)
⚙  EXEC          imports 'child_process' (line 1)
🔑  ENV/SECRETS  reads process.env       (line 3)
⚠  UNVERIFIABLE eval() hides its input  (line 5)
RISK: EXFILTRATION — reads secrets and sends data out
RISK: DROPPER — downloads and runs code
VERDICT: HIGH RISK
```

## Safety

caplabel **never executes, imports, `require`s, or `eval`s** the file under analysis —
it only tokenizes it as text. There is no code path from input to execution.

## Validation

- `bun test` → 80 tests; `tsc --noEmit` clean; **zero runtime dependencies**.
- A 29-fixture labeled corpus: **zero false-safe in-scope**, and precision = recall = 1.00
  for every capability category that has positives. This is a curated **regression/contract**
  set — not a claim of universal real-world accuracy.
- 5 evasion patterns are **tracked as known gaps** (non-gating, see below).

## Limitations

- **JavaScript only.** No TypeScript, shell, or Python yet.
- **Single file + local relative imports.** It does **not** walk `node_modules` / the
  dependency tree yet — so it answers "what can *this file* do", not "this package and all its deps".
- **Conservative, not a guarantee.** Anything it can't resolve becomes `UNVERIFIABLE`, never a
  silent "safe" — but it is **not** proof against a determined, deeply obfuscated adversary.
- **Tracked evasion gaps** (currently NOT caught, asserted in tests): `window['eval']`,
  `self['eval']`, `window.eval`, `setTimeout`/`setInterval('code')`, computed `process['env']`.
- **Native/FFI** capability detection is not implemented yet (`NATIVE_FFI` is a reserved category).
- The numbers above come from a curated seed corpus, not a real-world package sweep.

## Status

Prototype (v1). JS, single-file. Built test-first.

## License

MIT — see [LICENSE](LICENSE).
