# Issue 112 cleanup: AVA Neuro Tangle Guardian SAFE

Marker: `AVA 01610 1`.

This draft extracts the useful local defensive collector from issue #112 into a standalone, reviewable PowerShell script. It does not treat a heuristic finding as proof of compromise or attribution.

## Files

- `scripts/AVA_NeuroTangle_Guardian_v1_SAFE.ps1` - bounded local collection, baseline deltas, explicit decision bits, main and per-finding hash chains, capped JSONL evidence, SHA256 manifest, and encoded HTML portal.
- `scripts/Test_AVA_NeuroTangle_Guardian_v1_SAFE.ps1` - PowerShell AST policy, prohibited-command checks, negative fixtures, HTML-injection test, UNC-path test, collector-error test, and fail-closed JSON test.
- `.github/workflows/ava-neuro-tangle-safe-check.yml` - two bounded Windows-runner cycles, persisted-byte hash checks, chain continuity checks, corruption-stop test, and targeted lint.

## Defensive scope

The collector reads only its local authorized Windows host:

- computer and operating-system metadata;
- Defender and firewall status;
- local administrators, running processes and services;
- non-Microsoft scheduled tasks, excluding the retired AVA task name;
- local TCP listeners and connections;
- IPv4 neighbors, network adapters, and visible WLAN BSSIDs;
- recent Defender, PowerShell, and System events.

It does not scan or contact a remote host, modify Defender or firewall settings, alter accounts, registry, services, or tasks, delete evidence, exploit anything, or perform a counterattack.

## Bounded modes

Only these modes exist:

- `Once` - exactly one cycle.
- `Loop` - exactly `MaxCycles` cycles; accepted range is 1 through 10,080.
- `OpenPortal` - opens an already generated local HTML file.

There is no unlimited-loop sentinel and there are no task-installation modes. Persistence or SYSTEM execution is deliberately outside this change.

The output path must resolve to a local file-system drive. UNC roots and mapped network roots are rejected. Defaults remain:

- elevated process: `C:\Windows\SecurityGuardian\AVA_NeuroTangle_SAFE`
- standard user: `%LOCALAPPDATA%\AVA_NeuroTangle_SAFE`

Writes are constrained beneath that root. JSON replacements use a same-directory `.pending` file; an abandoned pending file causes a visible stop. JSONL files have a byte cap, the whole evidence tree has a byte cap, and the main chain has a cycle cap.

## Evidence order and verification

For each cycle the script:

1. acquires an output-directory mutex;
2. parses and verifies every existing main and branch entry;
3. verifies each archived snapshot and analysis against its recorded file hash;
4. reads or creates a structurally checked baseline;
5. writes cycle-specific snapshot and analysis files atomically;
6. hashes those exact persisted bytes;
7. appends the main block and updates state;
8. appends independent per-finding branch blocks and deduplicated alerts;
9. writes the manifest and HTML portal.

Malformed JSON/JSONL, a missing chain counterpart, a sequence gap, a previous-hash mismatch, an evidence-file mismatch, or a state/head mismatch stops the next cycle. Existing evidence is never silently reset.

The chain makes later modification detectable when actively verified; it does not make a user-writable directory immutable. Preserve important evidence on separately controlled storage.

## Analysis behavior

Collector failures use a stable `{ Available, Collector, Error }` shape and produce an `INCOMPLETE` result instead of causing a StrictMode property crash. Added and removed baseline items are reported. Decision bits explicitly cover Defender, firewall, ports, command lines, administrators, neighbors, WLAN, tasks, services, adapters, removed baseline entries, and collection gaps.

The risk score is the highest finding severity, not a sum. This prevents several low-confidence observations from automatically saturating to 100. The score is a triage aid only.

Every table header and cell in the portal is encoded with `WebUtility.HtmlEncode` before insertion into HTML.

## Review and bounded local use

Run the validator first:

```powershell
powershell.exe -NoProfile -File .\scripts\Test_AVA_NeuroTangle_Guardian_v1_SAFE.ps1
```

Then run one cycle into a dedicated local directory:

```powershell
powershell.exe -NoProfile -File .\scripts\AVA_NeuroTangle_Guardian_v1_SAFE.ps1 `
  -Mode Once `
  -OutputDirectory C:\AVA\NeuroTangleReview
```

A finite five-cycle review run is:

```powershell
powershell.exe -NoProfile -File .\scripts\AVA_NeuroTangle_Guardian_v1_SAFE.ps1 `
  -Mode Loop `
  -MaxCycles 5 `
  -IntervalSeconds 60 `
  -OutputDirectory C:\AVA\NeuroTangleReview
```

Use a new, reviewed directory rather than altering files after a fail-closed stop.

## GitHub execution status

The workflow executes only in an ephemeral Windows runner. It performs AST and negative safety tests, two sequential `Once` cycles, persisted-file SHA256 checks, active main/branch verification, alert-deduplication checks, a deliberate state-corruption stop test, and targeted PSScriptAnalyzer linting. Runtime evidence stays under `RUNNER_TEMP` and is not uploaded; only validation diagnostics and source files are retained.

This does not execute the collector on a user's laptop. The pull request remains draft until the bounded workflow and review are green.

## Excluded issue material

The cleanup excludes invalid JSON, duplicated or unbalanced PowerShell, copied conversation text, speculative physics claims, remote takeover, malware return, mass distribution, source-IP attacks, and counterattack instructions.
