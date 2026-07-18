# Issue 112 cleanup: AVA Neuro Tangle Guardian v1 SAFE

This change extracts the useful local defensive collector from the mixed content in issue #112 and places it in a standalone PowerShell file.

## Files

- `scripts/AVA_NeuroTangle_Guardian_v1_SAFE.ps1` - local collector, baseline/delta analysis, JSONL evidence chain, SHA256 manifest, and HTML portal.
- `scripts/Test_AVA_NeuroTangle_Guardian_v1_SAFE.ps1` - parser and prohibited-command validation.
- `.github/workflows/ava-neuro-tangle-safe-check.yml` - Windows syntax and safety validation for pull requests and pushes that change these files.

## Scope

`Once`, `Loop`, and `OpenPortal`:

- read local Windows state;
- write only AVA-owned reports and state files;
- do not change Defender, firewall, accounts, registry, services, or remote systems;
- do not scan remote systems;
- do not perform counterattacks.

`InstallTask` and `UninstallTask` are optional local changes. They require an elevated shell and exact interactive confirmation (`INSTALL` or `REMOVE`). The scheduled task starts the same local collector and does not add remote behavior.

## Safe review and run order

1. Review the pull-request diff.
2. Run the static validator:

   ```powershell
   powershell.exe -NoProfile -File .\scripts\Test_AVA_NeuroTangle_Guardian_v1_SAFE.ps1
   ```

3. Run one local cycle first:

   ```powershell
   powershell.exe -NoProfile -File .\scripts\AVA_NeuroTangle_Guardian_v1_SAFE.ps1 -Mode Once -OpenPortal
   ```

4. Inspect the baseline, findings, logs, manifest, and portal.
5. Use bounded loop mode before an unlimited loop:

   ```powershell
   powershell.exe -NoProfile -File .\scripts\AVA_NeuroTangle_Guardian_v1_SAFE.ps1 -Mode Loop -MaxCycles 5 -IntervalSeconds 60 -OpenPortal
   ```

6. Install a startup task only after review:

   ```powershell
   powershell.exe -NoProfile -File .\scripts\AVA_NeuroTangle_Guardian_v1_SAFE.ps1 -Mode InstallTask
   ```

   Type exact text `INSTALL` when prompted.

7. Remove the task with:

   ```powershell
   powershell.exe -NoProfile -File .\scripts\AVA_NeuroTangle_Guardian_v1_SAFE.ps1 -Mode UninstallTask
   ```

   Type exact text `REMOVE` when prompted.

## Output directories

- Elevated run: `C:\Windows\SecurityGuardian\AVA_NeuroTangle_SAFE`
- Standard-user run: `%LOCALAPPDATA%\AVA_NeuroTangle_SAFE`

## Security notes

- A hash chain can make later modifications detectable when the chain is independently verified. It does not make a writable file immutable.
- A risk score is a triage aid, not proof of compromise or attribution.
- Visible WLANs, network neighbors, listeners, and administrative tools can be legitimate.
- Preserve evidence and verify context before remediation.
- Never access, scan, disrupt, or attack systems without explicit authorization.

## Deliberately removed from the mixed issue text

The cleanup excludes invalid JSON, duplicated and unbalanced PowerShell blocks, copied pull-request prose, speculative physics text, and all instructions involving remote takeover, malware return, mass distribution, source-IP attacks, or counterattacks.

## Execution status

Creating this pull request does not execute the Windows collector on any device. GitHub Actions performs syntax and prohibited-command checks only.
