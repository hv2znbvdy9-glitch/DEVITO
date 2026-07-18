# AVA Safe Audit Trigger

Run requested: 2026-07-18.
Retry: 8 — isolated PowerShell receives only an ephemeral writable HOME/XDG area inside `/tmp`; root filesystem remains read-only.
Scope: full tracked-file inventory and SHA-256, static parse report for every PowerShell file, dangerous-capability removal verification, and exactly one isolated non-root `--network none` cleaned-script self-test.
No original security script is executed.
