# AVA Safe Audit Trigger

Run requested: 2026-07-18.
Retry: 2 — record pre-existing parse failures, then continue to independent validation and isolated execution of exactly one cleaned script.
Scope: inventory and SHA-256, static parsing of every PowerShell file, verification that dangerous capabilities are absent from the cleaned derivative, and a non-root `--network none` self-test with no secrets or persistent workspace writes.
