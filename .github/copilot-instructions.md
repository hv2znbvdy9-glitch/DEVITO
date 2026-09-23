# DEVITO / AVA repository instructions

## Scope
These instructions apply to work in this repository, especially AVA/01610 audit, safety, evidence, PowerShell, and defensive tooling.

## Core principles
- Preserve existing behavior unless the task explicitly requests a behavior change.
- Prefer small, reviewable, reversible changes.
- Treat existing documentation and tests as part of the repository contract.
- Keep facts, observations, interpretations, and proposals clearly separated.
- Never claim a check, test, scan, command, or deployment was performed unless it was actually performed.
- Do not invent hashes, identifiers, test results, repository state, or external evidence.

## Safety boundary
- AVA tooling is defensive/local by default.
- Do not add exploits, credential theft, persistence, unauthorized access, destructive actions, automated propagation, or scanning of systems that are not explicitly authorized.
- Prefer read-only inspection and isolated/in-memory implementations for security-sensitive logic.
- For system-changing operations, make the change explicit, reversible where possible, and require deliberate confirmation when appropriate.
- Never silently remove users, firewall rules, services, scheduled tasks, registry entries, files, or security controls.
- Do not weaken authentication, authorization, integrity checks, or audit trails to make a test pass.

## Integrity / evidence
- Follow `docs/AVA_FLASH_IMMUTABLE_RULE.md`.
- Preserve original evidence; never overwrite an original event merely to update a result.
- Use unique event identifiers for separate events.
- Hashes are evidence of byte equality, not proof of authorship or safety.
- If an integrity check fails, stop and report the mismatch rather than silently repairing or replacing the source.

## PowerShell
- Use strict error handling for security-sensitive scripts.
- Prefer `-LiteralPath`, explicit parameters, and deterministic output.
- Avoid `Invoke-Expression`, hidden downloads, dynamic remote execution, and implicit network access.
- Clearly distinguish scripts that only inspect from scripts that modify the system.
- Do not add administrator/SYSTEM or scheduled-task execution merely for convenience.

## Changes and testing
1. Inspect the relevant files and existing conventions before editing.
2. Make the smallest change that satisfies the request.
3. Run the repository's documented or discovered validation/tests when available.
4. Report exact results, including failures and skipped checks.
5. If tests cannot be run, state why; do not substitute an invented success.
6. Avoid unrelated formatting or refactors.

## 01610 / NACHHALL
When working on 01610 or NACHHALL:
- Treat it as an integrity/stability verification layer, not permission for unrestricted feature expansion.
- Compare current behavior with the documented baseline before changing it.
- Preserve reproducibility and local safety boundaries.
- Keep any new evidence or reports append-only/non-destructive where the repository's evidence model requires it.

## GitHub workflow
- Prefer a focused change with a clear commit message.
- Review the resulting diff/state before declaring work complete.
- Issue comments must describe what was actually changed or verified.
- Do not close an issue merely because an agent session failed; close only when the requested repository work is actually complete.
