# Attack Vectors & Security Considerations

This document captures likely attack vectors for a **complicated Windows desktop application** with:
- Win32/MFC components
- A DDD-based **.NET 10** application exposing an **API**
- Interactions between **old and new components over a JSON protocol**
- An **Avalonia** UI that talks to the API
- Execution on **one machine** under a **standard Windows user**, while **other users on the same computer may have administrator rights**

## Scope & Assumptions
- Primary goal: prevent compromise of confidentiality/integrity/availability for user data and system behavior.
- The machine is potentially multi-tenant: another local user (possibly admin) may attempt to influence or observe the app.
- If a local attacker has **Administrator** privileges, they can generally tamper with user-mode applications on that machine. Security controls should focus on:
  - Preventing **non-admin** cross-user attacks.
  - Making **tampering harder to do unnoticed** (integrity verification, signatures, audit logs), even if not impossible.

## Assets (What To Protect)
- User data: documents, local caches, exports, locally stored domain data.
- Credentials/secrets: API tokens, refresh tokens, certificates, connection strings, keys.
- Integrity of domain commands: preventing unauthorized state changes.
- Availability: resisting easy DoS (hang/crash/memory exhaustion) from malformed inputs or local interference.
- Update channel integrity (if applicable): preventing malicious update injection/downgrade.

## Trust Boundaries & Data Flows (High Level)
- Avalonia UI <-> .NET API (loopback HTTP? IPC? in-proc?) over JSON.
- Old component <-> new component over JSON (same machine; potentially file/pipe/socket).
- App <-> local filesystem/registry (per-user settings, caches, logs).
- Optional: App/API <-> external services (if any).

Explicitly identify each boundary and apply **authentication + authorization + input validation** at every boundary.

## Primary Attack Surfaces (And What To Do About Them)

### 1) Local Multi-User Machine Risks (Standard User + Other Admin Users)
**Threats**
- Another local user can attempt to read/modify the standard user's data (e.g., via misconfigured file permissions, shared folders, world-readable logs).
- An administrator can tamper with binaries/configs, inject DLLs, attach debuggers, install root CAs, intercept loopback traffic, etc.

**Considerations / Mitigations**
- Store per-user data in `%LOCALAPPDATA%` (or `%APPDATA%`) and verify ACLs are not permissive.
- Do not store secrets in plaintext. Prefer Windows **DPAPI** (CurrentUser) for secrets; avoid custom crypto.
- Prefer installing binaries under `%ProgramFiles%` (admin-writable) rather than user-writable directories to reduce opportunistic tampering.
- Use Authenticode signing for shipped binaries; optionally verify signature on critical components at runtime (best-effort tamper evidence).
- Assume “admin on the box” is effectively a trusted operator; for adversarial admins, focus on detection rather than absolute prevention.

### 2) API Exposure (Localhost, Named Pipes, or Network)
**Threats**
- Accidental exposure to the network (binding to `0.0.0.0`), allowing remote access.
- Local malware or other local user calling the API if it lacks strong auth.
- CSRF-like issues if a browser can reach the API on localhost.
- SSRF and injection through proxying requests.

**Considerations / Mitigations**
- Bind explicitly to `127.0.0.1` (or use a Windows Named Pipe / local-only transport) unless remote access is required.
- Add authentication even for local-only APIs; do not trust "localhost" as an identity.
  - If using loopback HTTP: use an unguessable per-session bearer token + strict origin checks.
  - If using Named Pipes: enforce Windows ACLs on the pipe and validate the client identity.
- Use least privilege for the API process. Avoid running as admin.
- Harden request handling:
  - Input size limits (body size, recursion depth, string lengths).
  - Timeouts and cancellation.
  - Rate limiting / concurrency limits.
- Disable debug endpoints and introspection in production builds.

### 3) JSON Protocol Between Old/New Components (Compatibility Layer)
**Threats**
- Deserialization vulnerabilities, type confusion, coercion bugs, and logic bypass via “optional/unknown fields”.
- Inconsistent validation between old and new sides.
- Downgrade attacks: forcing the system into an older, weaker protocol mode.
- Replay attacks (re-sending old commands/events).

**Considerations / Mitigations**
- Treat the JSON protocol as untrusted input, even if it “comes from yourself”.
- Define a versioned schema:
  - Explicit version field.
  - Forward/backward compatibility rules.
  - Reject unknown fields for security-sensitive messages (or log + ignore safely).
- Avoid polymorphic deserialization and any “type name handling”.
- Validate at the boundary:
  - Required fields present, constraints, ranges, enums.
  - Canonicalize before verification/authorization (e.g., normalize paths).
- Add integrity and anti-replay where needed:
  - Include message IDs + monotonic counters/timestamps.
  - For cross-process control messages, use an authenticated channel rather than “trusting JSON”.

### 4) Authorization At The Domain Layer (DDD Command/Query Model)
**Threats**
- UI or legacy component can bypass business rules by calling internal command handlers directly or forging messages.
- “Confused deputy”: a privileged component performs an action on behalf of an unprivileged caller.

**Considerations / Mitigations**
- Enforce authorization in the **domain/application layer**, not just in the UI.
- Define a clear identity model for callers:
  - “Which user/session is calling this command?”
  - Tie each call to an authenticated principal.
- Apply authorization checks close to state mutation:
  - Command handlers validate permissions and invariants.
- Ensure auditing:
  - Log who did what, when, and the outcome (without logging secrets).

### 5) Win32/MFC Attack Vectors
**Threats**
- Memory corruption (buffer overflows, use-after-free), especially around parsing, string handling, and IPC.
- DLL search order hijacking / side-loading.
- Insecure temporary file usage (TOCTOU).
- Window message shatter attacks (less common with modern integrity levels, but still consider message handling).

**Considerations / Mitigations**
- Enable modern compiler/linker mitigations (where applicable):
  - /GS, /guard:cf, ASLR, DEP, CET (if feasible)
- Avoid unsafe CRT functions; prefer bounded APIs.
- Harden DLL loading:
  - Use `SetDefaultDllDirectories` and `AddDllDirectory` where possible.
  - Load DLLs by absolute path; avoid current-directory search.
- Use safe temp files:
  - Create with exclusive access; avoid predictable names.
- Treat WM_COPYDATA / custom messages as untrusted if used cross-process; authenticate the sender.

### 6) Avalonia UI Considerations
**Threats**
- UI-to-API trust: malicious local process could attempt to script UI or inject input to cause actions.
- Rendering untrusted content (HTML-like, markdown, rich text) that may contain links or “active” content.
- Clipboard, drag-and-drop, and file pickers enabling data exfil or unsafe file opens.

**Considerations / Mitigations**
- Keep privileged operations behind explicit confirmations and clear user intent.
- Sanitize any untrusted rich content and disallow dangerous URI schemes (`file:`, `shell:`, etc.).
- Constrain file operations (open/save) to expected types; validate content, not just extensions.
- Avoid embedding a browser engine with relaxed settings; if needed, lock it down.

### 7) File System, Registry, and Configuration
**Threats**
- Path traversal and unsafe path joins leading to writing/reading unexpected files.
- Loading config/plugins/scripts from user-writable directories.
- Insecure permissions causing cross-user access.

**Considerations / Mitigations**
- Use canonicalized absolute paths; block traversal sequences early.
- Do not auto-load executable content from writable locations.
- Prefer per-user config locations with strict ACLs.
- If plugins are required:
  - Sign plugins, pin publisher, or require explicit user approval.

### 8) Secrets, Crypto, and Certificates
**Threats**
- Secrets in logs, crash dumps, config files.
- Using custom crypto incorrectly.
- Trusting machine-wide root store when local admin may install malicious CAs.

**Considerations / Mitigations**
- Use DPAPI (CurrentUser) for secrets at rest; keep secrets in memory as briefly as practical.
- For remote TLS connections: prefer certificate pinning / key pinning only when operationally acceptable.
- Never roll your own crypto; use platform primitives.
- Scrub secrets from logs; treat crash dumps as sensitive.

### 9) Update, Install, and Dependency Supply Chain
**Threats**
- Malicious updates, downgrade attacks, tampered installers.
- Dependency confusion or compromised packages.

**Considerations / Mitigations**
- Sign installers and update payloads; verify before applying.
- Include anti-rollback where feasible (minimum version).
- Pin dependencies; use lock files; run dependency scanning.
- Prefer official package sources; monitor for vulnerable transitive dependencies.

### 10) Logging, Telemetry, and Error Handling
**Threats**
- Sensitive data leaks to logs.
- Log injection (attacker controls content that is later parsed/acted on).
- Overly detailed error messages assisting attackers.

**Considerations / Mitigations**
- Redact secrets and PII by default.
- Use structured logging; encode untrusted values.
- Separate debug logs from production logs; protect log file permissions.
- Return safe error messages across trust boundaries; keep full detail internal.

## Concrete Checklist (Recommended Baseline)
- Define explicit **API binding** strategy (loopback-only or named pipes) and enforce caller identity.
- Add **authentication** between UI/legacy components and the API even on localhost.
- Version and validate the **JSON protocol**; avoid polymorphic deserialization.
- Enforce **authorization** at command handlers (domain/application layer).
- Use DPAPI for secrets; avoid plaintext secrets in `%APPDATA%`.
- Harden native DLL loading and enable compiler mitigations in MFC components.
- Ensure strict ACLs for data, config, and logs (no world-readable/writable).
- Implement input limits, timeouts, and rate limiting for API and protocol handlers.
- Sign binaries/installers; verify update integrity and prevent downgrades.

## Notes On Threat Model Reality (Admin On The Same Box)
If another user is an Administrator on the same machine, they can usually:
- Read or alter files, inject code into processes, intercept traffic, and replace dependencies.

Your best defenses in that scenario are:
- Least privilege execution to reduce blast radius.
- Tamper evidence (signatures, integrity checks, audit logs).
- Minimizing stored secrets and sensitive data at rest.
