# MEMPAL Hardening Plan — SELARIX-Compatible

**Date:** 2026-06-05
**Author:** Claude (commissioned by Mike Bennett)
**Scope:** Address Critical Findings F1 (no MCP auth) and F2 (ClientInfo.name spoofing) from MEMPAL_SECURITY_AUDIT.md; design governance-grade hardening compatible with SELARIX doctrine
**Status:** Design only. No code changes.

---

## Executive Summary

mempal's MCP server trusts whoever connects. The only "identity" is `ClientInfo.name` — a self-reported string set by the connecting process (`src/mcp/server.rs:3839`). This string drives three security-relevant decisions: partner session reads (`peek_partner`), cowork message routing (`cowork_push`), and tunnel attribution. An attacker who can connect to the stdio pipe can impersonate any agent, read session logs, inject messages, and delete data.

This plan introduces **three layers** — a shared-secret gate, a verified identity binding, and a provenance-stamped audit trail — while preserving local-first operation and full backward compatibility for unconfigured single-user deployments.

The design follows SELARIX governance principles: controls are explicit, denial is evidence, and every mutation has provenance. No control depends on network connectivity, cloud services, or external PKI.

---

## Threat Model

### Current Assumptions (Valid for Single-User Local)

1. Only the user's own Claude Code / Codex processes connect to mempal MCP
2. `~/.mempal/` is protected by OS file permissions
3. The stdio pipe is not exposed over a network
4. There is one human operator (Mike)

### SELARIX Integration Changes

| Assumption | Change | Consequence |
|------------|--------|-------------|
| Single MCP client | Paperclip agent swarm (4+ agents) | Multiple processes compete for MCP access |
| Trusted client name | Agents self-report identity | Any agent can claim to be any other agent |
| Single human | Board Chair + automated agents | Agents must not have Board Chair privileges |
| Local only | REST API may serve dashboard | Network exposure possible |

### Adversary Model

| Adversary | Capability | Goal |
|-----------|-----------|------|
| **Rogue local process** | Can connect to stdio pipe or read `~/.mempal/` | Read governance decisions, inject messages, delete drawers |
| **Compromised agent** | Has valid MCP connection but acts outside its role | Escalate privileges, impersonate other agents, modify governance data |
| **Supply-chain implant** | Runs as dependency inside an agent process | Exfiltrate session data via peek_partner, inject cowork messages |

### What Is NOT In Scope

- Network-level attacks (mempal MCP is stdio, not TCP)
- Physical access to the machine
- Attacks on Claude Code / Codex themselves
- Attacks on the Rust compiler or build toolchain

---

## Proposed Architecture

### Three-Layer Defense

```
Layer 1: GATE          — Shared secret rejects unauthenticated clients
Layer 2: IDENTITY      — Verified client ID replaces self-reported name
Layer 3: PROVENANCE    — Every mutation stamped with verified identity + timestamp
```

### Layer 1: MCP Shared-Secret Gate

**Problem:** Any process that can write to mempal's stdin gets full tool access.

**Design:**

Add an optional `[security]` section to `~/.mempal/config.toml`:

```toml
[security]
# When set, MCP clients must include this token in initialize() params.
# When unset, all clients are accepted (backward compatible).
mcp_secret = "mempal_sk_a1b2c3d4e5f6..."
```

**Mechanism:**

1. On startup, `MempalServer::new()` reads `config.security.mcp_secret` (new field in `src/core/config.rs` `Config` struct)
2. In `initialize()` (`src/mcp/server.rs:3827`), if a secret is configured:
   - Check `request.client_info.name` for a token suffix: `"claude-code::mempal_sk_a1b2c3d4e5f6..."`
   - Or check a custom field in the MCP initialize params (rmcp 1.3.0 allows extra fields via serde)
   - If token missing or wrong: return `ErrorData` with code `-32001` ("authentication required")
   - If token matches: proceed normally
3. If no secret is configured: accept all clients (current behavior, backward compatible)

**Token Format:** `mempal_sk_` prefix + 32 hex chars (128-bit entropy). Generated via:
```
mempal security generate-secret
```
Writes to `~/.mempal/config.toml` `[security]` section. Prints the token for the user to paste into Claude Code / Codex MCP server config.

**Why shared secret, not PKI:**
- Local-first: no CA, no certificate management, no network dependency
- Single-user: one human generates and distributes the token
- Simple: one config field, one check, one error path
- Sufficient: the threat is rogue local processes, not nation-state attackers

**Token Delivery to MCP Clients:**

Claude Code MCP server config (`~/.claude/settings.json` or project `.claude/settings.json`):
```json
{
  "mcpServers": {
    "mempal": {
      "command": "mempal",
      "args": ["mcp"],
      "env": {
        "MEMPAL_MCP_SECRET": "mempal_sk_a1b2c3d4e5f6..."
      }
    }
  }
}
```

mempal reads `MEMPAL_MCP_SECRET` env var as an alternative to config file. This lets the MCP client process pass the secret without touching `config.toml`. The env var takes precedence if both are set.

**Rationale for env var approach:** The MCP spec's `initialize()` `ClientInfo` struct has `name` and `version` — no dedicated auth field. Passing the secret via environment variable is cleaner than overloading `ClientInfo.name` and avoids depending on rmcp supporting custom init fields.

The server reads `MEMPAL_MCP_SECRET` from its own environment (set by the MCP client launcher), not from the MCP protocol. This means:
- The secret never crosses the stdio pipe
- The secret is set by the process that spawns mempal (Claude Code / Codex)
- A rogue process connecting to an already-running mempal stdio pipe cannot inject the secret

**Wait — stdio pipe model clarification:**

MCP over stdio means the MCP client (Claude Code) **spawns** mempal as a child process and communicates via stdin/stdout. There is no persistent listening socket. A rogue process cannot connect to an already-running mempal MCP server — it would need to spawn its own instance.

This means **F1 (no auth) is lower severity than initially assessed for stdio transport.** The real risk is:
1. A rogue process spawning its own `mempal mcp` and reading `~/.mempal/palace.db` directly
2. A compromised agent within a legitimate MCP session

Layer 1 (shared secret) still has value: it prevents accidental misconfiguration (e.g., a second MCP client connecting to a mempal instance intended for a specific project) and provides defense-in-depth. But the primary mitigation for rogue database reads is filesystem permissions on `~/.mempal/`.

### Layer 2: Verified Client Identity

**Problem:** `ClientInfo.name` is self-reported and drives security decisions at 3 code locations (`src/mcp/server.rs:2792, 2876, 2931`).

**Design:**

Replace trust-by-name with trust-by-registration:

1. **New config field** in `[security]`:
   ```toml
   [security]
   mcp_secret = "mempal_sk_..."
   
   # Registered client identities. Each entry maps a logical name
   # to its allowed capabilities.
   # When this list is non-empty, only registered clients are accepted.
   # When empty, all authenticated clients get full access (backward compatible).
   [[security.clients]]
   name = "claude-code"
   role = "primary"      # full access to all tools
   
   [[security.clients]]
   name = "codex-cli"
   role = "primary"
   
   [[security.clients]]
   name = "paperclip-security"
   role = "agent"         # restricted: no peek_partner, no delete, read-only knowledge lifecycle
   
   [[security.clients]]
   name = "paperclip-seo"
   role = "agent"
   ```

2. **Role-based tool access** (3 roles, expandable):

   | Role | Search | Ingest | Delete | Peek Partner | Cowork Push/Bus | Knowledge Lifecycle | Context/Brief |
   |------|--------|--------|--------|-------------|-----------------|--------------------:|---------------|
   | `primary` | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
   | `agent` | Yes | Yes | No | No | Yes (own identity only) | Read-only (gate, policy) | Yes |
   | `observer` | Yes | No | No | No | No | Read-only | Yes |

3. **Identity binding in initialize():**
   - After secret validation (Layer 1), look up `request.client_info.name` in `config.security.clients`
   - If found: store the **registered name and role** (not the raw client_info.name) in `self.client_identity`
   - If not found and `clients` list is non-empty: reject with "unregistered client"
   - If `clients` list is empty: accept with role=`primary` (backward compatible)

4. **Replace client_name usage:**

   | Current Code | Change |
   |-------------|--------|
   | `src/mcp/server.rs:2792` (tunnel created_by) | Use `self.client_identity.name` instead of raw client_name |
   | `src/mcp/server.rs:2876` (peek_partner caller) | Check `role == primary`; reject agents |
   | `src/mcp/server.rs:2931` (cowork_push caller) | Use verified identity; enforce `from == self.client_identity.name` |
   | `src/mcp/server.rs:3839` (initialize store) | Store verified `ClientIdentity { name, role }` instead of raw string |

5. **New server field:**
   ```rust
   // Replace:
   client_name: Arc<Mutex<Option<String>>>
   
   // With:
   client_identity: Arc<Mutex<Option<ClientIdentity>>>
   
   struct ClientIdentity {
       name: String,        // Verified against config
       role: ClientRole,    // primary | agent | observer
   }
   ```

**Why not per-client secrets:**

Each client could have its own secret, but this adds complexity without proportional security gain for the single-user threat model. The shared secret gates access; the registered client list controls authorization. A compromised secret compromises all clients regardless of per-client keys.

### Layer 3: Provenance-Stamped Audit Trail

**Problem:** Current audit log (`audit.jsonl`) records *what* happened but not *who* did it. Governance-grade audit requires attributable, tamper-evident records.

**Design:**

**3a. Extend audit schema with client identity:**

Current format (`src/main.rs:2186-2196`, `src/knowledge_lifecycle.rs:268-271`):
```json
{"timestamp":"...","command":"ingest","wing":"research",...}
```

New format:
```json
{
  "timestamp": "2026-06-05T14:32:15.123456Z",
  "client": {
    "name": "claude-code",
    "role": "primary"
  },
  "command": "ingest",
  "wing": "research",
  "details": {...},
  "prev_hash": "a1b2c3d4..."
}
```

New fields:
- `client`: Verified identity from Layer 2 (not self-reported name)
- `prev_hash`: SHA-256 of the previous audit entry (hash chain for tamper detection)

**3b. Audit all mutations, not just ingest/lifecycle:**

Current audit coverage:
- `ingest` (src/main.rs:2100)
- `delete` (src/main.rs:5499)
- `promote` / `demote` (src/knowledge_lifecycle.rs)
- `knowledge gate` (src/main.rs:5540)

Missing (add in hardening):
- `cowork_push` — who sent what to whom
- `cowork_bus send/broadcast` — message provenance
- `tunnel add/delete` — cross-wing link changes
- `kg add/invalidate` — triple mutations
- `knowledge_card promote/demote` — Phase-2 card lifecycle
- `peek_partner` — who read whose session (access log)

**3c. Hash chain for tamper detection:**

Each audit entry includes `prev_hash` = SHA-256 of the previous entry's JSON line. The first entry uses `prev_hash = "genesis"`. This creates a lightweight tamper-detection chain:

```
Entry 1: {..., "prev_hash": "genesis"}
Entry 2: {..., "prev_hash": sha256(Entry 1)}
Entry 3: {..., "prev_hash": sha256(Entry 2)}
```

Verification: `mempal security verify-audit` reads the file and checks each entry's `prev_hash` against the actual hash of the previous line. Any insertion, deletion, or modification breaks the chain.

**Why not a database table:**

The audit log is deliberately separate from `palace.db` for two reasons:
1. **Independence:** A bug or attack that corrupts the database doesn't corrupt the audit trail
2. **Append-only guarantee:** JSONL append is simpler to reason about than SQLite transactions. The `knowledge_events` table has triggers, but those can be bypassed by direct SQLite access. A separate file with hash chaining provides an independent integrity signal.

**3d. Governance event classification:**

For SELARIX compatibility, audit entries should carry a governance classification:

```json
{
  "governance": {
    "rule": "GOV-DESTRUCT-PUBLIC-001",
    "action": "gate_check",
    "outcome": "denied",
    "evidence_bundle": "drawer_abc123"
  }
}
```

This field is **optional** — only populated when the operation is explicitly governance-tagged by the calling agent. mempal does not interpret governance rules; it stores the agent's self-reported governance context as provenance metadata.

---

## Recommended Controls

### Control 1: Secret Generation and Rotation

```
mempal security generate-secret          # Generate and store new secret
mempal security rotate-secret            # Generate new, invalidate old
mempal security show-client-config       # Print MCP client config snippet
```

- Secrets stored in `~/.mempal/config.toml` with `0600` permissions
- Rotation writes new secret, prints updated client config
- No automatic expiry (manual rotation only — appropriate for single-user)

### Control 2: Client Registration

```
mempal security register-client --name paperclip-security --role agent
mempal security list-clients
mempal security revoke-client --name paperclip-security
```

- Writes to `[security.clients]` in config.toml
- `list-clients` shows name, role, and whether currently connected
- `revoke-client` removes from config; next initialize() rejects

### Control 3: Audit Integrity Verification

```
mempal security verify-audit             # Check hash chain integrity
mempal security audit-summary            # Show mutation counts by client/command
mempal security audit-search --client paperclip-security --command delete
```

- `verify-audit` exits 0 if chain intact, exits 1 with details if broken
- `audit-summary` provides quick overview for Board Chair review
- `audit-search` enables investigation of specific client actions

### Control 4: Tool Access Enforcement

New middleware in `src/mcp/server.rs` — inserted between request parsing and handler execution:

```rust
fn check_access(&self, tool_name: &str) -> Result<(), ErrorData> {
    let identity = self.client_identity.lock()...;
    match identity.role {
        ClientRole::Primary => Ok(()),
        ClientRole::Agent => {
            if AGENT_DENIED_TOOLS.contains(&tool_name) {
                Err(ErrorData::invalid_params("insufficient role for this tool", None))
            } else {
                Ok(())
            }
        }
        ClientRole::Observer => {
            if !OBSERVER_ALLOWED_TOOLS.contains(&tool_name) {
                Err(ErrorData::invalid_params("insufficient role for this tool", None))
            } else {
                Ok(())
            }
        }
    }
}
```

Denied tools by role:

```rust
const AGENT_DENIED_TOOLS: &[&str] = &[
    "mempal_delete",
    "mempal_peek_partner",
];

const OBSERVER_ALLOWED_TOOLS: &[&str] = &[
    "mempal_status",
    "mempal_search",
    "mempal_context",
    "mempal_brief",
    "mempal_knowledge_policy",
    "mempal_knowledge_gate",
    "mempal_field_taxonomy",
    "mempal_doctor",
    "mempal_knowledge_cards",  // read-only actions only
    "mempal_phase3",           // read-only actions only
];
```

### Control 5: Cowork Identity Enforcement

In `mempal_cowork_push` (`src/mcp/server.rs:2931`) and `mempal_cowork_bus send` (`src/mcp/server.rs:2984`):

- Replace `caller_name` (self-reported) with `client_identity.name` (verified)
- In bus `send`: enforce `request.from == client_identity.name` — agents cannot spoof `from`
- In bus `broadcast`: stamp all messages with verified sender identity

---

## Implementation Phases

### Phase 0: Audit Trail Foundation (No Breaking Changes)

**Scope:** Extend audit.jsonl with client identity and hash chain. Add audit to all mutations.

**Changes:**
- New `AuditEntry` struct with `client`, `prev_hash`, optional `governance` fields
- New `append_audited()` function that computes hash chain
- Add audit calls to cowork_push, cowork_bus send/broadcast, tunnel add/delete, kg add/invalidate
- Add `mempal security verify-audit` CLI command
- New spec: `specs/p107-audit-provenance.spec.md`
- New plan: `docs/plans/...-p107-audit-provenance.md`

**Client identity in Phase 0:** When security is not configured, `client` field is `{"name": "<client_info.name>", "role": "unverified"}`. This preserves current behavior while establishing the audit schema.

**Breaking changes:** None. Audit format extends, doesn't replace.

**Estimated scope:** ~200 lines of Rust. 1 new CLI command. 1 spec + 1 plan.

### Phase 1: Shared-Secret Gate (Opt-In)

**Scope:** Add `[security]` config section. Implement secret validation. Add CLI for secret management.

**Changes:**
- New `SecurityConfig` struct in `src/core/config.rs`
- Secret validation in `initialize()` (`src/mcp/server.rs:3827`)
- `MEMPAL_MCP_SECRET` env var support
- `mempal security generate-secret` / `rotate-secret` / `show-client-config` CLI commands
- New spec: `specs/p108-mcp-shared-secret.spec.md`
- New plan: `docs/plans/...-p108-mcp-shared-secret.md`

**Breaking changes:** None. Secret is opt-in. Unconfigured = current behavior.

**Estimated scope:** ~150 lines of Rust. 3 new CLI commands. 1 spec + 1 plan.

### Phase 2: Client Identity and Role Enforcement (Opt-In)

**Scope:** Replace `client_name: Arc<Mutex<Option<String>>>` with `client_identity: Arc<Mutex<Option<ClientIdentity>>>`. Implement role-based tool access.

**Changes:**
- `ClientIdentity` struct with `name` and `role`
- `[[security.clients]]` config parsing
- `check_access()` middleware in MCP server
- Cowork identity enforcement (from field binding)
- `mempal security register-client` / `list-clients` / `revoke-client` CLI commands
- Update all 3 `client_name` read sites to use verified identity
- Audit entries now carry verified identity
- New spec: `specs/p109-client-identity-rbac.spec.md`
- New plan: `docs/plans/...-p109-client-identity-rbac.md`

**Breaking changes:** None. Empty `clients` list = current behavior (all authenticated clients get `primary` role).

**Estimated scope:** ~300 lines of Rust. 3 new CLI commands. 1 spec + 1 plan.

### Phase 3: Governance Provenance Metadata (Optional)

**Scope:** Add optional `governance` field to audit entries. Define SELARIX-compatible governance event schema.

**Changes:**
- Optional `governance` field in `AuditEntry`
- MCP tools accept optional `governance_context` parameter (JSON object, opaque to mempal)
- `mempal security audit-search --governance-rule GOV-DESTRUCT-PUBLIC-001`
- New spec: `specs/p110-governance-provenance.spec.md`
- New plan: `docs/plans/...-p110-governance-provenance.md`

**Breaking changes:** None. Field is optional. Tools that don't pass governance context work unchanged.

**Estimated scope:** ~100 lines of Rust. 1 spec + 1 plan.

### Phase Summary

| Phase | Spec | Breaks Backward Compat | Depends On |
|-------|------|----------------------|------------|
| 0 — Audit provenance | P107 | No | Nothing |
| 1 — Shared secret | P108 | No | Nothing |
| 2 — Identity + RBAC | P109 | No | P108 |
| 3 — Governance metadata | P110 | No | P107 |

Phases 0 and 1 are independent and can be implemented in parallel.

---

## Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| **Secret leaked in MCP client config** | HIGH | Document: treat `MEMPAL_MCP_SECRET` like a password. Use env var, not command-line arg (visible in `ps`). File permissions 0600 on config.toml. |
| **Hash chain broken by concurrent writers** | MEDIUM | Audit append uses file-level flock (same pattern as ingest lock, `src/ingest/lock.rs`). Single-writer guarantee. |
| **Role escalation via config edit** | LOW | Config.toml is user-owned. If attacker can edit config, they already have full filesystem access. Defense-in-depth only. |
| **Backward compat regression** | MEDIUM | Every phase defaults to current behavior when `[security]` is absent. Integration tests must cover both configured and unconfigured paths. |
| **Over-engineering for single-user** | MEDIUM | Phase 0-1 are lightweight (~350 lines total). Phase 2-3 are opt-in and only needed for SELARIX multi-agent deployment. Don't build Phase 2-3 until Paperclip integration is real. |
| **rmcp version upgrade breaks auth** | LOW | Auth is implemented outside rmcp (env var + config). No dependency on rmcp auth features. |
| **Audit log grows unbounded** | MEDIUM | Same risk as F10 in security audit. Add rotation in Phase 0 (keep last N entries or time-window). |

---

## Build vs. Adopt Analysis

### Build (Recommended)

| What | Why Build |
|------|-----------|
| Shared-secret gate | ~50 lines. Too simple to justify a dependency. No existing MCP auth crate. |
| Client identity + RBAC | ~100 lines for 3 roles. Standard pattern. No framework needed. |
| Hash-chained audit | ~80 lines. SHA-256 via `sha2` crate (already a transitive dependency via rustls). |
| Governance metadata | ~50 lines. Opaque JSON field. No SELARIX-specific logic in mempal. |

**Total new code: ~400-750 lines across 4 phases.** This is well within mempal's architectural style (single crate, no external frameworks).

### Don't Adopt

| What | Why Not |
|------|---------|
| OAuth / OIDC | Requires network, token endpoint, refresh flow. Violates local-first. |
| mTLS | Requires certificate management. MCP stdio has no TLS layer. |
| External audit service | Network dependency. Violates local-first. |
| Vault / KMS | Over-engineered for single-user. mempal runs on a developer laptop, not a datacenter. |
| RBAC framework (casbin-rs, etc.) | 3 roles with static tool lists. A framework adds ~50 dependencies for a 20-line match statement. |

### SELARIX-Specific: Don't Build In mempal

| What | Why Not | Where Instead |
|------|---------|---------------|
| Governance rule enforcement | mempal is memory, not policy | Paperclip agent policy layer |
| Approval workflow (approve/deny/comment) | mempal has no UI or workflow engine | Paperclip QSL Review board |
| Constitutional invariant routing | Requires LLM-level routing decisions | Model Gateway (future) |
| Multi-tenant isolation | Requires separate databases, auth domains | Wait for enterprise need |

---

## Backward Compatibility Guarantee

**Zero breaking changes across all 4 phases.**

| Scenario | Behavior |
|----------|----------|
| No `[security]` section in config.toml | All clients accepted, all tools available, audit entries show `"role": "unverified"` |
| `[security]` with only `mcp_secret` | Authenticated clients get `primary` role, all tools available |
| `[security]` with `mcp_secret` + `clients` list | Authenticated + registered clients only, role-based access |
| Existing audit.jsonl without `prev_hash` | New entries start fresh chain. `verify-audit` reports "chain starts at entry N" |
| MCP client that doesn't set `MEMPAL_MCP_SECRET` env var | Rejected only if secret is configured. Otherwise accepted. |

**Migration path:** None required. Users who don't configure security get exactly current behavior. Users who configure security get progressive hardening.

---

## Appendix: SELARIX Governance Alignment

| SELARIX Principle | mempal Hardening Response |
|-------------------|--------------------------|
| **GOV-DESTRUCT-PUBLIC-001:** No delete without verification bundle + human approval | `agent` role cannot call `mempal_delete`. Only `primary` (human-operated) can delete. Audit entry records who deleted what. |
| **GOV-DENIAL-IS-GOVERNANCE:** Denial is evidence escalation | Tool access denials are audited with `"outcome": "denied"` and `"reason"`. Denial events are queryable via `audit-search`. |
| **Bottom-up doctrine:** Governance rules emerge from operations, not design | Audit trail captures operational events. Governance metadata is optional and agent-supplied, not mempal-imposed. |
| **Human approval boundary:** Agents propose, humans approve | `agent` role is read-heavy, write-limited. Destructive operations require `primary` role. Knowledge promotion gates remain deterministic. |
| **Inverted maturity pyramid:** Operational rules (Tier 1) carry more weight | No change needed — mempal's knowledge lifecycle already supports status progression (candidate -> established -> authoritative). |

---

## Appendix: Affected Code Locations

| File | Lines | Current | After Hardening |
|------|-------|---------|-----------------|
| `src/core/config.rs` | 11-27 | `Config { db_path, embed, context }` | Add `security: SecurityConfig` |
| `src/mcp/server.rs` | 101 | `client_name: Arc<Mutex<Option<String>>>` | `client_identity: Arc<Mutex<Option<ClientIdentity>>>` |
| `src/mcp/server.rs` | 113, 135 | `client_name: Arc::new(Mutex::new(None))` | `client_identity: Arc::new(Mutex::new(None))` |
| `src/mcp/server.rs` | 3827-3847 | Store raw client_info.name | Validate secret + resolve identity from config |
| `src/mcp/server.rs` | 2792-2795 | `self.client_name` for tunnel created_by | `self.client_identity.name` |
| `src/mcp/server.rs` | 2876-2880 | `self.client_name` for peek_partner | `self.client_identity` with role check |
| `src/mcp/server.rs` | 2931-2940 | `self.client_name` for cowork_push | `self.client_identity` with role check |
| `src/main.rs` | 2168-2200 | `append_ingest_audit_log()` | Add client identity + prev_hash |
| `src/main.rs` | 5540-5559 | `append_audit_entry()` | Add client identity + prev_hash |
| `src/knowledge_lifecycle.rs` | 257-276 | `append_audit_entry()` | Add client identity + prev_hash |
