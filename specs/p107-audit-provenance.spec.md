spec: task
name: "P107: hash-chained provenance audit log"
inherits: project
tags: [security, audit, provenance, hardening]
estimate: 1d
---

## Intent

P107 replaces mempal's ad-hoc audit logging with a unified, hash-chained
provenance audit log. Every mutation to palace.db, cowork state, or knowledge
lifecycle gets a single-format audit entry that records WHAT changed, WHEN,
and WHO requested it. Entries are linked by a SHA-256 hash chain so that
insertion, deletion, or modification of any entry is detectable offline
without network services, cloud signing, or LLM calls.

This is the foundation layer for SELARIX-compatible governance provenance.
mempal remains a memory tool — it records provenance, it does not enforce
governance rules.

## Threat Model

P107 addresses three threats identified in MEMPAL_SECURITY_AUDIT.md:

1. **Unattributed mutations.** Current audit entries record the command but
   not the MCP client or CLI user that triggered it. In a multi-agent
   deployment, this means governance decisions have no provenance. An agent
   could delete drawers or inject cowork messages with no attribution.

2. **Audit log tampering.** The current audit.jsonl is append-only by
   convention (OpenOptions::append), but any process with write access to
   `~/.mempal/` can insert, delete, or modify entries. There is no integrity
   check. A tampered audit log undermines governance trust.

3. **Incomplete audit coverage.** Only 7 of the ~15 mutation paths are
   currently audited. cowork_push, cowork_bus send/broadcast, tunnel
   add/delete, kg add/invalidate, and knowledge_card promote/demote are
   unaudited. Missing entries create blind spots in governance history.

Out of scope for P107's threat model:
- Network-level attacks (mempal is local-first)
- Attacks on the Rust compiler or OS
- Attacks that require root/admin access to the machine
- Real-time tamper prevention (P107 detects, it does not prevent)

## Decisions

### Event schema

- Every audit entry is a single JSON line in `{db_parent}/audit.jsonl`.
- All entries share a common envelope:
  ```json
  {
    "v": 2,
    "timestamp": "<RFC-3339 with subsecond precision>",
    "command": "<operation-slug>",
    "client": {
      "name": "<client-identity-or-unknown>",
      "role": "<role-or-unverified>",
      "source": "<mcp|cli|rest>"
    },
    "details": { ... },
    "prev_hash": "<hex-encoded SHA-256 of previous entry, or 'genesis'>"
  }
  ```
- The `v` field is the audit schema version. Existing entries without `v` are
  implicitly v1. New entries are v2. The verifier handles both.
- The `client` field is populated from the verified `ClientIdentity` when
  available (after P109). Until P109, `client.name` is populated from
  `ClientInfo.name` (self-reported, best-effort) for MCP calls, `"cli"` for
  CLI invocations, and `"rest"` for REST API calls. `client.role` is
  `"unverified"` until P109 introduces role verification.
- The `client.source` field distinguishes MCP, CLI, and REST entry points.
  CLI commands set `source: "cli"`. MCP tool handlers set `source: "mcp"`.
  REST handlers set `source: "rest"`.
- The `details` object is command-specific (see event catalog below).
- The `prev_hash` field contains the lowercase hex SHA-256 of the entire
  previous JSON line (bytes, not parsed). The first entry in a fresh log
  uses `"genesis"`. If the log file does not exist or is empty, the next
  entry uses `"genesis"`.

### Timestamp key normalization

- The existing `knowledge_distill.rs` audit writer uses `"ts"` instead of
  `"timestamp"`. P107 normalizes all new entries to `"timestamp"`. The
  verifier treats both `"ts"` and `"timestamp"` as valid for v1 entries.

### Hash-chain design

- Hash function: SHA-256 (via `sha2` crate, already a transitive dependency
  through rustls/ring).
- Input: the raw bytes of the previous JSON line, including the trailing
  newline character if present. This makes verification trivial: read each
  line, hash it, compare to the next entry's `prev_hash`.
- The chain is append-only. Entries are never updated or deleted.
- A broken chain does not prevent new entries from being appended. The new
  entry's `prev_hash` is computed from whatever the last line currently is.
  This means a tampered log accumulates evidence of tampering (the break
  point is detectable) but does not halt operations.
- Concurrent writers: the audit append function acquires an exclusive flock
  on `audit.jsonl.lock` (same pattern as `src/ingest/lock.rs`) before
  reading the last line, computing the hash, and appending. This serializes
  writes and ensures hash chain consistency. On Windows where flock is a
  no-op, concurrent writes may produce a broken chain; the verifier reports
  this as a warning, not an error.

### Event catalog — what must be recorded

Every mutation path gets an audit entry. The `command` slug and `details`
shape for each:

| # | Command Slug | Trigger | Details Shape |
|---|-------------|---------|---------------|
| 1 | `ingest` | `mempal ingest` / `mempal_ingest` | `{ wing, dir, format, dry_run, files, chunks, skipped }` |
| 2 | `delete` | `mempal delete` / `mempal_delete` | `{ drawer_id }` |
| 3 | `purge` | `mempal purge` | `{ before, purged }` |
| 4 | `knowledge_promote` | `mempal knowledge promote` / `mempal_knowledge_promote` | `{ drawer_id, old_status, new_status, verification_refs, reason, reviewer }` |
| 5 | `knowledge_demote` | `mempal knowledge demote` / `mempal_knowledge_demote` | `{ drawer_id, old_status, new_status, evidence_refs, reason, reason_type }` |
| 6 | `knowledge_distill` | `mempal knowledge distill` / `mempal_knowledge_distill` | `{ drawer_id, statement, tier, status, supporting_refs, counterexample_refs, teaching_refs }` |
| 7 | `knowledge_publish_anchor` | `mempal knowledge publish-anchor` / `mempal_knowledge_publish_anchor` | `{ drawer_id, old_anchor_kind, new_anchor_kind, reason, reviewer }` |
| 8 | `kg_add` | `mempal kg add` / `mempal_kg action=add` | `{ triple_id, subject, predicate, object }` |
| 9 | `kg_invalidate` | `mempal kg invalidate` / `mempal_kg action=invalidate` | `{ triple_id, reason }` |
| 10 | `tunnel_add` | `mempal tunnels add` / `mempal_tunnels action=add` | `{ tunnel_id, left_room, right_room, label }` |
| 11 | `tunnel_delete` | `mempal tunnels delete` / `mempal_tunnels action=delete` | `{ tunnel_id }` |
| 12 | `card_promote` | `mempal knowledge-card promote` / `mempal_knowledge_cards action=promote` | `{ card_id, old_status, new_status, evidence_refs }` |
| 13 | `card_demote` | `mempal knowledge-card demote` / `mempal_knowledge_cards action=demote` | `{ card_id, old_status, new_status, evidence_refs, reason }` |
| 14 | `cowork_push` | `mempal cowork-push` / `mempal_cowork_push` | `{ from, target, message_preview, cwd }` |
| 15 | `cowork_bus_send` | `mempal_cowork_bus action=send` | `{ from, to, message_preview, thread_id, channel }` |
| 16 | `cowork_bus_broadcast` | `mempal_cowork_bus action=broadcast` | `{ from, to, message_preview, thread_id, channel }` |

- `message_preview` is the first 200 characters of the message content,
  matching the existing bus event preview length. Full message content is
  NOT stored in the audit log to avoid unbounded growth.
- `dry_run: true` operations are audited (they record intent) but the
  `command` slug is not changed. The `dry_run` field in `details`
  distinguishes them.

### Linking to mempal entities

Audit entries link to mempal entities through ID fields in `details`:

| Entity | ID Field | Format |
|--------|----------|--------|
| Drawer | `drawer_id` | `drawer_{hex}` |
| Knowledge card | `card_id` | `card_{hex}` |
| KG triple | `triple_id` | `triple_{hex}` |
| Tunnel | `tunnel_id` | `tunnel_{hex}` |
| Source file | `dir` (ingest) | Filesystem path |
| MCP client | `client.name` | Self-reported string (unverified until P109) |
| Cowork agent | `from` / `to` | Agent ID string |

These are foreign-key-style references, not joins. The audit log is a
standalone JSONL file; it does not query palace.db to resolve IDs. Consumers
(human or tool) cross-reference by reading both the audit log and the
database.

### Verification command

`mempal security verify-audit` reads `audit.jsonl` and checks:

1. **Schema validity**: Each line parses as JSON with required fields
   (`timestamp` or `ts`, `command`). v2 entries must have `prev_hash`.
2. **Hash chain integrity**: For each v2 entry, `prev_hash` must equal the
   SHA-256 of the previous line's raw bytes. The first v2 entry's
   `prev_hash` must equal either `"genesis"` (if it is the first line) or
   the SHA-256 of the preceding line (which may be a v1 entry).
3. **Continuity**: No gaps in line numbering (detected by line count vs
   expected sequence).

Output:
- Exit 0: `audit.jsonl: OK — {n} entries, chain intact since entry {first_v2}`
- Exit 1: `audit.jsonl: BROKEN — chain break at line {line}, expected {hash}, found {found}`
- Exit 2: `audit.jsonl: PARSE ERROR — line {line}: {error}`

The verifier is read-only. It never modifies audit.jsonl.

`mempal security audit-summary` reads `audit.jsonl` and prints:
- Entry count by `command`
- Entry count by `client.name`
- Entry count by `client.source`
- Earliest and latest timestamp
- Chain status (intact / broken at line N)

Both commands are CLI-only. No MCP tool is added in P107.

### Unified audit writer

All 7 existing audit write sites and 9 new ones funnel through a single
function:

```
fn append_provenance_entry(
    db: &Database,
    command: &str,
    client: &AuditClient,
    details: &serde_json::Value,
) -> Result<()>
```

This function:
1. Acquires flock on `{db_parent}/audit.jsonl.lock`
2. Reads the last line of `audit.jsonl` (or detects empty/missing file)
3. Computes SHA-256 of last line (or uses `"genesis"`)
4. Constructs the v2 entry JSON
5. Appends the entry with `writeln!`
6. Releases flock

The 7 existing module-local `append_audit_entry` / `append_ingest_audit_log`
functions are replaced by calls to this shared function. The function lives
in a new `src/audit.rs` module.

### AuditClient population

- **CLI path**: `AuditClient { name: "cli", role: "unverified", source: "cli" }`
- **MCP path**: `AuditClient { name: client_info.name, role: "unverified", source: "mcp" }`.
  The MCP server passes its stored `client_name` (or `"unknown"` if None).
- **REST path**: `AuditClient { name: "rest", role: "unverified", source: "rest" }`
- After P109 (identity verification): `name` and `role` come from verified
  `ClientIdentity`. P107 does not implement verification — it only
  establishes the schema field.

### Backward compatibility

- Existing v1 entries (no `v`, no `prev_hash`) remain valid and are not
  modified.
- The verifier skips hash chain checks for v1 entries. The chain starts at
  the first v2 entry.
- The `"ts"` key in existing distill entries is accepted by the verifier.
- New entries always use `"timestamp"`, never `"ts"`.
- No database schema changes. No new tables. No migration.
- No changes to MCP tool signatures, CLI argument shapes, or REST endpoints.
- No changes to `mempal_status`, `mempal_doctor`, or any read-only tool.

### Failure modes

| Failure | Behavior |
|---------|----------|
| `audit.jsonl` does not exist | Created on first write. `prev_hash` = `"genesis"`. |
| `audit.jsonl` is empty | First entry uses `prev_hash` = `"genesis"`. |
| `audit.jsonl` is not writable | Audit append fails with error. The triggering command still succeeds — audit failure does not block operations. Warning printed to stderr. |
| Flock acquisition fails (timeout) | Same as not-writable: warn, do not block. |
| Last line is malformed (not valid JSON) | Hash is computed on raw bytes regardless. Chain integrity is preserved even if content is corrupt. |
| Concurrent writes without flock (Windows) | Entries may interleave. Hash chain may break. Verifier reports break point as warning, not error, on Windows. |
| Disk full | Audit append fails. Command succeeds. Warning printed. |
| Hash chain already broken | New entries chain from whatever the current last line is. The old break point remains detectable. |

Key invariant: **audit failure never blocks mempal operations.** The audit
log is observability infrastructure, not a control gate.

## Boundaries

### Allowed Changes
- src/audit.rs (new file — unified audit writer + verifier)
- src/main.rs (replace existing audit calls with `append_provenance_entry`,
  add `security verify-audit` and `security audit-summary` subcommands,
  add audit calls to kg add/invalidate and tunnel add/delete)
- src/knowledge_lifecycle.rs (replace local audit function with shared)
- src/knowledge_anchor.rs (replace local audit function with shared)
- src/knowledge_distill.rs (replace local audit function with shared,
  normalize `"ts"` to `"timestamp"`)
- src/knowledge_card_lifecycle.rs (add audit calls to promote/demote)
- src/mcp/server.rs (pass client_name to audit calls for cowork_push,
  cowork_bus send/broadcast, tunnel add/delete, kg add/invalidate,
  card promote/demote)
- src/cowork/bus.rs (no change — bus events.jsonl is a separate log, not
  replaced by audit.jsonl)
- Cargo.toml (add `sha2` as direct dependency if not already present)
- specs/p107-audit-provenance.spec.md
- docs/plans/...-p107-audit-provenance.md
- CLAUDE.md (add P107 to spec table and plan list)
- AGENTS.md (if applicable)

### Forbidden
- Do not modify palace.db schema. No new tables, columns, or migrations.
- Do not add MCP tools in P107. Verification is CLI-only.
- Do not add authentication or identity verification (that is P108/P109).
- Do not add governance rule enforcement or interpretation.
- Do not make audit failure block mempal operations.
- Do not delete or modify existing v1 audit entries.
- Do not add network calls, cloud services, or LLM dependencies.
- Do not change cowork bus events.jsonl format or behavior.
- Do not add encryption to the audit log (plaintext JSONL, human-readable).
- Do not add automatic rotation or cleanup of audit.jsonl in P107.

## Acceptance Criteria

Scenario: new audit entries include v2 envelope with hash chain
  Test:
    Filter: cargo test --test audit_provenance test_v2_entry_format
  Given an empty audit.jsonl
  When a drawer is ingested via CLI
  Then audit.jsonl contains one line
  And the entry has `"v": 2`
  And the entry has `"timestamp"` in RFC-3339 format
  And the entry has `"command": "ingest"`
  And the entry has `"client": { "name": "cli", "role": "unverified", "source": "cli" }`
  And the entry has `"prev_hash": "genesis"`

Scenario: hash chain links consecutive entries
  Test:
    Filter: cargo test --test audit_provenance test_hash_chain_links
  Given an audit.jsonl with one v2 entry
  When a second mutation is performed
  Then the second entry's `prev_hash` equals the SHA-256 of the first entry's raw line bytes

Scenario: all 16 mutation paths produce audit entries
  Test:
    Filter: cargo test --test audit_provenance test_all_mutations_audited
  Given an empty audit.jsonl
  When each of the 16 mutation types is performed once
  Then audit.jsonl contains 16 entries
  And each entry has a distinct `command` slug matching the event catalog

Scenario: MCP calls include client name in audit entry
  Test:
    Filter: cargo test --test audit_provenance test_mcp_client_in_audit
  Given an MCP server with client_info.name = "claude-code"
  When a mutation is performed via MCP
  Then the audit entry has `"client": { "name": "claude-code", ..., "source": "mcp" }`

Scenario: verify-audit reports intact chain
  Test:
    Filter: cargo test --test audit_provenance test_verify_intact_chain
  Given an audit.jsonl with 5 v2 entries and valid hash chain
  When `mempal security verify-audit` is run
  Then exit code is 0
  And output contains "chain intact"

Scenario: verify-audit detects tampered entry
  Test:
    Filter: cargo test --test audit_provenance test_verify_detects_tampering
  Given an audit.jsonl with 5 v2 entries
  When the third entry is modified (content changed, hash not updated)
  Then `mempal security verify-audit` exits with code 1
  And output contains "chain break at line 4"

Scenario: verify-audit handles mixed v1 and v2 entries
  Test:
    Filter: cargo test --test audit_provenance test_verify_mixed_v1_v2
  Given an audit.jsonl with 3 v1 entries (no `v`, no `prev_hash`) followed by 2 v2 entries
  When `mempal security verify-audit` is run
  Then exit code is 0
  And output reports chain starts at entry 4
  And v1 entries are counted but not hash-checked

Scenario: audit-summary reports counts by command and client
  Test:
    Filter: cargo test --test audit_provenance test_audit_summary
  Given an audit.jsonl with entries from multiple commands and clients
  When `mempal security audit-summary` is run
  Then output shows entry count grouped by `command`
  And output shows entry count grouped by `client.name`
  And output shows earliest and latest timestamps

Scenario: audit failure does not block operations
  Test:
    Filter: cargo test --test audit_provenance test_audit_failure_non_blocking
  Given audit.jsonl is not writable (read-only permissions)
  When a drawer is ingested
  Then ingestion succeeds
  And a warning is printed to stderr
  And no audit entry is written

Scenario: concurrent writes maintain chain integrity under flock
  Test:
    Filter: cargo test --test audit_provenance test_concurrent_flock
  Given two threads performing mutations concurrently
  When both complete
  Then audit.jsonl contains entries from both threads
  And `mempal security verify-audit` reports chain intact

Scenario: existing distill entries with "ts" key are accepted by verifier
  Test:
    Filter: cargo test --test audit_provenance test_verifier_accepts_ts_key
  Given an audit.jsonl with a v1 entry using `"ts"` instead of `"timestamp"`
  When `mempal security verify-audit` is run
  Then exit code is 0
  And the entry is counted in the summary

Scenario: dry-run operations are audited with dry_run flag
  Test:
    Filter: cargo test --test audit_provenance test_dry_run_audited
  Given a dry-run ingest
  When the command completes
  Then audit.jsonl contains an entry with `"command": "ingest"` and `"details": { "dry_run": true, ... }`

## Out of Scope

- MCP tool for audit verification (CLI-only in P107; MCP may come later).
- Audit log rotation, cleanup, or size management.
- Encryption of audit entries.
- Authentication or identity verification (P108/P109).
- Governance rule enforcement or interpretation.
- Governance provenance metadata field (P110).
- Real-time tamper prevention or alerting.
- Changes to cowork bus events.jsonl (separate event stream, not replaced).
- REST API endpoints for audit queries.
- Database schema changes.
