# MEMPAL Security Audit

**Date:** 2026-06-05
**Author:** Claude (commissioned by Mike Bennett)
**Scope:** Pre-integration security audit of mempal v0.6.0 codebase
**Method:** Static source analysis across 10 focus areas, no runtime testing
**Status:** Audit only. No code changes.

---

## Executive Summary

mempal demonstrates strong security fundamentals for a single-user Rust CLI tool: minimal unsafe code, no telemetry, parameterized SQL, strict filesystem confinement, and clean dependency sourcing. However, the MCP server — designed for trusted local agent communication — has **no authentication**, making it the primary attack surface. The tmux cowork transport has an **unvalidated user input path** to `Command::new()` arguments. These are acceptable for the current threat model (single-user, local-only) but must be addressed before any multi-user or networked deployment.

**Critical findings: 2 | High: 5 | Medium: 8 | Low: 5 | Info: 3**

---

## Finding Summary Table

| # | Finding | Severity | Area | Status |
|---|---------|----------|------|--------|
| 1 | MCP server has no authentication | CRITICAL | MCP | Open |
| 2 | MCP ClientInfo.name spoofing enables partner session read | CRITICAL | MCP | Open |
| 3 | Unvalidated `tmux_target` passed to Command args | HIGH | Shell/Injection | Open |
| 4 | Cowork message injection via spoofed client identity | HIGH | MCP/Cowork | Open |
| 5 | No authorization on mempal_delete (any drawer_id) | HIGH | MCP | Open |
| 6 | No channel membership validation before broadcast | HIGH | Cowork | Open |
| 7 | No rate limiting on MCP tools | HIGH | MCP | Open |
| 8 | No encryption at rest (SQLite + JSONL plaintext) | MEDIUM | Data | Open |
| 9 | No automatic data retention / purge policy | MEDIUM | Data | Open |
| 10 | Unbounded cowork events.jsonl growth | MEDIUM | Data | Open |
| 11 | No `top_k` / `query` size bounds in mempal_search | MEDIUM | MCP | Open |
| 12 | tmux peek captures raw terminal (potential secret exposure) | MEDIUM | Cowork | By design |
| 13 | Codex session files readable by any local process | MEDIUM | Cowork | By design |
| 14 | Hook script relies on PATH resolution of `mempal` binary | MEDIUM | Hooks | Open |
| 15 | `cwd` parameter accepts arbitrary paths (no canonicalization) | MEDIUM | MCP | Open |
| 16 | model2vec `from_pretrained()` may download at first use | LOW | Network | Open |
| 17 | ONNX model download from hardcoded HuggingFace URL | LOW | Network | By design |
| 18 | Windows flock is no-op (no concurrent ingest protection) | LOW | Platform | Documented |
| 19 | `.draining` file orphaned on crash (inbox drain) | LOW | Cowork | Documented |
| 20 | Executable permission bits on .rs source files | LOW | Hygiene | Cosmetic |
| 21 | No telemetry, analytics, or phone-home behavior | INFO | Network | Verified clean |
| 22 | All SQL uses parameterized queries (no injection) | INFO | Data | Verified clean |
| 23 | No hardcoded secrets, backdoors, or easter eggs | INFO | Supply chain | Verified clean |

---

## 1. Network Calls / Telemetry / Outbound Requests

### Verified Clean

- **No telemetry.** No Sentry, Datadog, Honeycomb, Prometheus, or any analytics SDK.
- **No phone-home.** No crash reporting, usage tracking, or background network calls.
- **REST API is localhost-only.** CORS restricts to `http://localhost` and `http://127.0.0.1` (`src/api/handlers.rs:48-58`).
- **MCP uses stdio transport.** No network listener for MCP.

### Outbound Connections (All Opt-In)

| Connection | Trigger | Default | File |
|------------|---------|---------|------|
| Ollama / OpenAI-compatible embedding API | `backend = "api"` in config | `http://localhost:11434` (local) | `src/embed/api.rs:57-115` |
| HuggingFace ONNX model download | `backend = "onnx"` + feature flag `onnx` | Not enabled | `src/embed/onnx.rs:13-16, 182-230` |
| model2vec `from_pretrained()` | Default embedding backend | May download on first use | `src/embed/model2vec.rs:19` |

**Hardcoded URLs (complete list):**

| URL | File:Line | Purpose |
|-----|-----------|---------|
| `http://localhost:11434/api/embeddings` | `src/embed/factory.rs:50` | Default Ollama endpoint |
| `https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/main/onnx/model.onnx` | `src/embed/onnx.rs:14` | ONNX model (opt-in) |
| `https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/main/tokenizer.json` | `src/embed/onnx.rs:16` | Tokenizer (opt-in) |
| `https://example.invalid/report` | `src/mcp/server.rs:5440,5482` | Example in docs only |

### [F16] model2vec First-Use Download — LOW

**File:** `src/embed/model2vec.rs:19`

The default embedding backend calls `model2vec_rs::model::StaticModel::from_pretrained()`. The upstream `model2vec-rs` crate may download the model (`minishlab/potion-multilingual-128M`) on first use. This is not directly visible in mempal's source code.

**Mitigation:** Verify `model2vec-rs` crate behavior. If it downloads, document the first-run network requirement. Consider bundling or pre-caching the model.

### [F17] ONNX HuggingFace Download — LOW

**File:** `src/embed/onnx.rs:182-230`

Downloads ~150MB model from HuggingFace on first use. Cached at `~/.mempal/models/`. Uses atomic temp-then-rename write pattern. Only triggered with explicit feature flag `onnx` + config `backend = "onnx"`.

**Mitigation:** Acceptable for opt-in feature. Consider checksum verification of downloaded files.

---

## 2. File System Writes Outside ~/.mempal

### Write Confinement — Verified

All filesystem writes are confined to three locations:

| Location | Purpose | Files |
|----------|---------|-------|
| `~/.mempal/` | DB, config, locks, inboxes, bus, models, audit log | `src/core/db.rs`, `src/core/config.rs`, `src/ingest/lock.rs`, `src/cowork/inbox.rs`, `src/cowork/bus.rs`, `src/embed/onnx.rs` |
| `.claude/` (project-local) | Hook script + settings.json | `src/main.rs:6684-6796` |
| `~/.codex/hooks.json` | Codex hook registration | `src/main.rs:6804-6901` |

**No writes to:** system directories, global temp, user home root, or arbitrary paths.

### Path Traversal Protection — Verified

| Validator | File:Line | Protection |
|-----------|-----------|------------|
| `encode_project_identity()` | `src/cowork/inbox.rs:89-95` | Rejects relative paths, rejects `..`, replaces `/` with `-` |
| `validate_agent_id()` | `src/cowork/bus.rs:343-349` | 1-64 ASCII alphanumeric + `_-/.` only |
| `acquire_source_lock()` | `src/ingest/lock.rs:74-79` | Rejects source_key containing `/`, `\`, `..` |
| `project_identity()` | `src/cowork/inbox.rs:73-84` | Walks up to `.git` root for normalization |

### [F15] CWD Parameter Accepts Arbitrary Paths — MEDIUM

**File:** `src/mcp/server.rs:1038-1052`

The `cwd` parameter in `mempal_context`, `mempal_brief`, and cowork tools accepts any string via `PathBuf::from(value)` without canonicalization. While downstream validators (`encode_project_identity`) reject `..`, the lack of `fs::canonicalize()` at the entry point is a defense-in-depth gap.

**Mitigation:** Add `fs::canonicalize()` or at minimum reject relative paths at MCP parameter parsing.

---

## 3. Shell Execution / Command Injection

### Complete Process Execution Inventory

| Location | Command | Input Source | Risk |
|----------|---------|--------------|------|
| `src/core/anchor.rs:175-195` | `git rev-parse` | `&'static str` args only | **SAFE** — compile-time constants |
| `src/cowork/bus.rs:1298-1300` | `tmux send-keys -t {tmux_target}` | User-supplied via MCP | **VULNERABLE** |
| `src/cowork/bus.rs:1315-1317` | `tmux capture-pane -t {tmux_target}` | User-supplied via MCP | **VULNERABLE** |
| `src/cowork/bus.rs:1332-1333` | `tmux has-session -t {tmux_target}` | User-supplied via MCP | **VULNERABLE** |
| `src/main.rs:4090-4092` | Child process wrap | CLI args after `--` | **BY DESIGN** (P82, CLI-only) |

### [F3] Unvalidated tmux_target in Command Arguments — HIGH

**File:** `src/cowork/bus.rs:1296-1360`

The `tmux_target` parameter flows from MCP client (`src/mcp/tools.rs:1732`) through `register_agent()` (`src/cowork/bus.rs:485-494`) to three `Command::new("tmux")` calls with **zero format validation**. The only check is for empty string.

While `Command::new().args()` does not invoke a shell (preventing classic injection), tmux itself interprets special characters in the `-t` target parameter. The `capture-pane` and `has-session` calls lack the `--` separator that `send-keys` has.

**Input path:** MCP `tmux_target` param → `CoworkBusRequest` → `register_agent()` → stored in `AgentRecord` → used in `send_tmux()` / `capture_tmux()` / `probe_tmux_target()`

**Mitigation:** Add `validate_tmux_target()` that restricts to alphanumeric + `:` + `-` + `_` + `.` (valid tmux session:window.pane format). Apply at `register_agent()` and before all Command invocations.

### Hook Script Safety — Verified

**File:** `src/main.rs:6687-6691, 6847`

Hook scripts are hardcoded string literals with no user input concatenation:
```bash
mempal cowork-drain --target claude --cwd "${CLAUDE_PROJECT_CWD:-$PWD}" 2>/dev/null || true
```

The `${CLAUDE_PROJECT_CWD:-$PWD}` uses safe shell parameter expansion. No injection vector.

### [F14] Hook Binary PATH Resolution — MEDIUM

The hook script invokes `mempal` by bare name, relying on `$PATH` resolution. If an attacker can place a malicious `mempal` binary earlier in `$PATH`, the hook executes it with user privileges on every Claude Code prompt submission.

**Mitigation:** Consider using absolute path to mempal binary in hook script (captured at install time).

---

## 4. MCP Server Attack Surface

### [F1] No Authentication — CRITICAL

**File:** `src/mcp/server.rs:139-145`

The MCP server uses stdio transport with **no authentication mechanism**. Any local process that can connect to the stdio pipe has full access to all 23 MCP tools. There is no:
- API key or token validation
- Client identity verification beyond self-reported `ClientInfo.name`
- Per-tool authorization
- Request signing

**Current threat model:** This is acceptable for single-user, local-only use where the MCP client (Claude Code / Codex) is the only consumer. It becomes a vulnerability if mempal is exposed over a network or used in multi-tenant environments.

**Mitigation:** For SELARIX integration, add at minimum a shared-secret token validated on `initialize()`. For multi-tenant, implement RBAC.

### [F2] ClientInfo.name Spoofing Enables Session Read — CRITICAL

**File:** `src/mcp/server.rs:3827-3847`, `src/cowork/peek.rs:26-39`

The `client_info.name` from the MCP handshake is stored without validation (`server.rs:3839`). This name is used to:

1. **Infer caller identity** for `mempal_peek_partner` (auto tool selection)
2. **Determine self-push rejection** in `mempal_cowork_push`
3. **Populate `created_by`** in tunnel creation audit

An attacker connecting with `ClientInfo.name = "codex-mcp-client"` can call `mempal_peek_partner(tool="auto")` to read the **entire active Claude Code session** — including all user prompts, code reviewed, and Claude's responses.

**Recognized names** (`src/cowork/peek.rs:26-39`): `claude`, `claude-code`, `claude_code`, `codex`, `codex-cli`, `codex_cli`, `codex-tui`, `codex-mcp-client`

**Mitigation:** Do not trust `ClientInfo.name` for access control. Require explicit tool specification instead of auto-inference. Add authentication (see F1).

### [F4] Cowork Message Injection — HIGH

**Files:** `src/mcp/server.rs:2917-2982` (push), `src/mcp/server.rs:2984-3102` (bus)

With a spoofed `ClientInfo.name`, an attacker can:
- `mempal_cowork_push`: Inject messages into any agent's inbox (up to 8KB per message, 32KB total)
- `mempal_cowork_bus send`: Send messages with arbitrary `from` field to any registered agent

Injected messages are delivered to the target agent's next session, potentially influencing agent behavior through prompt injection.

**Mitigation:** Authenticate clients (F1). Validate `from` field matches authenticated identity in bus operations.

### [F5] No Authorization on mempal_delete — HIGH

**File:** `src/mcp/server.rs:2554-2576`

`mempal_delete` accepts any `drawer_id` and performs soft-delete without ownership checks. Any MCP client can delete any drawer.

**Mitigation:** For single-user use, this is acceptable (user is deleting their own data). For multi-tenant, add ownership validation.

### [F7] No Rate Limiting — HIGH

No rate limiting exists on any MCP tool. An attacker or misbehaving client can:
- Exhaust disk with repeated `mempal_ingest` calls
- Exhaust CPU/memory with `mempal_search(top_k=1000000)`
- Fill inboxes with repeated `mempal_cowork_push`

**Mitigation:** Add per-tool rate limits. Enforce `top_k` maximum (e.g., 100). Add content size limits.

### [F11] No top_k / query Size Bounds — MEDIUM

**File:** `src/mcp/server.rs:969-1018`, `src/mcp/tools.rs:32-74`

`mempal_search` defaults `top_k` to 10 but enforces no upper bound. The `query` string has no size limit. Large values cause unbounded memory and compute usage (vector embedding + search + result assembly).

**Mitigation:** Cap `top_k` at 100. Cap `query` at 10KB.

### Input Validation Summary

| MCP Tool | Validated | Gaps |
|----------|-----------|------|
| `mempal_search` | wing/room used as filters | No top_k max, no query size limit |
| `mempal_ingest` | memory_kind, domain, field, tier, status, drawer_refs | wing/room arbitrary strings, no content size limit |
| `mempal_delete` | drawer_id format | No ownership check |
| `mempal_cowork_push` | content ≤ 8KB, inbox ≤ 32KB | client identity not verified |
| `mempal_cowork_bus` | agent_id/channel/thread format validated | tmux_target unvalidated, from field not verified |
| `mempal_peek_partner` | tool name whitelist | Trusts unverified ClientInfo.name |
| `mempal_context` | cwd emptiness check | No path canonicalization |
| `mempal_tunnels` | action whitelist | created_by from unverified client_name |

---

## 5. Claude/Codex Hook Behavior

### Hook Installation

**File:** `src/main.rs:6670-6920`

`mempal cowork-install-hooks` writes three artifacts:

| Artifact | Path | Scope |
|----------|------|-------|
| Claude hook script | `.claude/hooks/user-prompt-submit.sh` | Project-local |
| Claude settings entry | `.claude/settings.json` | Project-local |
| Codex hook config | `~/.codex/hooks.json` | Global |

### Security Properties

- **Hook content is hardcoded** — no user input flows into script text
- **Graceful degradation** — `|| true` ensures hook failure doesn't block user
- **Self-healing** — detects and replaces stale hooks on re-run
- **Unix permissions** — script set to 0o755

### Codex Feature Flag

Codex hooks depend on `codex_hooks` feature flag (default OFF in codex-cli ≤ 0.120.0). `install-hooks` prints a warning and activation command when detected.

---

## 6. Cowork Inbox/Session Leakage

### Storage Model

| Component | Storage | Location | Encryption |
|-----------|---------|----------|------------|
| Legacy inbox | JSONL files | `~/.mempal/cowork-inbox/{target}/{project}.jsonl` | None |
| Bus registry | JSON file | `~/.mempal/cowork-bus/{project}/agents.json` | None |
| Bus inboxes | JSONL files | `~/.mempal/cowork-bus/{project}/inbox/{agent_id}.jsonl` | None |
| Bus events | JSONL file | `~/.mempal/cowork-bus/{project}/events.jsonl` | None |
| Bus sessions | JSON file | `~/.mempal/cowork-bus/{project}/sessions.json` | None |

### Project Isolation — Verified

Project identity is derived by walking up to the `.git` root (`src/cowork/inbox.rs:73-84`). Different git repos get different encoded project IDs in the filesystem path. Cross-project data access requires knowing the encoded project identity.

### [F6] No Channel Membership Validation — HIGH

**File:** `src/cowork/bus.rs:772-798`

`send_channel()` broadcasts to all agents in a channel record but does **not verify the sender is a member** of that channel. Any registered agent can send to any channel.

**Mitigation:** Check `registry.agents.contains_key(&from)` and verify agent is in channel member list before broadcast.

### [F12] Tmux Peek Captures Raw Terminal — MEDIUM (By Design)

**File:** `src/cowork/bus.rs:800-829, 1313-1328`

`tmux_peek` captures raw pane content (up to 500 lines) from registered agent's tmux target. This may include passwords, tokens, or other secrets visible in the terminal.

**Mitigations present:** Only reads tmux_target from registered agent record (no arbitrary pane access). Line count bounded to [1, 500].

### [F13] Codex Session Files Readable — MEDIUM (By Design)

**File:** `src/cowork/peek.rs` (codex session scanning)

`mempal_peek_partner` reads Codex session files from `~/.codex/sessions/`. Any process with home directory read access can use this to read conversation history. This is inherent to the Codex session file model, not a mempal vulnerability.

---

## 7. SQLite Schema and Data Retention

### SQL Injection — Verified Clean

All user data flows through parameterized queries (`params![]`). The only `format!()` in SQL is for:
- Schema constants (table/column names — not user input)
- Vector dimension (`usize` — integer, safe)
- FTS5 queries with proper double-quote escaping (`src/core/db.rs:2642-2655`)

### Schema Integrity

- **Migrations:** V1-V9, each wrapped in `BEGIN IMMEDIATE; ... COMMIT;` with `ROLLBACK` on error (`src/core/db.rs:1841-1872`)
- **Append-only events:** `knowledge_events` table has `BEFORE UPDATE` and `BEFORE DELETE` triggers that `RAISE(ABORT)` (`src/core/db.rs:2067-2108`)
- **Soft-delete:** Sets `deleted_at` timestamp, preserves FKs. Hard-delete via `purge_deleted()` clears FK references atomically before removal.

### [F8] No Encryption at Rest — MEDIUM

**Files:** `src/core/db.rs`, `src/cowork/bus.rs`, `src/cowork/inbox.rs`

SQLite database (`palace.db`), cowork JSONL files, and audit logs are stored as plaintext. No SQLite encryption extension (e.g., SQLCipher) is loaded.

**Impact:** Any process with filesystem read access to `~/.mempal/` can read all stored memories, including potentially sensitive content ingested from conversations.

**Mitigation:** For single-user local use, filesystem permissions are sufficient. For shared/enterprise use, add SQLCipher or OS-level disk encryption.

### [F9] No Automatic Data Retention Policy — MEDIUM

There is no automatic purge of aged content. `purge_deleted()` only removes soft-deleted items and requires explicit invocation. Active drawers persist indefinitely.

**Risk:** Sensitive data (API keys, passwords accidentally ingested) remains in the database until manually identified and deleted.

**Mitigation:** Add configurable retention policy (e.g., auto-purge soft-deleted items older than N days). Document data hygiene practices.

### [F10] Unbounded Cowork Events Log — MEDIUM

**File:** `src/cowork/bus.rs`

`events.jsonl` is append-only with no rotation or cleanup. All events are loaded into memory on every `list_events()` call — O(n) memory growth.

**Mitigation:** Add event rotation (e.g., keep last 10,000 events) or time-based cleanup.

---

## 8. Unsafe Rust Usage

### Total: 4 Unsafe Blocks (2 Production, 2 Test-Only)

| Location | Purpose | Risk |
|----------|---------|------|
| `src/core/db.rs:2185-2201` | sqlite-vec FFI extension registration via `transmute` | LOW — standard SQLite extension loading pattern |
| `src/ingest/lock.rs:149-172` | Unix `flock()` FFI for exclusive file locking | LOW — standard POSIX syscall binding |
| `src/mcp/server.rs:7603-7605` | `set_var("HOME")` in test setup | NEGLIGIBLE — test-only |
| `src/mcp/server.rs:7696-7699` | `set_var("PATH")` / `set_var("TMUX_LOG")` in test setup | NEGLIGIBLE — test-only |

**Assessment:** Minimal and justified. All unsafe code is for legitimate FFI (sqlite-vec C extension, POSIX flock). No unsafe in business logic.

### [F18] Windows flock No-Op — LOW

**File:** `src/ingest/lock.rs:174-189`

On Windows, `acquire_source_lock()` always returns success (no-op). Concurrent ingest of the same source is not protected on Windows.

**Mitigation:** Documented limitation. Consider Windows `LockFileEx` for parity.

---

## 9. Dependency Supply-Chain Risks

### Registry Source — Verified

- **All 22 direct dependencies** from `registry+https://github.com/rust-lang/crates.io-index`
- **No git dependencies**
- **No build.rs** in mempal itself
- **Cargo.lock present** (381 transitive dependencies, 3762 lines)

### Dependency Risk Assessment

| Dependency | Version | Native Code | Risk | Notes |
|------------|---------|-------------|------|-------|
| `rusqlite` | 0.37.0 | Yes (bundled SQLite) | LOW | Well-established, compiles SQLite from source |
| `sqlite-vec` | 0.1.9 | Yes (bundled C) | LOW | Compiles via `cc` crate, public source |
| `ort` | 2.0.0-rc.12 | Yes (ONNX Runtime) | MEDIUM | Pre-release, optional feature only |
| `model2vec-rs` | 0.1.4 | No | LOW | Lightweight, pure Rust |
| `rmcp` | 1.3.0 | No | LOW | MCP protocol implementation |
| `reqwest` | 0.12 | No (rustls-tls) | LOW | Uses Rust-native TLS, no system OpenSSL |
| `tokio` | 1.x | No | LOW | Standard async runtime |
| `axum` | 0.8.8 | No | LOW | Optional, production-ready |
| `clap` | 4.6.0 | No | LOW | Well-established CLI parser |
| `jieba-rs` | 0.8.1 | No | LOW | Pure Rust Chinese tokenizer |

### Notable

- **`ort` is pre-release (rc.12)** but gated behind optional `onnx` feature flag — not compiled by default
- **`rusqlite` with `bundled` feature** compiles SQLite from source at build time — standard practice, no network fetch
- **No pre/post-build scripts** in mempal itself

---

## 10. Hidden Content / Backdoors / Suspicious Strings

### Verified Clean

- **No hardcoded API keys, tokens, passwords, or credentials** in any `.rs` file
- **No base64-encoded payloads** that could indicate hidden data
- **No commented-out backdoor code**
- **No obfuscated strings or code**
- **No hidden binaries** in `src/`
- **No easter eggs or hidden functionality**
- **No `.env` files or credential files** in repository

### [F20] Executable Bits on Source Files — LOW (Cosmetic)

12 `.rs` files have executable permission bits set. These are source files, not executables — likely a filesystem metadata artifact. Harmless but untidy.

**Mitigation:** `chmod -x src/**/*.rs` (cosmetic cleanup).

---

## Threat Model Assessment

### Current Threat Model: Single-User Local Tool

mempal is designed as a personal developer tool running locally. The implicit trust assumptions are:
1. The user controls `~/.mempal/` filesystem access
2. MCP clients are trusted (Claude Code, Codex)
3. No network exposure
4. Single-tenant

**This threat model is valid for current use.** The findings above become vulnerabilities only when these assumptions are violated.

### SELARIX Integration Threat Model Shift

Integrating mempal with SELARIX changes the threat model:
- **Multiple agents** (Paperclip swarm) interact via MCP — trust boundary expands
- **Governance data** stored in mempal — higher sensitivity than developer notes
- **Potential network exposure** if REST API is enabled for dashboard
- **Multi-project** — cross-project data isolation becomes important

### Risk Matrix for SELARIX Integration

| Current State | SELARIX Integration Risk | Required Before Integration |
|---------------|-------------------------|---------------------------|
| No MCP auth | Rogue agent reads/writes all data | Add shared-secret auth |
| ClientInfo.name trust | Agent impersonation → session read | Require auth, don't trust name |
| No rate limiting | Agent DOS fills DB / exhausts CPU | Add per-tool limits |
| Plaintext storage | Governance decisions readable on disk | Evaluate encryption needs |
| No RBAC | All tools available to all clients | Define tool access per agent role |

---

## Recommended Mitigations — Prioritized

### Before SELARIX Integration (Required)

1. **Add MCP shared-secret authentication** — Validate a token on `initialize()`. Reject unauthenticated clients. This closes F1, F2, F4, and F5.

2. **Validate `tmux_target` format** — Add `validate_tmux_target()` restricting to `[a-zA-Z0-9:._-]`. Apply at `register_agent()` and before all `Command::new("tmux")` calls. This closes F3.

3. **Enforce `top_k` and `query` size limits** — Cap `top_k` at 100, `query` at 10KB. This closes F11.

4. **Add channel membership validation** — Check sender is member before `send_channel()` broadcast. This closes F6.

### Near-Term Hardening (Recommended)

5. **Add per-tool rate limiting** — Simple token-bucket per client. Closes F7.

6. **Canonicalize `cwd` paths** — Apply `fs::canonicalize()` at MCP parameter parsing. Closes F15.

7. **Use absolute path in hook scripts** — Capture mempal binary path at `install-hooks` time. Closes F14.

8. **Add event log rotation** — Keep last N events or time-window. Closes F10.

9. **Document data retention practices** — Add `mempal purge` convenience command or auto-purge config. Closes F9.

### Long-Term (If Multi-Tenant/Enterprise)

10. Implement RBAC for MCP tool access
11. Add SQLCipher or OS-level encryption at rest
12. Add comprehensive mutation audit logging
13. Implement soft-delete recovery with retention windows
14. Add checksum verification for downloaded models

---

## Positive Security Properties

The following security properties are confirmed and should be preserved:

- **No telemetry or phone-home** — verified across entire codebase
- **Parameterized SQL everywhere** — no SQL injection vectors
- **Minimal unsafe Rust** — 2 production blocks, both justified FFI
- **Strict filesystem confinement** — all writes within `~/.mempal/`, `.claude/`, `~/.codex/`
- **Path traversal protection** — `..` and relative paths rejected in all path-sensitive operations
- **Atomic file operations** — temp-then-rename for model downloads, rename-based inbox drain
- **Append-only audit integrity** — `knowledge_events` enforced by database triggers
- **No shell invocation** — all `Command::new()` uses direct exec (no `sh -c`)
- **Clean dependency chain** — 100% crates.io, no git deps, no build scripts
- **Localhost-only REST** — CORS restricted to loopback addresses
- **Graceful hook degradation** — `|| true` prevents hook failures from blocking user

---

## Appendix: Files Reviewed

### Primary Attack Surface
- `src/mcp/server.rs` — MCP server (23 tools, ~8000 lines)
- `src/mcp/tools.rs` — MCP request/response types
- `src/cowork/bus.rs` — Multi-agent cowork bus
- `src/cowork/inbox.rs` — Legacy inbox system
- `src/cowork/peek.rs` — Partner session reading

### Data Layer
- `src/core/db.rs` — SQLite schema v9, all queries
- `src/core/config.rs` — Configuration loading
- `src/ingest/lock.rs` — Per-source file locking

### Network
- `src/embed/api.rs` — API embedding client
- `src/embed/onnx.rs` — ONNX model download
- `src/embed/model2vec.rs` — Default embedder
- `src/api/handlers.rs` — REST API CORS

### Execution
- `src/core/anchor.rs` — Git command execution
- `src/main.rs` — CLI entry, hook installation, wrap command

### Dependencies
- `Cargo.toml` — Direct dependencies
- `Cargo.lock` — Full dependency tree
