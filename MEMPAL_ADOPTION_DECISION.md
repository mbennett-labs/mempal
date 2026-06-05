# MEMPAL Adoption Decision Record

**Date:** 2026-06-05
**Decision Maker:** Mike Bennett, Board Chair
**Status:** BLOCKED — do not proceed with integration
**Applies To:** mempal as governance memory infrastructure for SELARIX-Lattice / Paperclip agent swarm

---

## Decision

**mempal integration with SELARIX/Paperclip is blocked.**

mempal is a strong candidate for replacing Chronicle and providing governance memory to the Paperclip agent swarm. The capability mapping is favorable. The architecture is sound. But the security audit found two Critical-severity findings that must be resolved before any multi-agent integration.

No MCP wiring. No Paperclip configuration. No agent registration. No Chronicle migration. Until the blockers are cleared.

---

## What Was Evaluated

Three audit documents were produced on 2026-06-05:

| Document | Scope | Outcome |
|----------|-------|---------|
| `MEMPAL_QSL_INTEGRATION_AUDIT.md` | Can mempal replace/augment Chronicle for SELARIX? | Yes — superset of Chronicle capabilities |
| `MEMPAL_SECURITY_AUDIT.md` | Is mempal safe to expose to a multi-agent swarm? | No — two Critical blockers |
| `MEMPAL_HARDENING_PLAN.md` | What fixes are needed and how? | Four-phase design, ~400-750 lines, zero breaking changes |

---

## Blockers

### Blocker 1: No MCP Authentication (F1 — Critical)

**Finding:** `src/mcp/server.rs:139-145` — The MCP server accepts any connecting client with no authentication. All 23 tools are available to any process.

**Why it blocks integration:** A Paperclip agent swarm means multiple processes interacting with mempal. Without authentication, a compromised or misconfigured agent has unrestricted access to governance data — including deletion, message injection, and session reads.

**Unblock condition:** Phase 1 of MEMPAL_HARDENING_PLAN.md (shared-secret gate via `MEMPAL_MCP_SECRET` env var, opt-in, backward compatible).

### Blocker 2: ClientInfo.name Spoofing (F2 — Critical)

**Finding:** `src/mcp/server.rs:3839` — Client identity is taken from self-reported `ClientInfo.name` with no verification. This name drives partner session reads (`peek_partner`), cowork message routing (`cowork_push`), and tunnel attribution.

**Why it blocks integration:** Any Paperclip agent can impersonate Claude Code or Codex, read full session logs, and inject messages into other agents' inboxes. In a governance context, this means forged provenance on governance decisions.

**Unblock condition:** Phase 2 of MEMPAL_HARDENING_PLAN.md (verified client identity with role-based tool access).

---

## What Is NOT Blocked

The following work can proceed independently:

| Activity | Why Safe |
|----------|----------|
| mempal development (new specs, features, bug fixes) | Internal to mempal, no SELARIX coupling |
| MEMPAL_HARDENING_PLAN.md implementation (Phases 0-2) | Fixes the blockers |
| mempal single-user usage (Mike's own Claude Code / Codex) | Current threat model is valid for single-user local |
| SELARIX governance documentation | No mempal dependency |
| Chronicle maintenance | Independent system |
| Paperclip agent development | No mempal MCP wiring |
| Security audit follow-up (High-severity findings) | Improves mempal regardless of integration |

---

## Unblock Criteria

Integration may proceed when ALL of the following are true:

| # | Criterion | Verification |
|---|-----------|-------------|
| 1 | MEMPAL_HARDENING_PLAN.md Phase 1 implemented and tested | Spec P108 accepted, `mempal security generate-secret` works, unauthenticated clients rejected when secret configured |
| 2 | MEMPAL_HARDENING_PLAN.md Phase 2 implemented and tested | Spec P109 accepted, `client_identity` replaces `client_name`, role-based tool access enforced |
| 3 | Audit trail includes client identity on all mutations | Phase 0 (P107) complete, `mempal security verify-audit` passes |
| 4 | No Critical or High findings remain open in MEMPAL_SECURITY_AUDIT.md | Re-audit after hardening confirms resolution |
| 5 | Board Chair (Mike) explicitly approves integration | This decision record updated with approval |

Criteria 1-4 are technical. Criterion 5 is governance. All five are required.

---

## Recommended Sequence

```
NOW         Hardening Phase 0 (audit provenance) — P107 spec + plan + implement
            Hardening Phase 1 (shared secret) — P108 spec + plan + implement
            ↓ can be parallel
THEN        Hardening Phase 2 (identity + RBAC) — P109 spec + plan + implement

THEN        Re-audit: update MEMPAL_SECURITY_AUDIT.md, verify blockers resolved

THEN        Board Chair go/no-go on this document

ONLY THEN   Minimal PoC: ingest 3 governance docs, test search, test MCP from one Paperclip agent
```

---

## What Was Considered and Rejected

| Option | Why Rejected |
|--------|-------------|
| **Proceed with integration now, harden later** | Violates GOV-DESTRUCT-PUBLIC-001 — no destructive capability exposure without verification. The audit is the verification bundle. It says no. |
| **Use mempal CLI only (skip MCP)** | CLI doesn't solve the problem — Paperclip agents need runtime memory access. CLI-only means no agent memory, which defeats the purpose. |
| **Fork mempal with auth bolted on** | Unnecessary complexity. The hardening plan is ~400-750 lines in the existing codebase with zero breaking changes. A fork creates maintenance burden. |
| **Use Chronicle instead** | Chronicle is a static index with no query engine, no auth, no lifecycle, no fact-checking. It has fewer capabilities AND the same security posture (no auth). Replacing one unauthenticated system with another solves nothing. |
| **Build a new governance memory system** | mempal already has 106 implemented specs, hybrid search, knowledge lifecycle, multi-agent cowork, and deterministic gates. Building from scratch is months of work to reach parity. The hardening plan is days. |

---

## Risk If Ignored

If integration proceeds without hardening:

1. **Any Paperclip agent can read Board Chair session logs** — full conversation history with Claude Code exposed via `peek_partner` spoofing
2. **Any agent can delete governance drawers** — no authorization check on `mempal_delete`
3. **Any agent can inject messages into other agents' inboxes** — prompt injection across the swarm via `cowork_push` with spoofed identity
4. **Governance decisions have no provenance** — audit log records what happened but not who did it, making the governance corpus unreliable as evidence
5. **GOV-DENIAL-IS-GOVERNANCE is violated** — this decision record IS the denial, and it must be respected as evidence, not bypassed

---

## Signatures

**Decision:** BLOCKED
**Decided by:** Mike Bennett, Board Chair
**Date:** 2026-06-05
**Review date:** After hardening Phases 0-2 are complete
