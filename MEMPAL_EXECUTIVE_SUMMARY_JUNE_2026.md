# MEMPAL Evaluation — Executive Summary

**Date:** 2026-06-05
**Prepared for:** Mike Bennett, Board Chair, Quantum Shield Labs LLC
**Subject:** mempal as governance memory infrastructure for SELARIX-Lattice
**Classification:** Internal — Board-level decision record

---

## Executive Summary

Over the course of 2026-06-05, five documents were produced to evaluate whether mempal — a Rust-based project memory tool with 106 implemented specifications — can serve as the governance memory layer for the SELARIX-Lattice ecosystem, replacing Chronicle and providing citation-backed decision storage to the Paperclip agent swarm.

**The evaluation found strong technical fit and two security blockers.**

mempal is a strict superset of Chronicle. It provides hybrid search, knowledge lifecycle with deterministic promotion gates, multi-agent coordination, fact-checking, and cognitive briefing — none of which Chronicle can offer. The architecture maps cleanly to SELARIX governance needs: governance rules become knowledge cards, operational evidence becomes drawers, and the existing lifecycle (candidate to established to authoritative) mirrors SELARIX's four-tier rule maturity model.

However, the security audit found that mempal's MCP server has no authentication and trusts self-reported client identity. In a multi-agent deployment, any Paperclip agent could impersonate another agent, read session logs, delete governance data, or inject messages into other agents' inboxes. These are Critical-severity findings that block integration.

A hardening plan has been designed (four phases, ~400-750 lines, zero breaking changes) and the first specification (P107: hash-chained provenance audit log) has been written. Integration is formally blocked until hardening Phases 0-2 are implemented, re-audited, and approved by the Board Chair.

**Recommendation: Production Candidate.** mempal should be hardened and adopted — not rejected, not deferred indefinitely, and not forked. The gap between current state and integration-ready is small and well-defined.

---

## What We Learned

### Technical Findings

mempal v0.6.0 is a mature single-crate Rust binary with a SQLite + sqlite-vec storage engine (schema v9), BM25 + vector hybrid search, 23 MCP tools, a multi-agent cowork bus, and a deterministic knowledge lifecycle. It ships as `cargo install mempal` and operates entirely locally with no cloud dependencies. Chronicle v0.1 is a Python pointer/index layer with 42 hardcoded sources, script-based validation, and no query engine. mempal replaces every Chronicle function and adds capabilities Chronicle cannot provide.

### Security Findings

The security audit covered 10 focus areas and produced 23 findings (2 Critical, 5 High, 8 Medium, 5 Low, 3 Info). Positive properties: no telemetry, no SQL injection, no backdoors, minimal unsafe Rust (2 production blocks, both justified FFI), strict filesystem confinement, clean dependency chain (100% crates.io). The two Critical findings — no MCP authentication and ClientInfo.name spoofing — are architectural gaps appropriate for a single-user tool but unacceptable for multi-agent governance use.

### Governance Findings

mempal can store governance rules (GOV-DESTRUCT-PUBLIC-001, GOV-DENIAL-IS-GOVERNANCE) as knowledge cards with evidence links and KG triples. It cannot enforce them — enforcement belongs in Paperclip's agent policy layer. This boundary is correct and must be preserved: mempal is memory infrastructure, not a governance engine. The current audit log records what happened but not who did it, which is insufficient for governance provenance. P107 addresses this with a hash-chained, client-attributed audit trail.

### Architecture Findings

mempal's generic data model (wings, rooms, fields, drawers, knowledge cards, triples, tunnels) accommodates SELARIX governance without schema changes. No SELARIX-specific tables, columns, or migrations are needed. Governance rules map to knowledge cards. Governance tiers map to lifecycle status. Governance evidence maps to evidence drawers. Cross-domain links map to tunnels. This means adoption does not couple mempal's schema to SELARIX — a key architectural constraint.

---

## Decision Record

**Current status:** BLOCKED

**Approved:**
- mempal development continues (specs, features, bug fixes)
- Hardening implementation (Phases 0-2 per MEMPAL_HARDENING_PLAN.md)
- Single-user mempal usage (Mike's own Claude Code / Codex sessions)
- SELARIX governance documentation (independent of mempal)
- Paperclip agent development (no mempal MCP wiring)

**Blocked:**
- MCP server configuration for Paperclip agents
- Chronicle-to-mempal migration
- Governance data ingestion into mempal
- Any multi-agent interaction with mempal

**Why:** Two Critical-severity security findings make multi-agent use unsafe. A compromised or misconfigured Paperclip agent could read Board Chair session logs, delete governance drawers, inject messages into other agents, and forge provenance on governance decisions. This violates GOV-DESTRUCT-PUBLIC-001 (no destructive capability exposure without verification) and undermines the governance corpus that is QSL's long-term strategic asset.

---

## Architectural Position

| System | Role | Relationship to mempal |
|--------|------|----------------------|
| **SELARIX** | Governance doctrine and agent operating system | mempal stores SELARIX governance knowledge; SELARIX does not depend on mempal for enforcement |
| **Paperclip** | Agent runtime (Security Engineer, SEO Content, Revenue Analyst) | Paperclip agents will query mempal via MCP for situational awareness; Paperclip enforces policy, mempal provides memory |
| **Chronicle** | Legacy index/handoff layer (42 canonical sources, React dashboard) | To be replaced by mempal for index/retrieval; dashboard retained as read-only visualization consumer |
| **mempal** | Governance memory infrastructure | Stores, searches, and lifecycle-manages governance knowledge with citations; does not enforce rules, route agents, or make governance decisions |
| **QSL** | Parent organization (Quantum Shield Labs LLC) | mempal is developer infrastructure internal to QSL operations; not a customer-facing product component |

---

## Risks

**Current risks:**
- Hardening delays block the integration path, extending Chronicle's role as an inadequate governance index
- Single-user mempal usage (already active) operates without audit provenance — governance decisions made today lack attribution
- The two Critical findings are mitigated by the stdio transport model (no listening socket), but a compromised agent within a legitimate MCP session remains a real vector

**Future risks:**
- Scope creep: pressure to add governance enforcement to mempal rather than keeping it in Paperclip
- Schema coupling: pressure to add SELARIX-specific tables rather than using the generic data model
- Over-reliance: treating mempal search results as governance truth rather than as evidence to be verified
- Enterprise gap: mempal has no auth, no multi-tenancy, no RBAC — fine for QSL's solo-operator model, not ready for multi-customer deployment

**Risks of doing nothing:**
- Chronicle remains the governance memory layer despite having no query engine, no lifecycle, no fact-checking, and no agent coordination
- Governance decisions continue to be scattered across markdown files with no citation-backed retrieval
- The Paperclip agent swarm operates without shared memory, coordinating through ad-hoc file passing
- The governance corpus — identified as QSL's long-term strategic asset — remains unstructured and unsearchable

---

## Required Future Work

Ordered by priority:

1. **P107 implementation** — Hash-chained provenance audit log (spec written, ready for plan + implementation)
2. **P108 specification and implementation** — MCP shared-secret gate (unblocks Criterion 1)
3. **P109 specification and implementation** — Client identity verification + role-based access (unblocks Criterion 2)
4. **Re-audit** — Update MEMPAL_SECURITY_AUDIT.md to confirm Critical and High findings resolved (unblocks Criterion 4)
5. **Board Chair go/no-go** — Update MEMPAL_ADOPTION_DECISION.md with approval or continued block (unblocks Criterion 5)
6. **Minimal PoC** — Ingest 3 governance documents, validate search quality, test MCP from one Paperclip agent
7. **Chronicle migration** — Selective ingestion of canonical sources into mempal with wing/room routing
8. **P110 specification** — Optional governance provenance metadata (SELARIX-compatible audit fields)

Items 1-5 unblock integration. Items 6-8 execute it.

---

## Final Recommendation

**Production Candidate.**

mempal is not ready for SELARIX integration today. It is ready to be made ready. The capability gap between mempal and what SELARIX needs is zero — the architecture fits, the data model maps, the interfaces exist. The security gap is well-defined (two Critical findings), the fix is designed (four-phase hardening plan), the first specification is written (P107), and the estimated effort is small (~400-750 lines of Rust across three phases, zero breaking changes).

Rejecting mempal means building a governance memory system from scratch or continuing with Chronicle, which has fewer capabilities and the same security posture. Deferring indefinitely means the governance corpus remains unstructured while the Paperclip swarm operates without shared memory. A limited PoC without hardening violates the security findings that this evaluation produced.

The correct path is: harden, re-audit, approve, then integrate. The work is scoped, the plan exists, and the first spec is committed.

---

*Documents produced during this evaluation:*

| Document | Commit | Purpose |
|----------|--------|---------|
| `MEMPAL_QSL_INTEGRATION_AUDIT.md` | `99d3ae2` | Capability and architecture comparison |
| `MEMPAL_SECURITY_AUDIT.md` | `99d3ae2` | 10-area security audit, 23 findings |
| `MEMPAL_HARDENING_PLAN.md` | `99d3ae2` | Four-phase hardening design |
| `MEMPAL_ADOPTION_DECISION.md` | `95c769e` | Formal go/no-go with unblock criteria |
| `specs/p107-audit-provenance.spec.md` | `e8d354d` | Phase 0 hardening specification |
| `MEMPAL_EXECUTIVE_SUMMARY_JUNE_2026.md` | — | This document |
