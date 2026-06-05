# MEMPAL / QSL-SELARIX Integration Audit

**Date:** 2026-06-05
**Author:** Claude (commissioned by Mike Bennett)
**Scope:** Evaluate mempal as governance memory infrastructure for the SELARIX-Lattice ecosystem
**Status:** Audit only. No code changes.

---

## Executive Summary

mempal is a Rust-based project memory tool with citation-backed retrieval, knowledge lifecycle, multi-agent cowork, and deterministic governance primitives. Chronicle is a Python pointer/index layer with 42 canonical sources, script-based validation, and no native query engine.

**Verdict:** mempal can replace Chronicle's index/retrieval function and substantially augment SELARIX governance with capabilities Chronicle cannot provide — citation-backed search, knowledge lifecycle with promotion gates, fact-checking, and multi-agent coordination. The integration is high-ROI because mempal already solves the problems Chronicle was designed to solve, with a superset of capabilities, and ships as a single binary.

The risk is scope creep: mempal is a memory tool, not a governance engine. SELARIX governance rules need enforcement at the agent runtime layer (Paperclip/Model Gateway), not in the memory layer. mempal should store and retrieve governance decisions — not enforce them.

---

## Architecture Comparison

| Dimension | Chronicle v0.1 | mempal v0.6.0 |
|-----------|---------------|---------------|
| **Language** | Python scripts | Rust, single binary (`cargo install mempal`) |
| **Storage** | Filesystem pointers (`POINTER.md` files) | SQLite + sqlite-vec (`palace.db`), schema v9 |
| **Index** | 42 hardcoded canonical sources | Dynamic — any file, transcript, diary ingested |
| **Query** | Manual file loading by task profile | Hybrid search: BM25 + vector + RRF fusion |
| **Validation** | `validate_chronicle.py` script | `mempal doctor` + `mempal release-readiness` |
| **Retrieval** | `retrieval_manifest.json` (9 task profiles) | `mempal_search` with wing/room routing + tunnel hints |
| **Handoff** | `canonical_handoff.md` (generated) | `mempal brief` (deterministic, citation-first) |
| **Lineage** | 18 lineage links (synthetic) | Knowledge cards with evidence links + lifecycle events |
| **Governance** | None (stores docs about governance) | Knowledge lifecycle: distill -> gate -> promote/demote |
| **Multi-agent** | None | Cowork bus: agent registry, inbox, channels, tmux transport, sessions |
| **Fact-checking** | None | `mempal_fact_check`: contradiction detection on KG triples |
| **Embedding** | None | model2vec (256d), potion-multilingual-128M |
| **Interfaces** | Python scripts only | CLI + MCP (23 tools) + REST API (feature-gated) |
| **Context assembly** | Load markdown files | `mempal context`: dao/shu/qi hierarchy with budget controls |

**Key architectural gap:** Chronicle is a static index that requires regeneration scripts. mempal is a live query engine with continuous ingestion. Chronicle cannot answer "what governance decisions were made about X?" — it can only point you to files that might contain the answer. mempal can search, rank, cite, and assemble context around that question.

---

## Feature Mapping

### What Chronicle does that mempal already does better

| Chronicle Feature | mempal Equivalent | Notes |
|-------------------|-------------------|-------|
| Canonical source index | Wing/Room taxonomy + `mempal_search` | Dynamic, not hardcoded |
| Task-profile retrieval | `mempal context` with dao/shu/qi hierarchy | Budget-controlled, not manual |
| Handoff generation | `mempal brief` / `mempal_cowork_bus handoff` | Deterministic, citation-first |
| Lineage links | Knowledge card evidence links | Typed, auditable, lifecycle-managed |
| Validation scripts | `mempal doctor` / `mempal release-readiness` | Binary, not Python dependency |
| Category index | Wings (project areas) + Rooms (topic clusters) | Searchable, not just navigable |

### What mempal adds that Chronicle cannot provide

| Capability | SELARIX Value |
|------------|---------------|
| **Hybrid search** (BM25 + vector) | Find governance decisions by semantic meaning, not just keywords |
| **Knowledge lifecycle** (distill -> gate -> promote) | Model governance rule maturity (Tier 1-4 from rule registry) |
| **Fact-checking** (triple contradictions) | Detect when new governance rules contradict existing ones |
| **Multi-agent cowork bus** | Paperclip agents coordinate through mempal, not ad-hoc |
| **Knowledge cards** (Phase-2) | Structured governance knowledge with evidence links |
| **Runtime adoption tracking** (Phase-3) | Measure whether governance rules are actually being used |
| **Cognitive brief** | On-demand situational awareness for any agent session |
| **AAAK output formatting** | Structured signals (entities, topics, flags, emotions, importance) |
| **Tunnels** | Cross-domain links (e.g., TheBinMap governance -> SELARIX doctrine) |

---

## Integration Opportunities

### 1. Can mempal replace or augment Chronicle?

**Replace the index function: YES.** Chronicle's 42 canonical sources can be ingested into mempal with wing/room routing. `mempal_search` replaces `retrieval_manifest.json` task profiles. `mempal brief` replaces `canonical_handoff.md`.

**Replace the lineage function: YES.** Knowledge cards with evidence links provide typed, auditable lineage that Chronicle's flat link list cannot. The lifecycle (candidate -> established -> authoritative) maps directly to governance rule maturity tiers.

**Replace the dashboard/replay: NO.** Chronicle's React timeline replay UI is a presentation layer. mempal has no UI. The dashboard should remain as a visualization consumer of mempal data, not be replaced by it.

**Recommendation:** Migrate Chronicle's canonical sources into mempal. Keep the dashboard as a read-only visualization that queries mempal via CLI/MCP/REST.

### 2. Can mempal store governance decisions with citations?

**YES.** This is mempal's core capability. Every search result includes `drawer_id`, `source_file`, and `tunnel_hints`. Knowledge cards track evidence links with roles (supporting/contradicting/contextual).

Governance decisions would be stored as:
- **Evidence drawers:** Raw decision records (who decided, what was decided, when, why)
- **Knowledge cards:** Distilled governance rules with evidence links back to the decisions that created them
- **KG triples:** Structured relationships (e.g., `GOV-DESTRUCT-PUBLIC-001 --requires--> verification_bundle`)

### 3. Can mempal model GOV-DESTRUCT-PUBLIC-001 and GOV-DENIAL-IS-GOVERNANCE?

**YES, as knowledge artifacts. NO, as enforcement mechanisms.**

**Storage model:**
```
Wing: selarix-governance
Room: operational-rules

Knowledge Card: GOV-DESTRUCT-PUBLIC-001
  Status: established (Tier 1 — validated from real operations)
  Statement: "No delete on public indexed content without verification bundle + human approval"
  Evidence links:
    - TheBinMap 53-listing denial event (role: supporting)
    - Board Chair denial directive (role: supporting)
  KG triples:
    - (GOV-DESTRUCT-PUBLIC-001, requires, verification_bundle)
    - (GOV-DESTRUCT-PUBLIC-001, requires, human_approval)
    - (GOV-DESTRUCT-PUBLIC-001, validated_by, TheBinMap_case)

Knowledge Card: GOV-DENIAL-IS-GOVERNANCE
  Status: established (Tier 1)
  Statement: "Denial is not rejection — it is evidence escalation and training data"
  Evidence links:
    - TheBinMap 53-listing denial event (role: supporting)
```

**What mempal will NOT do:** Enforce these rules at runtime. mempal stores, retrieves, and tracks the lifecycle of governance knowledge. Enforcement belongs in Paperclip's agent policy layer or a future Model Gateway. mempal can answer "what are the active governance rules?" — it cannot prevent an agent from violating them.

### 4. Can Paperclip interact with mempal?

**YES, through three interfaces:**

| Interface | Use Case | Setup |
|-----------|----------|-------|
| **MCP** (23 tools) | Agent runtime: search, context, brief, knowledge lifecycle | Configure mempal as MCP server in Paperclip agent config |
| **CLI** | Automation: ingest, search, cowork, maintenance | Shell out from Paperclip scripts or cron |
| **REST API** | Web integration: dashboard queries | `cargo install mempal --features rest`, then HTTP |

**MCP is the recommended path** for Paperclip agents. The `mempal_search`, `mempal_context`, and `mempal_brief` tools give agents situational awareness. The `mempal_cowork_bus` enables multi-agent coordination.

**Specific Paperclip agent integrations:**
- **Security Engineer agent:** `mempal_search wing=selarix-governance` before proposing destructive operations
- **Board Chair (Mike):** `mempal brief` for 7 AM digest context
- **Any agent:** `mempal_fact_check` before asserting governance claims

### 5. Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| **Scope creep: mempal becomes governance engine** | HIGH | mempal stores and retrieves. Enforcement stays in Paperclip/Model Gateway. Hard boundary. |
| **Dual maintenance: Chronicle + mempal** | MEDIUM | Migrate Chronicle fully. Don't run both as source-of-truth. |
| **Schema coupling: SELARIX governance schema baked into mempal** | MEDIUM | Use wing/room/field taxonomy — generic, not SELARIX-specific. No schema changes needed. |
| **Single-binary dependency: Rust build required** | LOW | `cargo install mempal` works. Pre-built binaries possible via CI. |
| **Embedding model mismatch: governance text is domain-specific** | LOW | model2vec handles multilingual/domain text well. Monitor search quality. |
| **Over-ingestion: dumping all 42 Chronicle sources** | MEDIUM | Selective migration. Only ingest sources that are actually queried. |
| **mempal is a personal project, not enterprise software** | HIGH | mempal has no auth, no multi-tenancy, no RBAC. Fine for solo/small-team use. Not ready for multi-customer deployment. |

### 6. Capabilities that already overlap with SELARIX

| SELARIX Need | mempal Capability | Overlap Quality |
|--------------|-------------------|-----------------|
| Governance decision history | Evidence drawers + knowledge cards | **Strong** — citation-backed, lifecycle-managed |
| Operational memory | Wing/Room taxonomy + hybrid search | **Strong** — better than Chronicle's static index |
| Agent coordination | Cowork bus (P84-P96) | **Strong** — agent registry, inbox, channels, sessions |
| Governance rule registry | Knowledge cards with status lifecycle | **Moderate** — status maps to tiers, but no enforcement |
| Lineage / provenance | Evidence links + KG triples | **Strong** — typed, auditable |
| Contradiction detection | `mempal_fact_check` | **Moderate** — works on KG triples, not free-text rules |
| Approval/denial recording | Drawers with metadata + diary convention | **Moderate** — stores events, doesn't model approval workflow |
| Timeline replay | None | **No overlap** — mempal has no UI |
| Model Gateway routing | None | **No overlap** — mempal is storage, not routing |

### 7. Capabilities missing for SELARIX

| Missing Capability | Why It Matters | Build vs. Wait |
|--------------------|----------------|----------------|
| **Governance rule enforcement** | Rules in mempal are inert knowledge, not runtime policy | **Don't build in mempal.** This belongs in Paperclip/Model Gateway. |
| **Approval workflow** | SELARIX needs approve/deny/comment/question flow | **Don't build in mempal.** Paperclip's QSL Review board handles this. |
| **Web UI / dashboard** | Chronicle dashboard is a key demo asset | **Keep Chronicle dashboard.** Wire it to mempal as data source. |
| **Multi-tenancy / auth** | Enterprise SELARIX deployment needs isolation | **Wait.** Not needed for solo/small-team phase. |
| **Governance rule schema** | Structured fields: tier, scope, enforcement_mode, validation_status | **Consider lightweight extension.** Field taxonomy can handle this without schema changes. |
| **Event sourcing / audit log** | SELARIX needs immutable governance event history | **Partially present.** `knowledge_events` table is append-only. Could be extended. |
| **Compliance reporting** | Export governance history for auditors | **Not present.** Would need a reporting layer on top of mempal queries. |

---

## Build vs. Adopt Analysis

### What to adopt (use mempal as-is)

1. **Governance knowledge storage** — Ingest governance rules, decisions, and case studies as evidence drawers. Distill into knowledge cards. Use lifecycle (candidate -> established -> authoritative) to track rule maturity.

2. **Agent memory** — Replace Chronicle's handoff mechanism with `mempal brief` and `mempal context`. Agents start sessions with situational awareness instead of loading markdown files.

3. **Multi-agent coordination** — Use cowork bus for Paperclip agent-to-agent communication instead of ad-hoc mechanisms.

4. **Fact-checking** — Use `mempal_fact_check` to detect governance contradictions before they reach production.

### What to build (extend mempal or build alongside)

1. **Chronicle-to-mempal migration script** — One-time script to ingest Chronicle's 42 canonical sources with appropriate wing/room routing. ~2 hours of work.

2. **Governance wing taxonomy** — Define `wing=selarix-governance` with rooms: `operational-rules`, `constitutional-invariants`, `approval-history`, `case-studies`. No code changes — just convention.

3. **Dashboard data adapter** — Modify Chronicle dashboard to query mempal (via REST API or CLI) instead of reading filesystem pointers. The dashboard's replay/lineage visualization stays; the data source changes.

### What NOT to build

1. **Governance enforcement in mempal** — mempal is memory, not policy. Don't add rule enforcement, approval gates, or agent blocking to mempal.

2. **SELARIX-specific schema changes** — mempal's generic wing/room/field/knowledge-card model handles governance without custom tables. Don't couple mempal's schema to SELARIX.

3. **Multi-tenant mempal** — Not needed at current scale. Each project gets its own `palace.db`. Cross-project queries use tunnels.

4. **AI-powered governance analysis** — mempal is deliberately deterministic (no LLM calls). Don't add LLM-based rule analysis. Keep that in the agent layer.

---

## Recommended Next Steps

### Minimum Useful Proof-of-Concept (1-2 hours)

1. Install mempal in QSL project: `cargo install mempal`
2. Ingest 3 governance artifacts:
   - `SELARIX_REAL_WORLD_VALIDATION_REPORT_JUNE_2026.md`
   - `GOVERNANCE_RULE_REGISTRY.md`
   - `SELARIX_LATTICE_CASE_STUDY_THEBINMAP_DATA_CLEANUP.md`
3. Create knowledge cards for GOV-DESTRUCT-PUBLIC-001 and GOV-DENIAL-IS-GOVERNANCE
4. Search: `mempal search "what rules apply to destructive operations"`
5. Verify citations point back to source documents

If that works, the integration thesis is proven.

### Highest ROI Integration Path

1. **Week 1:** PoC above. Validate search quality on governance corpus.
2. **Week 2:** Configure mempal as MCP server for Paperclip agents. Test `mempal_search` from Security Engineer agent.
3. **Week 3:** Migrate Chronicle canonical sources to mempal. Deprecate Chronicle scripts.
4. **Week 4:** Wire Chronicle dashboard to mempal REST API. Keep visualization, swap data source.

### What to Avoid

1. **Don't run Chronicle and mempal as parallel sources of truth.** Pick one. mempal is strictly more capable.
2. **Don't add SELARIX governance enforcement to mempal.** The temptation will be strong. Resist it.
3. **Don't ingest everything at once.** Start with the 3 highest-value governance documents. Validate. Expand.
4. **Don't modify mempal's schema for SELARIX.** Use the existing generic model. If it doesn't fit, that's a signal to keep the data in Paperclip, not to change mempal.
5. **Don't treat mempal as a product component of SELARIX.** mempal is developer infrastructure. SELARIX customers should never see or interact with mempal directly. It's the memory layer behind the agents.

---

## Appendix: SELARIX Governance Rule -> mempal Mapping

```
SELARIX Tier 1 (Operational, validated)  -> Knowledge Card status: established
SELARIX Tier 2 (Operational, exercised)  -> Knowledge Card status: established
SELARIX Tier 3 (Constitutional)          -> Knowledge Card status: candidate
SELARIX Tier 4 (Design-only)             -> Knowledge Card status: candidate

SELARIX Rule Registry                    -> Wing: selarix-governance, Room: rule-registry
SELARIX Case Studies                     -> Wing: selarix-governance, Room: case-studies
SELARIX Approval History                 -> Wing: selarix-governance, Room: approvals
SELARIX Constitutional Invariants        -> Wing: selarix-governance, Room: invariants

Paperclip agent policy candidates        -> mempal knowledge cards with `field: agent-policy`
Model Gateway routing rules              -> NOT in mempal (enforcement layer)
```
