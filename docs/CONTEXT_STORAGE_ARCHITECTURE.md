# SecureVibes Context Storage Architecture

## Overview

When SecureVibes runs as a service, vulnerability triage decisions need to be:
1. **Recorded** — Why was this a TP/FP? What was the reasoning?
2. **Persisted** — Survive across PRs, sprints, team changes
3. **Retrievable** — "Have we seen this before? What did we decide?"
4. **Self-improving** — Past decisions inform future ones
5. **Hierarchical** — Per-repo context + per-org patterns
6. **Lightweight** — Can't be heavy infra for every repo

This document outlines a phased approach: an MVP architecture using proven technologies, followed by a post-MVP architecture leveraging RuVector for self-learning capabilities.

---

## Table of Contents
1. [MVP Architecture](#mvp-architecture)
2. [Post-MVP Architecture (RuVector)](#post-mvp-architecture-ruvector)
3. [Migration Path](#migration-path)
4. [Implementation Phases](#implementation-phases)
5. [API Design](#api-design)
6. [Open Questions](#open-questions)

---

## MVP Architecture

### Design Principles
- Use proven, battle-tested technologies
- Minimize infrastructure complexity
- Prioritize developer experience (decisions travel with code)
- Enable future migration to more sophisticated solutions

### Three-Layer Storage

```
┌─────────────────────────────────────────────────────────────────┐
│                     SecureVibes Service                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │   PR Scan    │───▶│  Decision    │───▶│   Report     │       │
│  │   Engine     │    │  Engine      │    │   Generator  │       │
│  └──────────────┘    └──────┬───────┘    └──────────────┘       │
│                             │                                    │
│                             ▼                                    │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    Context Store (MVP)                       ││
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          ││
│  │  │  Layer 1    │  │  Layer 2    │  │  Layer 3    │          ││
│  │  │  Per-Repo   │  │  Per-Org    │  │  Semantic   │          ││
│  │  │  (Git)      │  │  (Postgres) │  │  (pgvector) │          ││
│  │  └─────────────┘  └─────────────┘  └─────────────┘          ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

### Layer 1: Per-Repo Storage (Git-Native)

**Purpose:** Store repo-specific decisions that travel with the code.

**Structure:**
```
repo/
└── .securevibes/
    ├── config.yaml              # Repo-specific settings
    ├── baseline/
    │   ├── threat_model.json    # Baseline threat model
    │   └── known_fps.json       # Curated false positives
    ├── decisions/
    │   ├── 2026-01-17-pr-42.jsonl
    │   └── ...
    └── index.db                 # SQLite cache (gitignored)
```

**Decision Schema (JSONL):**
```json
{
  "id": "dec-a1b2c3d4",
  "timestamp": "2026-01-17T23:00:00Z",
  "pr": "42",
  "commit": "abc123",
  
  "finding": {
    "hash": "sha256:...",
    "type": "sql_injection",
    "file": "src/api/users.py",
    "line": 42,
    "snippet": "cursor.execute(f\"SELECT * FROM users WHERE id={user_id}\")",
    "severity": "high",
    "cwe": "CWE-89"
  },
  
  "decision": {
    "verdict": "false_positive",
    "confidence": 0.95,
    "reasoning": "Using SQLAlchemy ORM with parameterized queries.",
    "evidence": ["src/api/users.py uses SQLAlchemy session.query()"]
  },
  
  "context": {
    "similar_decisions": ["dec-x1y2z3"],
    "org_pattern_match": "parameterized_queries_policy",
    "reviewer": "securevibes-agent"
  }
}
```

**Why Git-Native:**
- ✅ Versioned — Full history, blame, bisect
- ✅ Portable — Repo moves, decisions move with it
- ✅ Reviewable — Developers can see/challenge decisions
- ✅ Branch-aware — Different decisions on different branches
- ✅ No extra infra — Just files in the repo

### Layer 2: Per-Org Storage (PostgreSQL)

**Purpose:** Aggregate patterns across repos, store org-specific policies.

**Schema:**
```sql
-- Organizations
CREATE TABLE orgs (
  id UUID PRIMARY KEY,
  name TEXT NOT NULL,
  settings JSONB,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Repositories
CREATE TABLE repos (
  id UUID PRIMARY KEY,
  org_id UUID REFERENCES orgs(id),
  name TEXT NOT NULL,
  url TEXT,
  last_scan TIMESTAMP,
  decision_count INT DEFAULT 0
);

-- Aggregated Patterns (learned from decisions)
CREATE TABLE patterns (
  id UUID PRIMARY KEY,
  org_id UUID REFERENCES orgs(id),
  name TEXT NOT NULL,
  description TEXT,
  match_criteria JSONB,
  default_verdict TEXT,
  confidence FLOAT,
  occurrence_count INT DEFAULT 0,
  last_updated TIMESTAMP DEFAULT NOW()
);

-- Org-wide Policies
CREATE TABLE policies (
  id UUID PRIMARY KEY,
  org_id UUID REFERENCES orgs(id),
  name TEXT NOT NULL,
  rules JSONB,
  enabled BOOLEAN DEFAULT true
);

-- Decision Index (for cross-repo lookup)
CREATE TABLE decision_index (
  id UUID PRIMARY KEY,
  org_id UUID REFERENCES orgs(id),
  repo_id UUID REFERENCES repos(id),
  finding_hash TEXT NOT NULL,
  finding_type TEXT NOT NULL,
  verdict TEXT NOT NULL,
  reasoning TEXT,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_finding_hash ON decision_index(finding_hash);
CREATE INDEX idx_finding_type ON decision_index(org_id, finding_type);
```

### Layer 3: Semantic Search (pgvector)

**Purpose:** Answer "Have we seen something like this before?"

**Schema Extension:**
```sql
-- Enable pgvector
CREATE EXTENSION IF NOT EXISTS vector;

-- Add embedding column to decision_index
ALTER TABLE decision_index 
ADD COLUMN embedding vector(1536);

-- Create HNSW index for fast similarity search
CREATE INDEX idx_embedding ON decision_index 
USING hnsw (embedding vector_cosine_ops);
```

**Embedding Strategy:**
```python
def create_embedding(finding, code_context):
    text = f"""
    Finding Type: {finding.type}
    CWE: {finding.cwe}
    Severity: {finding.severity}
    Code Snippet: {code_context}
    File Path: {finding.file}
    """
    return openai.embeddings.create(
        model="text-embedding-3-small",
        input=text
    ).data[0].embedding
```

### MVP Query Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                        PR #42 Scan                               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 1. Run SecureVibes scan → Findings                              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. For each finding, query Context Store:                       │
│                                                                  │
│    a. Check repo baseline (Layer 1 - Git)                       │
│       → Is this in known_fps.json?                              │
│                                                                  │
│    b. Check org patterns (Layer 2 - Postgres)                   │
│       → Does this match a learned pattern?                      │
│                                                                  │
│    c. Semantic search (Layer 3 - pgvector)                      │
│       → Find similar past decisions                             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. Decision Engine combines context → Recommendation            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 4. Record decision back to all layers                           │
└─────────────────────────────────────────────────────────────────┘
```

---

## Post-MVP Architecture (RuVector)

### Why RuVector?

[RuVector](https://github.com/ruvnet/ruvector) is a distributed vector database with self-learning capabilities:

| Feature | Benefit for SecureVibes |
|---------|------------------------|
| **GNN Self-Learning** | Index improves with usage — no manual pattern extraction |
| **Cypher Queries** | Graph queries for complex relationships |
| **Hyperedges** | Model finding → file → commit → PR → decision relationships |
| **61µs Latency** | Real-time decision lookup |
| **PostgreSQL Extension** | Can integrate with existing Postgres |
| **SIMD Optimization** | Fast vector operations |

### Post-MVP Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     SecureVibes Service                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │   PR Scan    │───▶│  Decision    │───▶│   Report     │       │
│  │   Engine     │    │  Engine      │    │   Generator  │       │
│  └──────────────┘    └──────┬───────┘    └──────────────┘       │
│                             │                                    │
│                             ▼                                    │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                 Context Graph (RuVector)                     ││
│  │                                                               ││
│  │  ┌─────────────┐                                             ││
│  │  │  Layer 1    │  Git-native (.securevibes/)                 ││
│  │  │  Per-Repo   │  Unchanged from MVP                         ││
│  │  └──────┬──────┘                                             ││
│  │         │ sync                                                ││
│  │         ▼                                                     ││
│  │  ┌─────────────────────────────────────────────────────────┐ ││
│  │  │              RuVector Graph Database                     │ ││
│  │  │                                                          │ ││
│  │  │  ┌─────────┐    ┌─────────┐    ┌─────────┐              │ ││
│  │  │  │ Nodes:  │    │ Edges:  │    │ GNN:    │              │ ││
│  │  │  │Finding  │───▶│SIMILAR  │    │Self-    │              │ ││
│  │  │  │Decision │    │CAUSED_BY│    │Learning │              │ ││
│  │  │  │File     │    │IN_PR    │    │Index    │              │ ││
│  │  │  │Pattern  │    │MATCHES  │    │         │              │ ││
│  │  │  └─────────┘    └─────────┘    └─────────┘              │ ││
│  │  │                                                          │ ││
│  │  │  Query: Cypher + Vector Similarity                       │ ││
│  │  └─────────────────────────────────────────────────────────┘ ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

### Graph Schema (RuVector)

```cypher
// Node Types
(:Finding {
  hash: string,
  type: string,
  cwe: string,
  severity: string,
  snippet: string,
  embedding: vector
})

(:Decision {
  id: string,
  verdict: string,
  confidence: float,
  reasoning: string,
  timestamp: datetime
})

(:File {
  path: string,
  repo: string
})

(:PR {
  number: int,
  repo: string,
  commit: string
})

(:Pattern {
  name: string,
  description: string,
  confidence: float,
  occurrence_count: int
})

// Edge Types
(:Finding)-[:DECIDED_AS]->(:Decision)
(:Finding)-[:IN_FILE]->(:File)
(:Finding)-[:IN_PR]->(:PR)
(:Finding)-[:SIMILAR_TO {score: float}]->(:Finding)
(:Decision)-[:MATCHES_PATTERN]->(:Pattern)
(:Pattern)-[:APPLIES_TO_ORG]->(:Org)
```

### Query Examples (Cypher)

**Find similar past decisions:**
```cypher
MATCH (f:Finding {hash: $finding_hash})
MATCH (f)-[:SIMILAR_TO]->(similar:Finding)-[:DECIDED_AS]->(d:Decision)
WHERE d.confidence > 0.8
RETURN similar, d
ORDER BY similar.similarity DESC
LIMIT 5
```

**Find patterns for a finding type:**
```cypher
MATCH (f:Finding {type: $finding_type})-[:DECIDED_AS]->(d:Decision)
WHERE d.verdict = 'false_positive'
MATCH (d)-[:MATCHES_PATTERN]->(p:Pattern)
RETURN p.name, p.confidence, COUNT(*) as occurrences
ORDER BY occurrences DESC
```

**Trace decision lineage:**
```cypher
MATCH path = (f:Finding)-[:IN_FILE]->(file:File)<-[:IN_FILE]-(related:Finding)
WHERE f.hash = $finding_hash
MATCH (related)-[:DECIDED_AS]->(d:Decision)
RETURN path, d
```

### GNN Self-Learning Flow

```
Traditional MVP (manual pattern learning):
  Decisions → Aggregate → Extract Patterns → Update Rules

RuVector (automatic):
  Decisions → GNN Layer → Index Topology Updates → Better Retrieval
                ↑                                        │
                └──────── reinforcement loop ────────────┘
```

**How the GNN improves search:**
1. New finding submitted
2. HNSW index returns initial nearest neighbors
3. GNN attention layer re-weights neighbors based on graph structure
4. Frequently successful paths get reinforced
5. Next similar query benefits from learned weights

### Comparison: MVP vs Post-MVP

| Aspect | MVP (Postgres + pgvector) | Post-MVP (RuVector) |
|--------|---------------------------|---------------------|
| **Setup Complexity** | Low (standard Postgres) | Medium (new dependency) |
| **Pattern Learning** | Manual SQL aggregation | Automatic GNN |
| **Query Language** | SQL + vector similarity | Cypher + vector |
| **Relationship Modeling** | Foreign keys | Native graph edges |
| **Latency** | ~2-5ms | ~61µs |
| **Memory (1M vectors)** | ~1-2GB | ~200MB (compressed) |
| **Self-Improvement** | Requires batch jobs | Continuous |
| **Battle-Tested** | ✅ Very | ⚠️ Newer project |

---

## Migration Path

### Phase 1 → Phase 2 Migration

```
MVP State:
├── .securevibes/ (git) ─────────────────────────┐
├── PostgreSQL                                    │
│   ├── orgs, repos, policies                    │
│   ├── patterns (manually extracted)            │
│   └── decision_index + embeddings (pgvector)   │
└─────────────────────────────────────────────────┘

Migration Steps:
1. Deploy RuVector alongside Postgres
2. Create graph schema in RuVector
3. Backfill: Import decision_index → RuVector nodes
4. Backfill: Compute SIMILAR_TO edges from embeddings
5. Dual-write: New decisions go to both
6. Shadow mode: Compare query results
7. Cutover: RuVector becomes primary
8. Deprecate: Remove pgvector queries

Post-MVP State:
├── .securevibes/ (git) ─────────── unchanged ───┐
├── PostgreSQL                                    │
│   └── orgs, repos, policies (metadata only)    │
├── RuVector                                      │
│   ├── Graph: Findings, Decisions, Patterns     │
│   ├── Vector index with GNN                    │
│   └── Self-learning enabled                    │
└─────────────────────────────────────────────────┘
```

---

## Implementation Phases

### Phase 1: Per-Repo MVP
- [ ] Implement `.securevibes/` directory structure
- [ ] Decision recording in JSONL
- [ ] Basic `known_fps.json` matching
- [ ] SQLite local index for fast queries
- [ ] CLI commands: `securevibes baseline`, `securevibes decide`

### Phase 2: Per-Org (Postgres)
- [ ] Org database schema
- [ ] Decision sync from repos to central DB
- [ ] Manual pattern extraction pipeline
- [ ] Org-wide policy management
- [ ] API endpoints for decision CRUD

### Phase 3: Semantic Search (pgvector)
- [ ] Embedding generation pipeline
- [ ] pgvector index setup
- [ ] Similar decision queries
- [ ] Recommendation engine integration

### Phase 4: Self-Learning (RuVector)
- [ ] RuVector deployment
- [ ] Graph schema implementation
- [ ] Migration scripts from Postgres
- [ ] GNN configuration and tuning
- [ ] Cypher query integration
- [ ] Deprecate manual pattern extraction

### Phase 5: Continuous Improvement
- [ ] Feedback loop (user confirms/rejects)
- [ ] Confidence score calibration
- [ ] Drift detection (stale patterns)
- [ ] Cross-org anonymized learning (opt-in)

---

## API Design

### Record Decision
```http
POST /api/v1/decisions
Content-Type: application/json

{
  "org_id": "org-123",
  "repo": "mycompany/backend",
  "pr": "42",
  "finding": { ... },
  "decision": {
    "verdict": "false_positive",
    "reasoning": "Using ORM with parameterized queries",
    "confidence": 0.9
  }
}
```

### Query Similar Decisions
```http
POST /api/v1/decisions/similar
Content-Type: application/json

{
  "org_id": "org-123",
  "finding": {
    "type": "sql_injection",
    "code_snippet": "cursor.execute(f\"SELECT ...\")",
    "file": "src/api/users.py"
  },
  "limit": 5
}

Response:
{
  "similar": [
    {
      "id": "dec-a1b2",
      "similarity": 0.94,
      "verdict": "false_positive",
      "reasoning": "ORM usage confirmed"
    }
  ],
  "patterns_matched": ["orm_usage"],
  "recommendation": {
    "verdict": "false_positive",
    "confidence": 0.89
  }
}
```

### Get Org Patterns
```http
GET /api/v1/orgs/{org_id}/patterns

Response:
{
  "patterns": [
    {
      "name": "orm_usage",
      "description": "SQL injection FPs when using ORM",
      "default_verdict": "false_positive",
      "confidence": 0.85,
      "occurrence_count": 127
    }
  ]
}
```

---

## Open Questions

1. **Embedding model** — OpenAI `text-embedding-3-small` vs open-source (e5, bge)?
2. **Privacy** — Can we share anonymized patterns across orgs?
3. **Cold start** — How to bootstrap new repos with no history?
4. **Human override** — Workflow for correcting wrong decisions?
5. **Retention** — How long to keep old decisions?
6. **RuVector maturity** — Monitor project stability before Phase 4

---

## Summary

| Phase | Storage | Tech | Effort |
|-------|---------|------|--------|
| 1 | Per-Repo | Git + JSONL + SQLite | 1-2 weeks |
| 2 | Per-Org | PostgreSQL | 2-3 weeks |
| 3 | Semantic | pgvector | 1-2 weeks |
| 4 | Self-Learning | RuVector | 3-4 weeks |
| 5 | Continuous | Feedback loops | Ongoing |

**MVP (Phases 1-3):** Proven tech, low risk, gets us learning from decisions.

**Post-MVP (Phase 4+):** RuVector's GNN eliminates manual pattern extraction, Cypher enables powerful graph queries, self-learning index improves with every decision.
