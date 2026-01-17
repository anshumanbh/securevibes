# SecureVibes Context Graph Architecture

## Problem Statement

When SecureVibes runs as a service, vulnerability triage decisions need to be:
1. **Recorded** — Why was this a TP/FP? What was the reasoning?
2. **Persisted** — Survive across PRs, sprints, team changes
3. **Retrievable** — "Have we seen this before? What did we decide?"
4. **Self-improving** — Past decisions inform future ones
5. **Hierarchical** — Per-repo context + per-org patterns
6. **Lightweight** — Can't be heavy infra for every repo

---

## Architecture Overview

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
│  │                    Context Graph                             ││
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          ││
│  │  │  Layer 1    │  │  Layer 2    │  │  Layer 3    │          ││
│  │  │  Per-Repo   │  │  Per-Org    │  │  Semantic   │          ││
│  │  │  (Git)      │  │  (DB)       │  │  (Vector)   │          ││
│  │  └─────────────┘  └─────────────┘  └─────────────┘          ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

---

## Layer 1: Per-Repo Storage (Git-Native)

### Purpose
Store repo-specific decisions that travel with the code.

### Structure
```
repo/
└── .securevibes/
    ├── config.yaml              # Repo-specific settings
    ├── baseline/
    │   ├── threat_model.json    # Baseline threat model
    │   └── known_fps.json       # Curated false positives
    ├── decisions/
    │   ├── 2026-01-17-pr-42.jsonl
    │   ├── 2026-01-16-pr-41.jsonl
    │   └── ...
    └── index.db                 # SQLite cache (gitignored)
```

### Decision Schema (JSONL)
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
    "reasoning": "Using SQLAlchemy ORM with parameterized queries. Raw SQL only used in test fixtures.",
    "evidence": [
      "src/api/users.py uses SQLAlchemy session.query()",
      "This file is test_fixtures.py, not production code"
    ]
  },
  
  "context": {
    "similar_decisions": ["dec-x1y2z3", "dec-p4q5r6"],
    "org_pattern_match": "parameterized_queries_policy",
    "reviewer": "securevibes-agent"
  },
  
  "embedding": [0.123, -0.456, ...]  // For semantic search
}
```

### Why Git-Native?
- **Versioned** — Full history, blame, bisect
- **Portable** — Repo moves, decisions move with it
- **Reviewable** — Developers can see/challenge decisions
- **Branch-aware** — Different decisions on different branches
- **No extra infra** — Just files in the repo

### Compaction Strategy
```yaml
# After 90 days, compact old decisions
compaction:
  age_days: 90
  strategy: summarize
  keep_fields: [finding.hash, decision.verdict, decision.reasoning]
  archive_to: .securevibes/archive/
```

---

## Layer 2: Per-Org Storage (Service Database)

### Purpose
Aggregate patterns across repos, store org-specific policies, enable cross-repo learning.

### Tech Options

| Option | Pros | Cons | Recommendation |
|--------|------|------|----------------|
| **SQLite** | Simple, portable, cheap | Limited concurrency | Good for < 100 repos |
| **PostgreSQL** | Scalable, rich queries, pgvector | More infra | Production service |
| **Turso (libSQL)** | SQLite + edge replication | Newer | If edge latency matters |

### Schema
```sql
-- Organizations
CREATE TABLE orgs (
  id UUID PRIMARY KEY,
  name TEXT,
  settings JSONB,
  created_at TIMESTAMP
);

-- Repositories (linked to org)
CREATE TABLE repos (
  id UUID PRIMARY KEY,
  org_id UUID REFERENCES orgs(id),
  name TEXT,
  url TEXT,
  last_scan TIMESTAMP,
  decision_count INT
);

-- Aggregated Patterns (learned from decisions)
CREATE TABLE patterns (
  id UUID PRIMARY KEY,
  org_id UUID REFERENCES orgs(id),
  name TEXT,                          -- e.g., "parameterized_queries"
  description TEXT,
  match_criteria JSONB,               -- How to detect this pattern
  default_verdict TEXT,               -- TP/FP/needs_review
  confidence FLOAT,
  occurrence_count INT,
  last_updated TIMESTAMP
);

-- Org-wide Policies
CREATE TABLE policies (
  id UUID PRIMARY KEY,
  org_id UUID REFERENCES orgs(id),
  name TEXT,
  rules JSONB,                        -- e.g., "ignore test files"
  enabled BOOLEAN
);

-- Cross-repo Decision Index (for fast lookup)
CREATE TABLE decision_index (
  id UUID PRIMARY KEY,
  org_id UUID REFERENCES orgs(id),
  repo_id UUID REFERENCES repos(id),
  finding_hash TEXT,
  finding_type TEXT,
  verdict TEXT,
  reasoning TEXT,
  embedding VECTOR(1536),             -- pgvector
  created_at TIMESTAMP
);

CREATE INDEX idx_finding_hash ON decision_index(finding_hash);
CREATE INDEX idx_finding_type ON decision_index(org_id, finding_type);
```

### Pattern Learning Pipeline
```python
# Pseudo-code for pattern extraction
def learn_patterns(org_id):
    # Get all FP decisions with high confidence
    fps = db.query("""
        SELECT finding_type, reasoning, COUNT(*) as count
        FROM decision_index
        WHERE org_id = ? AND verdict = 'false_positive' AND confidence > 0.9
        GROUP BY finding_type, reasoning
        HAVING count > 5
    """, org_id)
    
    for fp in fps:
        # Cluster similar reasonings
        clusters = cluster_by_embedding(fp.reasoning)
        
        # Extract pattern
        pattern = {
            "name": generate_pattern_name(clusters),
            "match_criteria": extract_criteria(clusters),
            "default_verdict": "false_positive",
            "confidence": calculate_confidence(clusters)
        }
        
        db.upsert_pattern(org_id, pattern)
```

---

## Layer 3: Semantic Search (Vector Embeddings)

### Purpose
Answer: "Have we seen something like this before?"

### How It Works
```
New Finding                     Similar Past Decisions
    │                                    │
    ▼                                    ▼
┌─────────┐     embed      ┌─────────────────────┐
│ Finding │───────────────▶│ Vector: [0.1, ...]  │
│ + Code  │                └──────────┬──────────┘
└─────────┘                           │
                                      │ cosine similarity
                                      ▼
                          ┌─────────────────────┐
                          │   Vector Index      │
                          │   (Chroma/pgvector) │
                          └──────────┬──────────┘
                                     │
                                     ▼
                          ┌─────────────────────┐
                          │ Top-K Similar:      │
                          │ - dec-a1b2: 0.94    │
                          │ - dec-c3d4: 0.91    │
                          │ - dec-e5f6: 0.87    │
                          └─────────────────────┘
```

### Embedding Strategy
```python
def create_embedding(finding, code_context):
    """Create embedding for semantic search."""
    
    # Combine finding info with code context
    text = f"""
    Finding Type: {finding.type}
    CWE: {finding.cwe}
    Severity: {finding.severity}
    Code Snippet:
    {code_context}
    File Path: {finding.file}
    """
    
    # Use embedding model
    embedding = openai.embeddings.create(
        model="text-embedding-3-small",
        input=text
    )
    
    return embedding.data[0].embedding
```

### Tech Options

| Option | Deployment | Pros | Cons |
|--------|------------|------|------|
| **Chroma** | Local/Embedded | Lightweight, Python-native | Limited scale |
| **pgvector** | PostgreSQL ext | Unified with main DB | Needs Postgres |
| **Qdrant** | Self-hosted | Fast, filtering | Extra service |
| **Pinecone** | Managed | Scalable, zero-ops | Cost, vendor lock |

### Recommendation
- **Small/Medium orgs**: Chroma (embedded in service)
- **Large orgs / Production**: pgvector (if using Postgres) or Qdrant

---

## Query Flow: PR Scan with Context

```
┌─────────────────────────────────────────────────────────────────┐
│                        PR #42 Scan                               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 1. Run SecureVibes scan → Findings                              │
│    [SQL Injection, XSS, Hardcoded Secret, ...]                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. For each finding, query Context Graph:                       │
│                                                                  │
│    a. Check repo baseline (Layer 1)                             │
│       → Is this a known FP in known_fps.json?                   │
│                                                                  │
│    b. Check org patterns (Layer 2)                              │
│       → Does this match a learned pattern?                      │
│       → "parameterized_queries" pattern → likely FP             │
│                                                                  │
│    c. Semantic search (Layer 3)                                 │
│       → Find similar past decisions                             │
│       → "3 similar findings marked FP with 0.92 avg confidence" │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. Decision Engine:                                             │
│                                                                  │
│    Finding: SQL Injection in src/api/users.py:42                │
│                                                                  │
│    Context:                                                      │
│    - Baseline: Not in known_fps.json                            │
│    - Org pattern: Matches "orm_usage" (85% confidence)          │
│    - Similar decisions: 3 FPs, avg confidence 0.92              │
│                                                                  │
│    Recommendation: FALSE POSITIVE (confidence: 0.89)            │
│    Reasoning: "Similar to dec-a1b2, dec-c3d4. Org uses          │
│               SQLAlchemy ORM. Raw SQL pattern is test-only."    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 4. Record decision back to Context Graph                        │
│    - Write to .securevibes/decisions/2026-01-17-pr-42.jsonl    │
│    - Update org decision_index                                  │
│    - Add to vector index                                        │
└─────────────────────────────────────────────────────────────────┘
```

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
      "reasoning": "ORM usage confirmed",
      "repo": "mycompany/api"
    },
    ...
  ],
  "patterns_matched": ["orm_usage"],
  "recommendation": {
    "verdict": "false_positive",
    "confidence": 0.89,
    "reasoning": "High similarity to 3 past FP decisions"
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
    },
    {
      "name": "test_file_findings",
      "description": "Findings in test files",
      "default_verdict": "false_positive",
      "confidence": 0.95,
      "occurrence_count": 342
    }
  ]
}
```

---

## Implementation Phases

### Phase 1: Per-Repo (MVP)
- [ ] Implement `.securevibes/` directory structure
- [ ] Decision recording in JSONL
- [ ] Basic known_fps.json matching
- [ ] SQLite local index for fast queries

### Phase 2: Per-Org
- [ ] Org database schema (Postgres)
- [ ] Decision aggregation pipeline
- [ ] Pattern learning algorithm
- [ ] API endpoints

### Phase 3: Semantic Search
- [ ] Embedding generation
- [ ] Vector index (pgvector or Chroma)
- [ ] Similar decision queries
- [ ] Recommendation engine

### Phase 4: Self-Improvement
- [ ] Feedback loop (user confirms/rejects recommendations)
- [ ] Pattern confidence updates
- [ ] Automatic policy suggestions
- [ ] Drift detection (patterns becoming stale)

---

## Open Questions

1. **Embedding model choice** — OpenAI text-embedding-3-small vs. open-source (e5, bge)?
2. **Privacy** — Can we share patterns across orgs (anonymized)?
3. **Cold start** — What to do for new repos with no history?
4. **Human override** — How do users correct wrong decisions?
5. **Retention** — How long to keep old decisions?

---

## Summary

| Layer | Storage | Purpose | Tech |
|-------|---------|---------|------|
| 1 | Per-Repo | Repo-specific decisions | Git + JSONL |
| 2 | Per-Org | Cross-repo patterns | Postgres |
| 3 | Semantic | "Have we seen this?" | pgvector/Chroma |

This architecture gives SecureVibes:
- **Memory** that persists across scans
- **Learning** that improves with each decision
- **Context** that makes recommendations smarter
- **Lightweight** per-repo, scalable per-org
