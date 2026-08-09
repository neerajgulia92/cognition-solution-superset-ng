# Architecture

High-level architectural decisions for the Superset-NG security remediation pipeline. For a detailed walkthrough of the solution, see the README.

## Key Architectural Decisions

### 1. GitHub Issues as State Store

**Problem**: Need to track pipeline state across runs without database infrastructure.

**Constraints**: 
- Minimal infrastructure overhead
- Natural audit trail
- Container restart resilience
- Human-readable state

**Decision**: Store all state as hidden HTML comments and labels on GitHub issues.

**Trade-offs**:
- Pros: No database to provision/maintain, every state change visible in issue timeline, container restarts don't lose state
- Cons: API rate limits on reads, slower than database queries

**Why this decision**: GitHub is already the system of record for findings and fixes. Using it as state store eliminates infrastructure complexity while providing full observability.

**Outcomes**: 
- Any run can resume where the last left off
- Engineers can debug by reading issues directly
- Zero data migration overhead

**Success metrics**:
- No data loss across container restarts
- All state changes visible in GitHub UI
- Average state read time < 2 seconds

---

### 2. Verification-First Security Model

**Problem**: Merged PRs don't guarantee vulnerabilities are actually fixed.

**Constraints**:
- Catch failed fixes that passed review
- Prevent false positive closures
- Maintain security integrity

**Decision**: Only re-scanning (not merging) can close issues as fixed.

**Trade-offs**:
- Pros: Catches failed fixes, prevents closure on stale evidence, strong security guarantees
- Cons: Slower closure loop, requires additional scan cycle

**Why this decision**: A reviewer might approve a PR that looks correct but doesn't fix the vulnerability. Only a fresh scan can prove the finding is gone.

**Outcomes**:
- Failed fixes detected and reopened
- No issues closed on stale evidence
- Security integrity maintained

**Success metrics**:
- Failed fix detection rate > 95%
- Zero false positive closures
- Average verification time < 1 hour

---

### 3. Stateless, Idempotent Stages

**Problem**: Need error recovery and safe re-execution across GitHub Actions workflows.

**Constraints**:
- GitHub Actions workflow isolation
- Independent stage execution
- Safe re-run capability
- No shared state between workflows

**Decision**: Each stage is self-contained, checks for existing work, and can run independently.

**Trade-offs**:
- Pros: Error recovery via re-run, independent stage execution, testable in isolation
- Cons: Sequential execution limits speed, duplicate work checks add overhead

**Why this decision**: GitHub Actions runs stages as separate workflows without shared state. Idempotency enables reliable error recovery.

**Outcomes**:
- Failed stages can be re-run without cleanup
- Stages can be tested independently
- Complex workflow orchestration not needed

**Success metrics**:
- Re-run success rate > 99%
- Stage execution time < 5 minutes
- Zero manual cleanup required

---

### 4. Zero External Dependencies

**Problem**: GitHub Actions startup time and dependency conflicts.

**Constraints**:
- Fast workflow startup
- No dependency conflicts
- Python 3.10+ compatibility
- GitHub Actions runner environment

**Decision**: Use only Python standard library in pipeline scripts.

**Trade-offs**:
- Pros: No pip install step, no dependency conflicts, faster workflow startup
- Cons: More verbose code, limited HTTP/client features

**Why this decision**: Dependencies slow down workflow startup and introduce version drift. Standard library is sufficient for HTTP requests and JSON handling.

**Outcomes**:
- Workflow startup time < 10 seconds
- Zero dependency-related failures
- Code runs on any Python 3.10+ environment

**Success metrics**:
- Workflow startup time < 15 seconds
- Zero dependency-related incidents
- 100% standard library usage

---

### 5. Structured Output Schema for Devin Sessions

**Problem**: Unpredictable session responses make parsing unreliable.

**Constraints**:
- Predictable session outcomes
- Type-safe response handling
- Consistent metrics data
- Controlled session behavior

**Decision**: Configure Devin sessions with strict JSON schema forcing specific verdict types.

**Trade-offs**:
- Pros: Predictable response parsing, controlled behavior, type-safe data
- Cons: Less flexible session responses, schema maintenance overhead

**Why this decision**: Structured output ensures the poller can reliably extract session outcomes and enables consistent metrics collection.

**Outcomes**:
- Parse success rate > 99%
- Consistent verdict categories
- Reliable metrics data

**Success metrics**:
- Parse failure rate < 1%
- Verdict distribution matches expected categories
- Zero unparseable responses

---

### 6. Multi-Source Finding Aggregation

**Problem**: Different security tools catch different vulnerability classes.

**Constraints**:
- Comprehensive vulnerability coverage
- Unified processing pipeline
- Deduplication across sources
- Extensible to new scanners

**Decision**: Normalize findings from OSV, npm audit, and bandit into unified format with stable fingerprints.

**Trade-offs**:
- Pros: Comprehensive coverage, source-agnostic processing, easy to add new scanners
- Cons: Normalization complexity, potential data loss in conversion

**Why this decision**: Different tools (dependency scanners, code analyzers) catch different vulnerability types. A unified format simplifies downstream processing.

**Outcomes**:
- Findings from 3+ sources processed uniformly
- Fingerprint-based deduplication prevents duplicates
- New scanners added via normalizer functions

**Success metrics**:
- Duplicate finding rate < 1%
- New scanner integration time < 1 day
- Finding coverage across dependency + code vulnerabilities

---

### 7. Event-Driven Multi-Trigger Architecture

**Problem**: Different teams need different ways to trigger the pipeline.

**Constraints**:
- Flexible trigger mechanisms
- Manual override capability
- Repository activity responsiveness
- Scheduled health checks

**Decision**: Support cron schedules, manual API calls, webhooks, and repository activity triggers.

**Trade-offs**:
- Pros: Maximum flexibility, responsive to changes, manual control
- Cons: More complex trigger logic, potential duplicate runs

**Why this decision**: Different teams and use cases require different trigger mechanisms. Multiple triggers provide maximum flexibility without forcing a single approach.

**Outcomes**:
- 4+ trigger mechanisms available
- Repository activity automatically triggers verification
- Manual testing via control panel

**Success metrics**:
- Trigger mechanism availability > 95%
- Response time to repository activity < 5 minutes
- Zero duplicate runs in production

---

### 8. Issue-Derived Observability

**Problem**: Separate analytics systems can drift from actual state.

**Constraints**:
- Single source of truth
- Auditable metrics
- No data synchronization
- Traceable numbers

**Decision**: Derive all metrics from visible GitHub issue state rather than separate database.

**Trade-offs**:
- Pros: Metrics always match visible state, every metric traceable to issue, no data drift
- Cons: Slower metric calculation, API rate limit concerns

**Why this decision**: A separate analytics system could drift from actual state. Deriving metrics from issues ensures accuracy and auditability.

**Outcomes**:
- Every metric traceable to specific issue/comment
- Zero data drift between metrics and reality
- Dashboard accuracy verifiable by reading issues

**Success metrics**:
- Metric accuracy rate > 99%
- All metrics traceable to source
- Dashboard refresh time < 30 seconds

---

### 9. Control Plane Orchestration

**Problem**: Need local development alternative to GitHub Actions workflows.

**Constraints**:
- Local development capability
- Unified API interface
- Real-time status visibility
- Scheduling capability

**Decision**: FastAPI service orchestrates stages, provides API, control panel, and scheduling.

**Trade-offs**:
- Pros: Local development support, unified API interface, real-time status dashboard
- Cons: Additional service to maintain, in-memory state lost on restart

**Why this decision**: GitHub Actions is great for production but doesn't support local development. A control plane enables local testing and alternative deployment models.

**Outcomes**:
- Local development without GitHub Actions
- Single API endpoint for all triggers
- Real-time run status visibility

**Success metrics**:
- Local development setup time < 5 minutes
- API response time < 100ms
- Dashboard refresh time < 3 seconds

---

### 10. Docker Compose Deployment

**Problem**: Balance simplicity with production-ready deployment.

**Constraints**:
- Simple deployment
- Cross-platform compatibility
- Production-ready monitoring
- Minimal operational overhead

**Decision**: Two-service Docker Compose stack (control + Grafana).

**Trade-offs**:
- Pros: Simple deployment, cross-platform compatible, production-ready monitoring
- Cons: Single-tenant only, limited scalability

**Why this decision**: Kubernetes is overkill for single-tenant deployments. Docker Compose provides simplicity while supporting production needs.

**Outcomes**:
- Deployment time < 5 minutes
- Runs on any Docker host
- Built-in Grafana monitoring

**Success metrics**:
- Deployment success rate > 99%
- Setup time < 10 minutes
- Zero platform-specific issues

---

## High-Level System Design

```
┌─────────────────────────────────────────────────────────────────┐
│                     Control Plane (FastAPI)                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐ │
│  │Scheduler │  │   API    │  │  Panel   │  │   Metrics Export │ │
│  └──────────┘  └──────────┘  └──────────┘  └──────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Pipeline Stages                             │
│  ┌──────┐ ┌──────┐ ┌──────────┐ ┌──────┐ ┌──────┐ ┌────────┐  │
│  │ Scan │→│ Sync │→│ Dispatch │→│ Poll │→│ Merge│→│ Verify │  │
│  └──────┘ └──────┘ └──────────┘ └──────┘ └──────┘ └────────┘  │
│                                                              │   │
│                                                              ▼   │
│                                                         ┌────────┐│
│                                                         │ Metrics ││
│                                                         └────────┘│
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      External Systems                            │
│  ┌──────────────────┐  ┌──────────┐  ┌────────────────────────┐ │
│  │   GitHub         │  │ Devin API│  │      Grafana            │ │
│  │  (Issues + PRs)  │  │          │  │   (Dashboard)           │ │
│  └──────────────────┘  └──────────┘  └────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## Data Flow

**Finding Lifecycle**: Scan -> Normalize -> File Issue -> Queue -> Dispatch Session -> Poll -> Merge -> Verify -> Close

**Metric Derivation**: GitHub Issues -> Parse Labels/Comments/Events -> Reconstruct Journey -> Calculate Metrics -> Dashboard

## Summary

The architecture prioritizes reliability and observability over raw performance. Key principles:

- GitHub as single source of truth for state and metrics
- Verification-first security requiring re-scans to prove fixes
- Idempotent, stateless stages for error recovery
- Zero dependencies for fast, reliable execution
- Event-driven triggers for maximum flexibility

Trade-offs accept slower performance and higher API usage in exchange for simplicity, reliability, and auditability.