# Bayora — Product Requirements Document (PRD)

**Document Version:** 1.0.0  
**Status:** Approved / Implemented (Hackathon MVP v1.0)  
**Target Release:** Production AI Safety Infrastructure  
**Author:** Code Slayers-(Utkarsh , Udit , Syed) 

---

## 1. Executive Summary & Vision

### 1.1 Purpose
Modern artificial intelligence evaluation environments suffer from an inherent security paradox: **adversarial model testing is fundamentally untrustworthy when attack teams (Red Team), defense teams (Blue Team), and target models share execution infrastructure.** Shared file systems, shared environment credentials, co-mingled networks, unauthenticated APIs, and mutable audit logs can compromise confidential test suites, allow covert defensive overfitting, or enable silent post-evaluation evidence tampering.

**Bayora** is an end-to-end, controlled adversarial AI safety testing platform. It enforces cryptographic boundaries between opposing teams, restricts all communications through mediated control-plane gates, and records all evaluation events in an append-only, SHA-256 hash-chained audit log with Ed25519 digital signatures.

### 1.2 Mission Statement
To provide enterprises, AI research labs, and compliance auditors with an undisputable, reproducible, and mathematically verifiable platform for validating LLM guardrails against hostile jailbreak attempts without mutual trust.

---

## 2. Target Personas & User Roles

| Persona | Role Key | Permissions & Workspaces | Primary Objectives |
| :--- | :--- | :--- | :--- |
| **Red Team Operator (Adversary)** | `red_team` | Access only to `/api/workspaces/red-team/*` and Red Team attack payloads. Forbidden from viewing Blue Team policies, active guardrail rules, or tripwire secrets. | Author attack vectors (prompt injections, jailbreaks, data exfiltration), run authorized attacks, review outcome verdicts. |
| **Blue Team Defender (Safety Engineer)** | `blue_team` | Access only to `/api/workspaces/blue-team/*` and defense guardrail configurations. Forbidden from viewing unreleased Red Team attack payloads. | Author defensive policies, configure keyword/regex/semantic shields, benchmark guardrail efficacy against test runs. |
| **Lead Safety Evaluator (Operator)** | `operator` | Full control plane access. Can initiate evaluation runs, rerun identical configurations, inspect all audit logs, trigger tripwire simulations, and sign manifests. | Execute reproducible evaluation suites, analyze delta reports, verify audit hash chains, export cryptographically signed compliance packages. |
| **Auditor / Regulatory Inspector (Auditor)** | `auditor` | Read-only access to `/api/eval/runs/*`, `/api/audit/*`, and `/api/security-tests/proof-mode`. Cannot modify policies or trigger runs. | Independently verify cryptographic signatures, inspect tamper-evident audit logs, review risk disclosures, and validate benchmark compliance. |

---

## 3. High-Level System Goals & Non-Goals

### 3.1 Core Goals
* **G1: Cryptographic Multi-Tenant Isolation:** Ensure strict zero-trust boundary separation between Red Team and Blue Team workspaces at the storage, API, and network layers.
* **G2: Tamper-Evident Auditability:** Every action (evaluation start, test case outcome, canary trip, policy change) must append to a SHA-256 cryptographic hash-chain that detects modification, reordering, or deletion.
* **G3: Asymmetric Non-Repudiation:** Evaluation manifests must be signed using Ed25519 asymmetric cryptography to guarantee authenticity.
* **G4: Reproducible Benchmarking:** Support exact deterministic re-runs of evaluation suites with automated delta computation and configuration fingerprinting.
* **G5: Active Tripwire Detection:** Deploy synthetic decoy canary secrets in each workspace to immediately alarm and record unauthorized access attempts.
* **G6: Honest Proof Disclosures:** Maintain an explicit "Proof Mode" separating machine-verified automated tests from documented hardware/architectural assumptions.

### 3.2 Non-Goals (Out of Scope for MVP v1.0)
* **Universal Model Safety Certification:** Bayora does not claim an AI model is unconditionally safe; it only certifies safety against bounded, tested adversarial suites.
* **Hardware-Level Enclave Isolation:** MVP v1.0 does not implement physical Intel SGX / AMD SEV confidential computing enclaves (transparently disclosed in residual risks).
* **Physical WORM Hardware Replacement:** Local audit hash-chains guarantee tamper-evidence, but absolute immutability against root OS destruction requires external object-lock storage adapters (provided via pluggable interface).

---

## 4. Functional Requirements

### 4.1 Role-Based Access Control & Cryptographic Authentication
* **FR-1.1:** System shall support dual-mode authentication:
  - *Demo/Testing Mode:* Rapid role simulation with automatic token provisioning (`POST /api/auth/token`).
  - *Strict Production Mode (`BAYORA_STRICT_AUTH=true`):* Rejects any request lacking a valid cryptographic HMAC-SHA256 bearer token with HTTP 401 Unauthorized.
* **FR-1.2:** Unauthenticated requests shall never default to elevated privileges (`operator`).
* **FR-1.3:** Cross-tenant API requests (e.g., Blue Team reading `/api/workspaces/red-team/cases`) shall be rejected with HTTP 403 Forbidden.

### 4.2 Mediated Model Execution & Egress Filtering
* **FR-2.1:** Direct network or API calls from tenant workspaces to the model endpoint shall be strictly denied.
* **FR-2.2:** The target model endpoint shall only accept calls originating from the Evaluation Orchestrator accompanied by an internal high-entropy orchestrator secret (`X-Internal-Token`).
* **FR-2.3:** The model service shall implement output scanning to redact inadvertent canary leaks, internal orchestrator secrets, or system credentials before responding.
* **FR-2.4:** The orchestrator shall enforce an asynchronous execution timeout per test (default 3500ms) to prevent Denial of Service or hanging prompt injection payloads.

### 4.3 Canary Tripwire Engine
* **FR-3.1:** Synthetic decoy tokens (`canary-red-payload-01`, `canary-blue-policy-01`, `canary-model-endpoint-01`) shall be injected into isolated workspaces.
* **FR-3.2:** Unauthorized read probes targeting canaries shall immediately trip an alert, log the event to the audit chain with its SHA-256 fingerprint, and block the caller.
* **FR-3.3:** The system shall never expose raw canary token secrets in API responses, UI text, or audit logs.

### 4.4 Tamper-Evident Hash Chain & Merkle Checkpoints
* **FR-4.1:** Every audit entry must include: `event_id`, `timestamp`, `event_type`, `role`, `actor`, `action`, `payload_hash`, `prev_hash`, and `entry_hash`.
* **FR-4.2:** Verification endpoint (`GET /api/audit/verify`) must recompute the entire hash chain from the genesis block to verify integrity.
* **FR-4.3:** Any alteration of historical payload bytes, removal of a block, or insertion/reordering of blocks must cause verification to fail with exact block index pinpointing.
* **FR-4.4:** Support exporting Merkle root checkpoints signed with Ed25519 to external storage adapters (`LocalFileCheckpointAdapter`, expandable to S3 WORM).

### 4.5 Evaluation Orchestration, Rerun & Delta Engine
* **FR-5.1:** Allow authorized operators to execute test suites against specified defense policies (`policy-standard`, `policy-strict`, `policy-lenient`).
* **FR-5.2:** Compute a deterministic `config_fingerprint` (SHA-256 hash of sorted test IDs, policy ID, model ID, and test suite version).
* **FR-5.3:** Allow 1-click re-run of prior evaluation runs using identical configuration parameters.
* **FR-5.4:** Provide side-by-side run comparison showing latency deltas, outcome state transitions (SAFE, EXPLOITED, TIMEOUT), and reproducibility percentage.

### 4.6 Cryptographic Evidence Reporting
* **FR-5.1:** Generate tamper-evident evidence reports in Markdown and JSON formats (`GET /api/eval/runs/{id}/evidence-report`).
* **FR-5.2:** Reports must embed:
  - Run metadata, test suite version, and deterministic configuration fingerprint.
  - Audit hash-chain tip hash and verification status.
  - Asymmetric Ed25519 signature of the evaluation manifest.
  - Summary of blocked cross-boundary attempts and canary tripwire alerts.
  - Complete, unedited Residual Risks and Assumptions disclosure.

---

## 5. Non-Functional Requirements (NFRs)

### 5.1 Performance & Latency
* **NFR-1:** Control-plane API overhead shall not exceed 50ms per test invocation (excluding target model inference latency).
* **NFR-2:** Cryptographic chain verification for logs with under 5,000 entries must complete within 250ms.
* **NFR-3:** Frontend UI initial load and render must complete under 1.5 seconds on standard broadband connections.

### 5.2 Security & Integrity
* **NFR-4:** Zero credential leakage: no private keys, session signing secrets, or raw canary values shall be emitted in logs, responses, or client artifacts.
* **NFR-5:** Path traversal protection: all file system accesses must be constrained to explicit target workspace directories. Any attempt containing `..`, absolute paths, or control characters must be rejected with HTTP 400.
* **NFR-6:** Strict CORS origin validation: Credentialed cross-origin browser requests must be restricted to explicitly whitelisted origin URLs (`BAYORA_CORS_ORIGINS`).

### 5.3 Reliability & Availability
* **NFR-7:** The audit log must use write-ahead synchronous flushing to disk to prevent event loss during sudden process termination.
* **NFR-8:** In-flight evaluation timeouts must be isolated so that a single hung model inference does not crash or stall the orchestrator.

---

## 6. Verification & Acceptance Criteria

1. **Automated Test Suite:** 100% pass rate across the comprehensive Pytest test suite covering:
   - Tenant boundary isolation (SEC-01 to SEC-04).
   - Tamper detection on payload edit, event deletion, and event reordering (SEC-05, SEC-09).
   - Canary tripwire alerts and fingerprint validation (SEC-08).
   - Ed25519 signature validity and non-repudiation.
   - Cross-Origin Resource Sharing (CORS) allowlists and strict bearer authentication.
2. **Deterministic Reproducibility:** 100% outcome reproducibility when running re-evaluations against identical configuration fingerprints.
3. **Audit Chain Soundness:** Independent verification script must reliably flag intentionally introduced tampering in the audit chain.
