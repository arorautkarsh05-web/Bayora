# Bayora — Security Measures & Defense-in-Depth Architecture

**Document Version:** 1.0.0  
**Status:** Implemented & Machine-Verified  
**Target Release:** Production AI Safety Infrastructure  
**Author:** Code Slayers — (Utkarsh, Udit, Syed)  

---

## 1. Executive Security Overview

In adversarial artificial intelligence evaluations, security is not an afterthought—it is the foundational prerequisite for scientific validity. If an attacker can inspect defensive tripwires, if a defender can overfit rules to unreleased attack vectors, or if an administrator can silently alter audit records, the evaluation results become meaningless.

**Bayora** implements a multi-layered **Defense-in-Depth (DiD)** architecture engineered to withstand hostile, untrusted participants operating within the same testing platform.

```mermaid
graph TD
    subgraph Layer 1: Network & Boundary Security
        CORS[Strict CORS Origin Filtering]
        NetSeg[Docker Micro-Segmented Networks]
        PathJail[Strict Path Traversal Jails]
    end

    subgraph Layer 2: Cryptographic Identity & Access
        AuthToken[HMAC-SHA256 Bearer Authentication]
        StrictAuth[BAYORA_STRICT_AUTH Enforcement]
        RBAC[Zero-Default Role-Based Access Control]
        Quota[Fair-Share Concurrency Quotas]
    end

    subgraph Layer 3: Model Egress & Execution Gate
        TokenGate[Orchestrator Internal Token Gate]
        EgressScanner[Output Canary & Credential Redaction]
        TimeoutSuper[Async Execution Timeout Supervisor]
        SessionWipe[Ephemeral Session & Cache Wiping]
    end

    subgraph Layer 4: Audit & Cryptographic Proof
        HashChain[Append-Only SHA-256 Hash Chain]
        Ed25519Sig[Ed25519 Asymmetric Manifest Signatures]
        CanaryTrips[Synthetic Decoy Canary Tripwires]
        MerkleCheck[Pluggable External Merkle Checkpoints]
    end

    Layer 1 --> Layer 2 --> Layer 3 --> Layer 4
```

---

## 2. Authentication & Authorization Security Controls

### 2.1 Cryptographic Bearer Token Architecture
* **Algorithm:** HMAC-SHA256 stateless session tokens issued via `POST /api/auth/token`.
* **Token Structure:** Contains `user_id`, cryptographically bound `role`, issue timestamp `iat`, and expiration timestamp `exp`.
* **Zero Shared Passwords:** Eliminates static passwords and database lookups, preventing database injection and credential stuffing vulnerabilities.

### 2.2 Dual-Mode Operation (`BAYORA_STRICT_AUTH`)
* **Strict Production Mode (`BAYORA_STRICT_AUTH=true`):**
  - Requires a valid `Authorization: Bearer <token>` on all protected endpoints.
  - Any request with a missing, malformed, expired, or tampered token returns **HTTP 401 Unauthorized**.
  - Simulation headers (`X-Bayora-Role`) are completely disabled and rejected.
* **Controlled Demo / Testing Mode (`BAYORA_STRICT_AUTH=false`):**
  - Permits test suites and quick evaluations via auto-generated tokens.
  - **Critical Rule:** Unauthenticated requests *never* default to elevated privileges (`operator`); missing credentials return **HTTP 401**.

### 2.3 Strict Role-Based Access Control (RBAC)

| Role | Permitted Routes & Workspaces | Prohibited Routes & Access |
| :--- | :--- | :--- |
| **`red_team`** | Red-team attack vectors, payload uploads, own run history. | **Forbidden:** Blue-team policies (403), active guardrail rules (403), internal model gate (403). |
| **`blue_team`** | Defensive policies, guardrails, regex rules, benchmark scores. | **Forbidden:** Red-team unreleased payloads (403), red-team canary secrets (403), internal model gate (403). |
| **`operator`** | Evaluation execution, rerun engine, audit verification, manifest signing. | Supervised orchestration of test lifecycle. |
| **`auditor`** | Read-only inspection of audit logs, proof matrix, and evidence reports. | **Forbidden:** Modifying policies, uploading attack payloads, triggering runs. |

---

## 3. Workload & Tenant Boundary Isolation

### 3.1 Strict Storage Namespacing & Path Traversal Prevention
* **Isolated Namespaces:** Red Team assets (`/backend/data/red_team/`) and Blue Team assets (`/backend/data/blue_team/`) are physically segregated on disk.
* **Path Traversal Jails:** All file access utility methods resolve and canonicalize paths using Python's `pathlib.Path`:
  ```python
  resolved_path = (target_directory / filename).resolve()
  if not resolved_path.is_relative_to(target_directory.resolve()):
      raise HTTPException(status_code=400, detail="Path traversal attempt detected")
  ```
  Any attempt using relative directory climbing (`../../etc/passwd` or `..\`) is halted with **HTTP 400 Bad Request**.

### 3.2 Mediated Internal Model Token Gate
* Direct access from tenant workstations or external networks to `/internal/model/*` is blocked.
* The model endpoint mandates the header `X-Internal-Token` matching a 256-bit dynamic secret (`ORCHESTRATOR_INTERNAL_SECRET`) generated at server initialization.
* Any unauthorized request attempting direct inference returns **HTTP 403 Forbidden**.

### 3.3 Micro-Segmented Container Networking
The accompanying `docker-compose.yml` provisions 4 isolated bridge networks:
1. `red_team_net` — Restricted to Red Team client containers and the API Gateway.
2. `blue_team_net` — Restricted to Blue Team client containers and the API Gateway.
3. `control_plane_net` — Orchestrator, signing authority, and audit engine.
4. `model_isolated_net` — Dedicated strictly to the model inference container; no IP routing from `red_team_net` or `blue_team_net`.

---

## 4. Active Intrusion & Probing Detection (Canary Tripwires)

### 4.1 Synthetic Decoy Secrets
Bayora deploys synthetic decoy secrets into segregated environments:
* `canary-red-payload-01` placed in `/backend/data/red_team/`
* `canary-blue-policy-01` placed in `/backend/data/blue_team/`
* `canary-model-endpoint-01` placed in `/backend/data/model/`

### 4.2 Probing Detection & Zero Secret Leakage
* If an unauthorized actor attempts to read, download, or query an opposing team's canary file:
  1. The attempt is immediately intercepted and blocked with **HTTP 403 Forbidden**.
  2. The tripwire transitions to `🚨 TRIPPED`.
  3. A tamper-evident security alert event is committed to the append-only audit chain.
* **Cryptographic Privacy:** The system records only the **SHA-256 fingerprint** of the canary in audit logs and API responses. The raw decoy secret is never revealed, preventing the detection system from becoming an information leakage vector.

---

## 5. Audit Trail Integrity & Cryptographic Non-Repudiation

### 5.1 Append-Only SHA-256 Hash Chain
Every evaluation lifecycle event (test start, test completion, canary trip, policy update) is appended to `audit_chain.jsonl`.
* Each entry computes:
  $$\text{entry\_hash} = \text{SHA-256}(\text{prev\_hash} \parallel \text{payload\_hash} \parallel \text{timestamp} \parallel \text{event\_type} \parallel \text{actor})$$
* **Mathematical Proof of Non-Tampering:**
  - If any prior record's bytes are edited $\rightarrow$ `payload_hash` breaks, invalidating all subsequent `prev_hash` pointers.
  - If a record is deleted $\rightarrow$ the hash link sequence breaks immediately.
  - If records are swapped or reordered $\rightarrow$ the hash continuity breaks.
* The verification engine (`GET /api/audit/verify`) traverses the entire ledger from Genesis Block (Index 0) to Tip, validating every hash in under 200 milliseconds.

### 5.2 Asymmetric Ed25519 Manifest Signing
* Every completed evaluation run produces an immutable run manifest containing:
  - Unique `run_id` and test timestamps.
  - SHA-256 `config_fingerprint` of model, policy, and test-case suite.
  - Outcome tallies (Safe, Exploited, Timeout).
  - Audit tip hash.
* The manifest is digitally signed using an asymmetric **Ed25519 private key** (`crypto.py`).
* Anyone (clients, auditors, external regulators) can verify the manifest's authenticity and non-repudiation against the public key (`GET /api/crypto/public-key`).

### 5.3 Pluggable Merkle Checkpoint Ledger (`CheckpointStorageAdapter`)
To defend against hostile root administrators rewriting local disk files, Bayora introduces external checkpointing:
* Periodically takes the cryptographic tip of the hash chain, builds a Merkle root, signs it with Ed25519, and pushes it out-of-band.
* Implements `LocalFileCheckpointAdapter` with pluggable extension hooks for **AWS S3 Object Lock** and **Azure Blob Immutable WORM** storage.

---

## 6. Model Egress Leakage & Resource Governance

### 6.1 Egress Data Redaction Scanner
The model inference layer incorporates output scanning (`_scan_and_sanitize_output()`) to protect against jailbreaks designed to exfiltrate system secrets:
* Scans all generated tokens for canary strings, internal secrets, API keys, or private key blocks before the output leaves the model boundary.
* Intercepted leaks are replaced with `[REDACTED_LEAK_PREVENTION]` and flagged in the evaluation report.

### 6.2 Ephemeral Session & Memory Cache Wiping
* LLMs can retain adversarial prompt fragments in internal KV caches or conversation contexts.
* Between evaluation runs, the orchestrator invokes `reset_session_context()`, wiping scratchpads and in-memory caches to prevent cross-test contamination.

### 6.3 Fair-Share Token-Bucket Rate Limiting & Concurrency Quotas
* Managed via `QuotaManager` in `backend/app/auth.py`.
* Each role is allocated a dedicated execution quota bucket (e.g., maximum 5 concurrent evaluations per tenant).
* Prevents a hostile or runaway tenant from exhausting GPU/CPU compute resources and causing Denial of Service (DoS) for other teams.

### 6.4 Asynchronous Execution Timeout Supervisor
* Adversarial prompts often attempt algorithmic denial of service (e.g., recursive reasoning loops or prompt expansion attacks).
* The orchestrator supervises all test executions with an asynchronous timeout (default 3.5 seconds).
* Workloads exceeding the threshold are forcefully terminated with verdict `TIMEOUT_TERMINATED`, releasing worker threads immediately.

---

## 7. Web Application & Network Security Controls

### 7.1 Cross-Origin Resource Sharing (CORS) Security
* Permitted web origins are explicitly restricted via `BAYORA_CORS_ORIGINS`.
* Default allowed origins: `http://127.0.0.1:8000`, `http://localhost:8000`, `http://127.0.0.1:3000`, `http://localhost:3000`.
* Wildcard origins (`*`) are disallowed for credentialed authentication endpoints.

### 7.2 Rootless Hardened OCI Container (`Dockerfile`)
* **Unprivileged User:** Executes as dedicated UID `10001` (`appuser`).
* **Dropped Capabilities:** Enforces `CAP_DROP ALL` to strip root privileges inside the container.
* **Read-Only Rootfs Compatible:** Ephemeral data is restricted to volume-mounted storage namespaces.

### 7.3 Frontend Attack Surface Minimization
* **Zero External Dependencies:** Built with native Vanilla ES6 JavaScript and Vanilla CSS3.
* **No npm Supply Chain Risk:** Eliminates vulnerable third-party JavaScript libraries, prototype pollution, and malicious upstream packages.
* **Content Injection Defense:** Output strings are sanitized using `textContent` and safe DOM manipulation, preventing Cross-Site Scripting (XSS).

---

## 8. Proof Mode: Tested Controls vs. Documented Assumptions

Bayora maintains an explicit, transparent distinction between what is **proven by automated software tests** and what is an **architectural assumption**:

### Section A: Tested Mechanisms (Machine-Verified via Pytest)
1. **CTRL-01:** Red Team storage isolation (HTTP 403 on cross-access).
2. **CTRL-02:** Blue Team policy isolation (HTTP 403 on cross-access).
3. **CTRL-03:** Path traversal jail enforcement (HTTP 400 on `../` traversal).
4. **CTRL-04:** Model interface token gate (HTTP 403 on unmediated access).
5. **CTRL-05:** Audit hash-chain tamper detection (Detects edit, delete, reorder).
6. **CTRL-06:** Ed25519 digital signature authenticity and non-repudiation.
7. **CTRL-07:** Async execution timeout supervisor (Forceful termination at 3.5s).
8. **CTRL-08:** Canary secret probing alert and fingerprint commitment.
9. **CTRL-14:** Cryptographic HMAC bearer token role verification.
10. **CTRL-15:** External Merkle checkpoint ledger export.
11. **CTRL-16:** Model output canary/credential egress redaction.
12. **CTRL-17:** Concurrency quotas and fair-share rate limiting.

### Section B: Documented Hardening Specs & Residual Risks
1. **CTRL-09 (Kernel Container Boundary):** Standard Linux containers share the host kernel. Hardware microarchitectural timing and cache-probing side-channels are not eliminated by Linux containers alone; untrusted hostile production workloads should be isolated via hypervisor microVMs (Kata / Firecracker).
2. **CTRL-10 (Physical Immobility vs Tamper-Evidence):** Local append-only logs are tamper-evident, but physical destruction by a compromised host root administrator requires external S3/WORM object lock mirroring.
3. **CTRL-11 (Bounded Safety Scope):** Passing test suite `2026.10-v1.0` certifies defense against evaluated vectors, but cannot prove universal safety against novel, unknown zero-day jailbreaks.

---

## 9. Automated Security Test Verification

The entire security architecture is continuously verified using an automated Pytest suite:
```powershell
# Run the complete security test suite
pytest -v
```

**Results:** **43 Passed, 0 Failed, 0 Warnings** across all 8 security test modules:
* `test_auth_roles.py` — Verifies RBAC, missing tokens (401), and elevation blocks.
* `test_boundary_enforcement.py` — Verifies cross-tenant 403 rejections and path jails.
* `test_audit_integrity.py` — Tests synthetic tamper attacks (modifications, deletions, reordering).
* `test_canaries.py` — Verifies tripwire alarms, canary state changes, and secret concealment.
* `test_cors_and_strict_auth.py` — Verifies CORS headers and strict bearer token mode.
* `test_eval_orchestrator.py` — Verifies deterministic rerun fingerprints and timeout termination.
