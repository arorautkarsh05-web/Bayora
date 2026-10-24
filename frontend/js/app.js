// Bayora Reviewer & Operator Dashboard Controller
const state = {
  activeRole: 'operator',
  activeUser: 'evaluator-operator-1',
  bearerToken: '',
  publicKeyFingerprint: '',
  runs: [],
  activeRun: null,
  auditEvents: [],
  testCases: [],
  policies: [],
};

// Helper: Fetch and cache cryptographic Bearer token for active role
async function ensureAuthToken() {
  try {
    const res = await fetch('/api/auth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_id: state.activeUser, role: state.activeRole, expires_in_seconds: 7200 }),
    });
    if (res.ok) {
      const data = await res.json();
      state.bearerToken = data.access_token;
    }
  } catch (err) {
    console.warn('Bearer token fetch error:', err);
  }
}

// Helper: API Fetch wrapper with cryptographic Bearer and fallback role headers
async function apiRequest(endpoint, options = {}) {
  if (!state.bearerToken && endpoint !== '/api/auth/token') {
    await ensureAuthToken();
  }

  const headers = {
    'Content-Type': 'application/json',
    ...(state.bearerToken ? { 'Authorization': `Bearer ${state.bearerToken}` } : {}),
    'X-Bayora-Role': state.activeRole,
    'X-Bayora-User': state.activeUser,
    ...(options.headers || {}),
  };

  const res = await fetch(endpoint, { ...options, headers });
  if (!res.ok) {
    let errorDetail = res.statusText;
    try {
      const errJson = await res.json();
      errorDetail = errJson.detail || errorDetail;
    } catch (e) {}
    throw new Error(errorDetail);
  }
  return res.json();
}

// ----------------- Initialization -----------------
document.addEventListener('DOMContentLoaded', () => {
  setupTabs();
  setupRoleSelector();
  setupModals();
  setupActionButtons();

  loadInitialData();
});

function setupTabs() {
  const tabs = document.querySelectorAll('.nav-tab-btn');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');

      const targetPaneId = tab.dataset.tab;
      document.querySelectorAll('.tab-pane').forEach(p => (p.style.display = 'none'));
      const activePane = document.getElementById(targetPaneId);
      if (activePane) activePane.style.display = 'block';

      // Refresh view-specific data
      if (targetPaneId === 'tab-proof-mode') loadProofModeMatrix();
      if (targetPaneId === 'tab-red-team') loadRedTeamWorkspace();
      if (targetPaneId === 'tab-blue-team') loadBlueTeamWorkspace();
      if (targetPaneId === 'tab-audit') loadAuditTrail();
      if (targetPaneId === 'tab-boundaries') {
        runSecurityBoundaryTests();
        loadCanaries();
      }
    });
  });
}

function setupRoleSelector() {
  const selector = document.getElementById('role-selector');
  const dropdown = document.getElementById('role-dropdown');
  const trigger = document.getElementById('role-dropdown-trigger');
  const menu = document.getElementById('role-dropdown-menu');
  const selectedText = document.getElementById('role-selected-text');
  const triggerDot = trigger ? trigger.querySelector('.role-indicator') : null;
  const items = menu ? menu.querySelectorAll('.dropdown-item') : [];

  const roleMeta = {
    operator: { name: 'Operator (Evaluator)', dotClass: 'role-indicator-operator' },
    red_team: { name: 'Red Team Participant', dotClass: 'role-indicator-red' },
    blue_team: { name: 'Blue Team Participant', dotClass: 'role-indicator-blue' },
    reviewer: { name: 'Reviewer (Auditor)', dotClass: 'role-indicator-reviewer' }
  };

  function updateCustomDropdownUI(role) {
    const meta = roleMeta[role] || { name: role, dotClass: 'role-indicator-operator' };
    if (selectedText) selectedText.textContent = meta.name;
    if (triggerDot) {
      triggerDot.className = `role-indicator ${meta.dotClass}`;
    }
    items.forEach(item => {
      if (item.getAttribute('data-value') === role) {
        item.classList.add('selected');
      } else {
        item.classList.remove('selected');
      }
    });
  }

  if (trigger && menu) {
    trigger.addEventListener('click', e => {
      e.stopPropagation();
      const isOpen = menu.classList.toggle('show');
      trigger.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
    });

    items.forEach(item => {
      item.addEventListener('click', e => {
        e.stopPropagation();
        const value = item.getAttribute('data-value');
        menu.classList.remove('show');
        trigger.setAttribute('aria-expanded', 'false');

        if (selector) {
          selector.value = value;
          updateCustomDropdownUI(value);
          selector.dispatchEvent(new Event('change'));
        }
      });

      item.addEventListener('keydown', e => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          item.click();
        }
      });
    });

    // Close when clicking outside
    document.addEventListener('click', e => {
      if (dropdown && !dropdown.contains(e.target)) {
        menu.classList.remove('show');
        trigger.setAttribute('aria-expanded', 'false');
      }
    });

    // Close on Escape key
    document.addEventListener('keydown', e => {
      if (e.key === 'Escape' && menu.classList.contains('show')) {
        menu.classList.remove('show');
        trigger.setAttribute('aria-expanded', 'false');
        trigger.focus();
      }
    });
  }

  if (selector) {
    selector.addEventListener('change', async e => {
      state.activeRole = e.target.value;
      state.activeUser = `user-${state.activeRole}`;
      state.bearerToken = '';
      updateCustomDropdownUI(state.activeRole);
      await ensureAuthToken();
      applyRolePermissions();
      // Refresh current active tab
      const activeTab = document.querySelector('.nav-tab-btn.active');
      if (activeTab) activeTab.click();
    });

    // Initial sync
    updateCustomDropdownUI(selector.value || 'operator');
  }
}

function applyRolePermissions() {
  const role = state.activeRole;

  // Evaluation button visibility
  const newRunBtn = document.getElementById('btn-open-run-modal');
  if (role === 'reviewer' || role === 'red_team' || role === 'blue_team') {
    newRunBtn.style.opacity = '0.5';
    newRunBtn.title = `Role '${role}' cannot initiate runs. Switch to Operator.`;
  } else {
    newRunBtn.style.opacity = '1';
    newRunBtn.title = 'Create new evaluation run';
  }

  // Red Team Workspace Boundary Enforcement (PR-2)
  const redContent = document.getElementById('red-team-content');
  const redBarrier = document.getElementById('red-team-barrier');
  if (role === 'blue_team') {
    if (redContent) redContent.style.display = 'none';
    if (redBarrier) redBarrier.style.display = 'flex';
  } else {
    if (redContent) redContent.style.display = 'block';
    if (redBarrier) redBarrier.style.display = 'none';
  }

  // Blue Team Workspace Boundary Enforcement (PR-2)
  const blueContent = document.getElementById('blue-team-content');
  const blueBarrier = document.getElementById('blue-team-barrier');
  if (role === 'red_team') {
    if (blueContent) blueContent.style.display = 'none';
    if (blueBarrier) blueBarrier.style.display = 'flex';
  } else {
    if (blueContent) blueContent.style.display = 'block';
    if (blueBarrier) blueBarrier.style.display = 'none';
  }
}

function setupModals() {
  // Close buttons
  document.querySelectorAll('.modal-close-btn, .modal-cancel-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.modal-overlay').forEach(m => m.classList.remove('open'));
    });
  });

  // Open Run Modal
  const openRunBtn = document.getElementById('btn-open-run-modal');
  openRunBtn.addEventListener('click', () => {
    if (state.activeRole !== 'operator') {
      alert(`Role '${state.activeRole}' is not authorized to create evaluation runs. Please switch to 'Operator' in the top header.`);
      return;
    }
    document.getElementById('modal-new-run').classList.add('open');
  });

  // Open Add Payload Modal
  const addPayloadBtn = document.getElementById('btn-add-test-case');
  if (addPayloadBtn) {
    addPayloadBtn.addEventListener('click', () => {
      if (state.activeRole !== 'red_team' && state.activeRole !== 'operator') {
        alert('Only Red Team or Operator can submit adversarial payloads.');
        return;
      }
      document.getElementById('modal-add-payload').classList.add('open');
    });
  }

  // Open Add Defensive Policy Modal (Blue Team)
  const addPolicyBtn = document.getElementById('btn-add-policy');
  if (addPolicyBtn) {
    addPolicyBtn.addEventListener('click', () => {
      if (state.activeRole !== 'blue_team' && state.activeRole !== 'operator') {
        alert('Only Blue Team or Operator can create defensive policies.');
        return;
      }
      document.getElementById('modal-add-policy').classList.add('open');
    });
  }

  // Submit Run Form
  const runForm = document.getElementById('form-create-run');
  runForm.addEventListener('submit', async e => {
    e.preventDefault();
    const name = document.getElementById('run-name-input').value;
    const model_id = document.getElementById('run-model-select').value;
    const policy_id = document.getElementById('run-policy-select').value || null;
    const timeout_seconds = parseFloat(document.getElementById('run-timeout-input').value) || 5.0;
    const trigger_timeout_test = document.getElementById('run-trigger-timeout').checked;

    document.getElementById('modal-new-run').classList.remove('open');

    try {
      showLoadingNotification('Starting secure evaluation run...');
      const run = await apiRequest('/api/eval/runs', {
        method: 'POST',
        body: JSON.stringify({
          name,
          model_id,
          policy_id,
          timeout_seconds,
          simulated_delay: 0.08,
          trigger_timeout_test,
        }),
      });
      state.activeRun = run;
      renderActiveRun(run);
      loadRunsHistory();
      loadAuditTrail();
    } catch (err) {
      alert(`Failed to start evaluation: ${err.message}`);
    }
  });

  // Submit Payload Form
  const payloadForm = document.getElementById('form-create-payload');
  if (payloadForm) {
    payloadForm.addEventListener('submit', async e => {
      e.preventDefault();
      const id = document.getElementById('payload-id-input').value.trim();
      const name = document.getElementById('payload-name-input').value.trim();
      const category = document.getElementById('payload-category-select').value;
      const severity = document.getElementById('payload-severity-select').value;
      const prompt = document.getElementById('payload-prompt-textarea').value.trim();

      document.getElementById('modal-add-payload').classList.remove('open');

      try {
        await apiRequest('/api/red-team/test-cases', {
          method: 'POST',
          body: JSON.stringify({ id, name, category, severity, prompt }),
        });
        alert(`Payload '${id}' securely saved to Red Team workspace.`);
        loadRedTeamWorkspace();
      } catch (err) {
        alert(`Submission failed: ${err.message}`);
      }
    });
  }

  // Submit Policy Form (Blue Team)
  const policyForm = document.getElementById('form-create-policy');
  if (policyForm) {
    policyForm.addEventListener('submit', async e => {
      e.preventDefault();
      const id = document.getElementById('policy-id-input').value.trim();
      const name = document.getElementById('policy-name-input').value.trim();
      const description = document.getElementById('policy-desc-input').value.trim();
      const ruleName = document.getElementById('policy-rule-name-input').value.trim();
      const ruleType = document.getElementById('policy-rule-type-select').value;
      const rulePattern = document.getElementById('policy-rule-pattern-input').value.trim();

      document.getElementById('modal-add-policy').classList.remove('open');

      try {
        await apiRequest('/api/blue-team/policies', {
          method: 'POST',
          body: JSON.stringify({
            id,
            name,
            version: '1.0',
            is_active: true,
            description,
            rules: [
              {
                rule_id: `rule-${id}-01`,
                name: ruleName,
                rule_type: ruleType,
                pattern: rulePattern,
                action: 'block',
                description: `Rule created via Blue Team Console: ${ruleName}`,
              },
            ],
          }),
        });
        alert(`Defensive policy '${id}' successfully created and active in Blue Team workspace.`);
        loadBlueTeamWorkspace();
      } catch (err) {
        alert(`Policy creation failed: ${err.message}`);
      }
    });
  }
}

function setupActionButtons() {
  // Anchor External Checkpoint Button (Priority 5)
  const anchorBtn = document.getElementById('btn-anchor-checkpoint');
  if (anchorBtn) {
    anchorBtn.addEventListener('click', async () => {
      try {
        const res = await apiRequest('/api/audit/checkpoints', {
          method: 'POST',
          body: JSON.stringify({ description: 'Manual Security Anchor' }),
        });
        alert(`🔒 External Trust Anchor Checkpoint Created!\n\nCheckpoint ID: ${res.checkpoint_id}\nBlock Height: ${res.block_height}\nTip Hash: ${res.tip_hash.substring(0, 16)}...\nEd25519 Sig: ${res.signature.substring(0, 24)}...`);
        loadCheckpoints();
        loadAuditTrail();
      } catch (err) {
        alert(`Failed to create checkpoint: ${err.message}`);
      }
    });
  }

  // Verify Audit Chain Button
  document.getElementById('btn-verify-audit-chain').addEventListener('click', () => {
    verifyAuditChain();
  });

  // Tamper Demo Buttons
  document.getElementById('btn-tamper-payload').addEventListener('click', async () => {
    try {
      const res = await apiRequest('/api/audit/tamper-demo', {
        method: 'POST',
        body: JSON.stringify({ action: 'tamper_payload' }),
      });
      showTamperBanner(`🚨 Tamper Injected: Event payload modified at index #${res.tampered_event_index}. Verifying chain...`, 'danger');
      await verifyAuditChain();
    } catch (err) {
      alert(`Tamper demo error: ${err.message}`);
    }
  });

  document.getElementById('btn-delete-event').addEventListener('click', async () => {
    try {
      const res = await apiRequest('/api/audit/tamper-demo', {
        method: 'POST',
        body: JSON.stringify({ action: 'delete_event' }),
      });
      showTamperBanner(`🚨 Tamper Injected: Event #${res.deleted_event_index} deleted from chain. Verifying chain...`, 'danger');
      await verifyAuditChain();
    } catch (err) {
      alert(`Tamper demo error: ${err.message}`);
    }
  });

  document.getElementById('btn-restore-chain').addEventListener('click', async () => {
    try {
      const res = await apiRequest('/api/audit/tamper-demo', {
        method: 'POST',
        body: JSON.stringify({ action: 'restore_clean' }),
      });
      showTamperBanner(`✅ Restored: Clean cryptographic chain restored. Re-verifying...`, 'success');
      await verifyAuditChain();
    } catch (err) {
      alert(`Restore error: ${err.message}`);
    }
  });

  // Run Security Tests
  document.getElementById('btn-run-security-tests').addEventListener('click', () => {
    runSecurityBoundaryTests();
    loadCanaries();
  });

  // Proof Mode Re-verify
  const refreshProofBtn = document.getElementById('btn-refresh-proof-mode');
  if (refreshProofBtn) {
    refreshProofBtn.addEventListener('click', () => {
      loadProofModeMatrix();
    });
  }

  // Header Proof Mode Indicator Click
  const proofIndicator = document.getElementById('proof-mode-indicator');
  if (proofIndicator) {
    proofIndicator.addEventListener('click', () => {
      const proofTab = document.querySelector('[data-tab="tab-proof-mode"]');
      if (proofTab) proofTab.click();
    });
  }

  // Canary Probe Simulation Button
  const simCanaryBtn = document.getElementById('btn-simulate-canary-trip');
  if (simCanaryBtn) {
    simCanaryBtn.addEventListener('click', async () => {
      try {
        const res = await apiRequest('/api/canaries/simulate-trip', {
          method: 'POST',
          body: JSON.stringify({ token_id: 'canary-red-payload-01', simulated_role: 'blue_team' }),
        });
        alert(`🚨 Canary Tripwire Triggered & Access Denied!\n\nTarget Decoy: Red Team Confidential Payload\nAttempted by: Blue Team\nFingerprint: ${res.token_fingerprint.substring(0, 16)}...\nResult: Blocked with HTTP 403 & logged in hash-chain without exposing fake secret.`);
        loadCanaries();
        loadAuditTrail();
      } catch (err) {
        alert(`Canary simulation error: ${err.message}`);
      }
    });
  }

  // Rerun Configuration Button (PR-5)
  const rerunBtn = document.getElementById('btn-rerun-run');
  if (rerunBtn) {
    rerunBtn.addEventListener('click', async () => {
      if (!state.activeRun) return;
      if (state.activeRole !== 'operator') {
        alert('Only Operators can execute evaluation reruns. Please switch to Operator in header.');
        return;
      }
      try {
        const rerun = await apiRequest(`/api/eval/runs/${state.activeRun.id}/rerun`, { method: 'POST' });
        state.activeRun = rerun;
        renderActiveRun(rerun);
        await loadRunsHistory();
        await loadAuditTrail();
        alert(`✅ Rerun completed! Run ID: ${rerun.id}\nConfig Fingerprint: ${rerun.config_fingerprint.substring(0, 16)}...`);
      } catch (err) {
        alert(`Rerun failed: ${err.message}`);
      }
    });
  }

  // Compare Runs Button (PR-5)
  const compareBtn = document.getElementById('btn-compare-run');
  if (compareBtn) {
    compareBtn.addEventListener('click', () => {
      if (state.activeRun) {
        openCompareModal(state.activeRun.id);
      }
    });
  }

  // Trigger Compare in Modal
  const triggerCompareBtn = document.getElementById('btn-trigger-compare');
  if (triggerCompareBtn) {
    triggerCompareBtn.addEventListener('click', async () => {
      const baseId = document.getElementById('compare-baseline-select').value;
      const rerunId = document.getElementById('compare-rerun-select').value;
      if (!baseId || !rerunId) {
        alert('Please select both a baseline run and a rerun to compare.');
        return;
      }
      try {
        const comp = await apiRequest('/api/eval/runs/compare', {
          method: 'POST',
          body: JSON.stringify({ baseline_run_id: baseId, rerun_run_id: rerunId }),
        });
        renderComparisonResult(comp);
      } catch (err) {
        alert(`Comparison error: ${err.message}`);
      }
    });
  }

  // Evidence Report Button (PR-6)
  const reportBtn = document.getElementById('btn-export-evidence-report');
  if (reportBtn) {
    reportBtn.addEventListener('click', () => {
      if (state.activeRun) {
        openEvidenceReportModal(state.activeRun.id);
      }
    });
  }

  // Download Evidence Report Markdown
  const dlMdBtn = document.getElementById('btn-download-evidence-md');
  if (dlMdBtn) {
    dlMdBtn.addEventListener('click', async () => {
      if (!state.currentReportRunId) return;
      try {
        const res = await fetch(`/api/eval/runs/${state.currentReportRunId}/evidence-report?format=markdown`, {
          headers: { 'X-Bayora-Role': state.activeRole, 'X-Bayora-User': state.activeUser },
        });
        const text = await res.text();
        downloadFile(text, `bayora_evidence_${state.currentReportRunId}.md`, 'text/markdown');
      } catch (err) {
        alert(`Download failed: ${err.message}`);
      }
    });
  }

  // Download Evidence Report JSON
  const dlJsonBtn = document.getElementById('btn-download-evidence-json');
  if (dlJsonBtn) {
    dlJsonBtn.addEventListener('click', async () => {
      if (!state.currentReportRunId) return;
      try {
        const data = await apiRequest(`/api/eval/runs/${state.currentReportRunId}/evidence-report?format=json`);
        downloadFile(JSON.stringify(data, null, 2), `bayora_evidence_${state.currentReportRunId}.json`, 'application/json');
      } catch (err) {
        alert(`Download failed: ${err.message}`);
      }
    });
  }

  // Manifest Actions
  document.getElementById('btn-export-manifest').addEventListener('click', async () => {
    if (!state.activeRun) return;
    try {
      const manifest = await apiRequest(`/api/eval/runs/${state.activeRun.id}/manifest`);
      document.getElementById('manifest-json-pre').textContent = JSON.stringify(manifest, null, 2);
      document.getElementById('manifest-sig-verify-status').textContent = 'Ed25519 Signature attached to manifest.';
      document.getElementById('modal-manifest').classList.add('open');
    } catch (err) {
      alert(`Could not export manifest: ${err.message}`);
    }
  });

  document.getElementById('btn-verify-manifest-sig').addEventListener('click', async () => {
    if (!state.activeRun) return;
    try {
      const res = await apiRequest(`/api/eval/runs/${state.activeRun.id}/verify-manifest`, { method: 'POST' });
      if (res.is_signature_valid) {
        alert(`✅ Cryptographic Proof Verified!\nEd25519 signature is VALID.\nSigner Key Fingerprint: ${res.signer_public_key_fingerprint}`);
      } else {
        alert('❌ INVALID SIGNATURE: Manifest was modified after signing!');
      }
    } catch (err) {
      alert(`Signature verification failed: ${err.message}`);
    }
  });
}

function showTamperBanner(message, type) {
  const banner = document.getElementById('tamper-status-banner');
  banner.style.display = 'block';
  banner.textContent = message;
  if (type === 'danger') {
    banner.style.background = 'rgba(244, 63, 94, 0.15)';
    banner.style.color = '#fda4af';
    banner.style.border = '1px solid rgba(244, 63, 94, 0.3)';
  } else {
    banner.style.background = 'rgba(16, 185, 129, 0.15)';
    banner.style.color = '#6ee7b7';
    banner.style.border = '1px solid rgba(16, 185, 129, 0.3)';
  }
}

function showLoadingNotification(msg) {
  // Simple non-blocking indicator
}

// ----------------- Data Loaders -----------------
async function loadInitialData() {
  try {
    // 1. Public Key
    const keyData = await apiRequest('/api/audit/public-key');
    state.publicKeyFingerprint = keyData.fingerprint_sha256;
    document.getElementById('header-key-fp').textContent = keyData.fingerprint_sha256;

    // 2. Audit Verification & Blocks count
    await verifyAuditChain();

    // 3. Runs History
    await loadRunsHistory();

    // 4. Proof Mode Matrix & Canaries
    await loadProofModeMatrix();
    await loadCanaries();

    // 5. Default run if exists
    if (state.runs.length > 0) {
      state.activeRun = state.runs[state.runs.length - 1];
      renderActiveRun(state.activeRun);
    }
  } catch (err) {
    console.error('Initialization error:', err);
  }
}

async function loadRunsHistory() {
  try {
    const runs = await apiRequest('/api/eval/runs');
    state.runs = runs;
    document.getElementById('metric-runs-count').textContent = runs.length;

    // Compute aggregate safety pass rate
    let totalTests = 0;
    let safeTests = 0;
    runs.forEach(r => {
      totalTests += r.total_tests;
      safeTests += r.passed_tests;
    });
    const passRate = totalTests > 0 ? Math.round((safeTests / totalTests) * 100) : 100;
    document.getElementById('metric-safety-pass-rate').textContent = `${passRate}%`;

    const tbody = document.getElementById('runs-history-tbody');
    if (runs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; padding:1.5rem; color:var(--text-muted);">No evaluation runs executed yet. Click "New Evaluation Run" above.</td></tr>';
      return;
    }

    tbody.innerHTML = runs.map(r => `
      <tr>
        <td style="font-family:var(--font-mono); font-weight:700; color:var(--accent-cyan); font-size:0.75rem;">${r.id}</td>
        <td><strong>${r.name}</strong></td>
        <td style="font-family:var(--font-mono); font-size:0.75rem;">${r.model_id}</td>
        <td style="font-family:var(--font-mono); font-size:0.75rem;">${r.policy_id || 'None (Baseline)'}</td>
        <td><span class="badge ${r.status === 'completed' ? 'badge-blocked' : 'badge-timeout'}">${r.status.toUpperCase()}</span></td>
        <td><strong>${r.passed_tests}</strong> / ${r.total_tests} safe</td>
        <td>
          <span style="font-family:var(--font-mono); font-size:0.7rem; color:var(--accent-emerald);">
            ${r.manifest_signature ? '✓ Signed Ed25519' : 'Pending'}
          </span>
        </td>
        <td>
          <div style="display:flex; gap:0.35rem; flex-wrap:wrap;">
            <button class="btn btn-secondary" style="padding:0.2rem 0.5rem; font-size:0.72rem;" onclick="inspectRun('${r.id}')">
              Inspect
            </button>
            <button class="btn btn-secondary" style="padding:0.2rem 0.5rem; font-size:0.72rem;" onclick="rerunRunFromHistory('${r.id}')" title="Rerun exact configuration (PR-5)">
              Rerun
            </button>
            <button class="btn btn-secondary" style="padding:0.2rem 0.5rem; font-size:0.72rem;" onclick="openCompareModal('${r.id}')" title="Compare with another run (PR-5)">
              Compare
            </button>
            <button class="btn btn-secondary" style="padding:0.2rem 0.5rem; font-size:0.72rem;" onclick="openEvidenceReportModal('${r.id}')" title="Export Evidence Report (PR-6)">
              Report
            </button>
          </div>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Failed to load runs history:', err);
  }
}

window.inspectRun = function(runId) {
  const run = state.runs.find(r => r.id === runId);
  if (run) {
    state.activeRun = run;
    renderActiveRun(run);
    window.scrollTo({ top: 150, behavior: 'smooth' });
  }
};

function renderActiveRun(run) {
  const container = document.getElementById('active-run-container');
  container.style.display = 'block';

  document.getElementById('active-run-title').textContent = run.name;
  document.getElementById('active-run-meta').textContent = `Run ID: ${run.id} | Model: ${run.model_id} | Policy: ${run.policy_id || 'Undefended Baseline'} | Started: ${run.started_at ? new Date(run.started_at).toLocaleTimeString() : 'N/A'}`;

  const statusBadge = document.getElementById('active-run-status-badge');
  statusBadge.textContent = run.status.toUpperCase();
  statusBadge.className = `badge ${run.status === 'completed' ? 'badge-blocked' : 'badge-timeout'}`;

  // Counter Pills
  const countersEl = document.getElementById('active-run-counters');
  countersEl.innerHTML = `
    <span class="badge badge-blocked">✓ ${run.passed_tests} Safe Outcomes</span>
    <span class="badge ${run.failed_tests > 0 ? 'badge-exploited' : 'badge-benign'}">⚠ ${run.failed_tests} Exploited</span>
    <span class="badge ${run.timeout_tests > 0 ? 'badge-timeout' : 'badge-benign'}">⏱ ${run.timeout_tests} Timeouts</span>
    <span class="badge badge-benign">Total Tests: ${run.total_tests}</span>
  `;

  // Results table
  const tbody = document.getElementById('active-run-results-tbody');
  tbody.innerHTML = run.results.map(res => {
    let outcomeBadgeClass = 'badge-blocked';
    let outcomeLabel = 'BLOCKED BY DEFENSE';

    if (res.outcome === 'vulnerability_exploited') {
      outcomeBadgeClass = 'badge-exploited';
      outcomeLabel = 'EXPLOIT SUCCEEDED';
    } else if (res.outcome === 'timeout_exceeded') {
      outcomeBadgeClass = 'badge-timeout';
      outcomeLabel = 'TIMEOUT TERMINATED';
    } else if (res.outcome === 'benign_success') {
      outcomeBadgeClass = 'badge-benign';
      outcomeLabel = 'BENIGN SUCCESS';
    } else if (res.outcome === 'model_refused') {
      outcomeBadgeClass = 'badge-blocked';
      outcomeLabel = 'MODEL REFUSED';
    }

    return `
      <tr>
        <td>
          <div style="font-weight:700; color:var(--text-primary);">${res.test_name}</div>
          <div style="font-size:0.72rem; font-family:var(--font-mono); color:var(--text-muted);">${res.test_id}</div>
        </td>
        <td><span style="font-size:0.78rem; text-transform:capitalize;">${res.category}</span></td>
        <td><span class="badge ${res.severity === 'critical' || res.severity === 'high' ? 'badge-exploited' : 'badge-timeout'}">${res.severity}</span></td>
        <td>
          <span style="font-family:var(--font-mono); font-size:0.72rem; color:var(--text-secondary);" title="Raw prompt was hashed with SHA-256 to prevent leakage in reviewer logs">
            🔒 ${res.prompt_hash.substring(0, 16)}...
          </span>
          <div style="font-size:0.7rem; color:var(--text-muted);">${res.prompt_preview}</div>
        </td>
        <td><span class="badge ${outcomeBadgeClass}">${outcomeLabel}</span></td>
        <td style="font-family:var(--font-mono); font-size:0.75rem;">${res.latency_ms} ms</td>
        <td style="font-size:0.8rem; color:var(--text-secondary); max-width:320px;">
          ${res.defense_triggered ? `<strong style="color:#38bdf8;">[Defense]</strong> ` : ''}
          ${res.model_response_snippet}
        </td>
      </tr>
    `;
  }).join('');
}

// ----------------- Audit Trail & Chain Verification (PR-5) -----------------
async function loadCheckpoints() {
  try {
    const ckpts = await apiRequest('/api/audit/checkpoints');
    const tbody = document.getElementById('checkpoints-tbody');
    if (!tbody) return;
    if (ckpts.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:1.25rem; color:var(--text-muted);">No external checkpoints anchored yet. Click "Anchor Trust Checkpoint" above to freeze state.</td></tr>';
      return;
    }
    tbody.innerHTML = ckpts.slice().reverse().map(c => `
      <tr>
        <td style="font-family:var(--font-mono); font-weight:700; color:var(--accent-cyan); font-size:0.75rem;">${c.checkpoint_id}</td>
        <td><strong>#${c.block_height}</strong></td>
        <td style="font-family:var(--font-mono); font-size:0.72rem; color:var(--text-secondary);" title="${c.tip_hash}">${c.tip_hash.substring(0, 16)}...</td>
        <td style="font-family:var(--font-mono); font-size:0.72rem; color:var(--text-muted);" title="${c.merkle_root}">${c.merkle_root.substring(0, 16)}...</td>
        <td style="font-size:0.75rem; color:var(--text-muted);">${new Date(c.timestamp).toLocaleTimeString()}</td>
        <td><span class="badge badge-blocked">✓ ANCHORED (Ed25519)</span></td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Failed to load checkpoints:', err);
  }
}

async function loadAuditTrail() {
  try {
    await loadCheckpoints();
    const events = await apiRequest('/api/audit/events');
    state.auditEvents = events;
    document.getElementById('metric-chain-blocks').textContent = `${events.length} Blocks`;

    const container = document.getElementById('chain-timeline-container');
    if (events.length === 0) {
      container.innerHTML = '<div style="text-align:center; padding:2rem; color:var(--text-muted);">No audit events recorded yet.</div>';
      return;
    }

    // Render events in reverse chronological order
    container.innerHTML = events.slice().reverse().map((ev, rIdx) => {
      const realIdx = events.length - 1 - rIdx;
      return `
        <div class="chain-block" id="audit-block-${realIdx}">
          <div class="block-meta">
            <div style="display:flex; align-items:center; gap:0.6rem;">
              <span class="block-id">#${realIdx} [${ev.event_id}]</span>
              <span class="badge badge-benign">${ev.event_type}</span>
            </div>
            <div style="font-size:0.75rem; color:var(--text-muted);">
              Actor: <strong style="color:var(--text-primary);">${ev.actor}</strong> (${ev.role}) | ${new Date(ev.timestamp).toLocaleTimeString()}
            </div>
          </div>
          <div class="block-hashes">
            <div>
              <div class="hash-label">Previous Hash (Pointer)</div>
              <div class="hash-val" title="${ev.prev_hash}">${ev.prev_hash}</div>
            </div>
            <div>
              <div class="hash-label">Current Event SHA-256 Hash</div>
              <div class="hash-val" title="${ev.event_hash}">${ev.event_hash}</div>
            </div>
          </div>
          <div style="font-size:0.75rem; font-family:var(--font-mono); color:var(--text-muted); background:rgba(0,0,0,0.2); padding:0.4rem 0.6rem; border-radius:var(--radius-sm); overflow-x:auto;">
            ${JSON.stringify(ev.payload)}
          </div>
        </div>
      `;
    }).join('');
  } catch (err) {
    console.error('Failed to load audit trail:', err);
  }
}

async function verifyAuditChain() {
  try {
    const res = await apiRequest('/api/audit/verify');
    const resultBox = document.getElementById('verification-result-box');
    const metricBadge = document.getElementById('metric-chain-badge');
    resultBox.style.display = 'block';

    // Clear any previous tampered highlights
    document.querySelectorAll('.chain-block').forEach(el => el.classList.remove('tampered-alert'));

    if (res.is_valid) {
      metricBadge.className = 'badge badge-blocked';
      metricBadge.textContent = 'Verified Valid';

      resultBox.innerHTML = `
        <div style="display:flex; align-items:center; gap:0.75rem; color:#34d399;">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
          <div>
            <div style="font-weight:700; font-size:1rem;">Cryptographic Audit Chain 100% Intact</div>
            <div style="font-size:0.8rem; color:var(--text-secondary); margin-top:0.15rem;">
              Verified ${res.total_events} blocks from genesis hash. All prev_hash pointers match and canonical JSON SHA-256 hashes are valid.
            </div>
          </div>
        </div>
      `;
    } else {
      metricBadge.className = 'badge badge-exploited';
      metricBadge.textContent = 'TAMPER DETECTED';

      resultBox.innerHTML = `
        <div style="display:flex; align-items:flex-start; gap:0.75rem; color:#fb7185;">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          <div>
            <div style="font-weight:700; font-size:1rem;">🚨 INTEGRITY VIOLATION DETECTED: Tampered Audit Event!</div>
            <div style="font-size:0.82rem; color:#fecdd3; margin-top:0.25rem; font-family:var(--font-mono);">
              ${res.error_message}
            </div>
            <div style="font-size:0.78rem; color:var(--text-secondary); margin-top:0.4rem;">
              The audit verification engine successfully flagged the alteration at block index #${res.broken_link_index}.
            </div>
          </div>
        </div>
      `;

      // Highlight the corrupted card
      if (res.broken_link_index !== null) {
        const corruptedEl = document.getElementById(`audit-block-${res.broken_link_index}`);
        if (corruptedEl) {
          corruptedEl.classList.add('tampered-alert');
          corruptedEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
      }
    }

    // Refresh chain view
    await loadAuditTrail();
  } catch (err) {
    console.error('Audit verification error:', err);
  }
}

// ----------------- Security Boundary Tests Runner (PR-1, PR-2, PR-3, PR-7, PR-8) -----------------
async function runSecurityBoundaryTests() {
  const tbody = document.getElementById('security-tests-tbody');
  const loading = document.getElementById('security-tests-loading');
  tbody.innerHTML = '';
  loading.style.display = 'block';

  try {
    const results = await apiRequest('/api/security-tests/run');
    loading.style.display = 'none';

    tbody.innerHTML = results.map(r => `
      <tr>
        <td style="font-family:var(--font-mono); font-weight:700; color:var(--accent-cyan);">${r.test_id}</td>
        <td>
          <div style="font-weight:700; color:var(--text-primary);">${r.name}</div>
          <div style="font-size:0.72rem; color:var(--text-muted);">${r.description}</div>
        </td>
        <td style="font-family:var(--font-mono); font-size:0.72rem; color:var(--text-secondary);">${r.action_attempted}</td>
        <td style="font-size:0.78rem; color:#94a3b8;">${r.expected_result}</td>
        <td style="font-size:0.78rem; font-family:var(--font-mono); color:${r.status === 'PASSED' ? '#34d399' : '#fb7185'};">
          ${r.actual_result}
        </td>
        <td>
          <span class="badge ${r.status === 'PASSED' ? 'badge-blocked' : 'badge-exploited'}">
            ${r.status === 'PASSED' ? '✓ DEFENSE PASSED' : '✗ BREACH'}
          </span>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    loading.style.display = 'none';
    tbody.innerHTML = `<tr><td colspan="6" style="color:#fb7185; text-align:center;">Failed to run security tests: ${err.message}</td></tr>`;
  }
}

// ----------------- Workspaces (Red & Blue Team) -----------------
async function loadRedTeamWorkspace() {
  if (state.activeRole === 'blue_team') return; // Handled by barrier
  try {
    const cases = await apiRequest('/api/red-team/test-cases');
    state.testCases = cases;
    const tbody = document.getElementById('red-team-tbody');
    if (cases.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding:1.5rem; color:var(--text-muted);">Red Team workspace is empty.</td></tr>';
      return;
    }

    tbody.innerHTML = cases.map(tc => `
      <tr>
        <td style="font-family:var(--font-mono); font-weight:700; color:var(--accent-cyan);">${tc.id}</td>
        <td><strong>${tc.name}</strong></td>
        <td><span style="font-size:0.78rem; text-transform:capitalize;">${tc.category}</span></td>
        <td><span class="badge ${tc.severity === 'critical' || tc.severity === 'high' ? 'badge-exploited' : 'badge-timeout'}">${tc.severity}</span></td>
        <td style="font-family:var(--font-mono); font-size:0.78rem; color:var(--text-secondary); max-width:280px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
          ${tc.prompt}
        </td>
        <td><span class="badge badge-blocked">${tc.expected_outcome}</span></td>
        <td style="font-size:0.78rem; color:var(--text-muted);">${tc.author}</td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Failed to load red team cases:', err);
  }
}

async function loadBlueTeamWorkspace() {
  if (state.activeRole === 'red_team') return; // Handled by barrier
  try {
    const policies = await apiRequest('/api/blue-team/policies');
    state.policies = policies;
    const container = document.getElementById('blue-policies-container');
    if (policies.length === 0) {
      container.innerHTML = '<div style="text-align:center; padding:2rem; color:var(--text-muted);">No policies configured.</div>';
      return;
    }

    container.innerHTML = policies.map(p => `
      <div class="glass-panel" style="padding:1.5rem;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem; flex-wrap:wrap; gap:0.5rem;">
          <div>
            <div style="display:flex; align-items:center; gap:0.6rem;">
              <h3 style="font-size:1.05rem; font-weight:700;">${p.name}</h3>
              <span class="badge ${p.is_active ? 'badge-blocked' : 'badge-timeout'}">${p.is_active ? 'ACTIVE' : 'DISABLED'}</span>
              <span style="font-size:0.72rem; font-family:var(--font-mono); color:var(--text-muted);">v${p.version}</span>
            </div>
            <p style="font-size:0.82rem; color:var(--text-secondary); margin-top:0.25rem;">${p.description}</p>
          </div>
          <div>
            <button class="btn btn-secondary" onclick="togglePolicy('${p.id}')">
              ${p.is_active ? 'Deactivate Shield' : 'Activate Shield'}
            </button>
          </div>
        </div>

        <div style="font-size:0.8rem; font-weight:600; text-transform:uppercase; color:var(--text-muted); margin-bottom:0.6rem;">
          Configured Defense Rules (${p.rules.length})
        </div>
        <div class="table-container">
          <table class="data-table">
            <thead>
              <tr>
                <th>Rule ID</th>
                <th>Rule Name</th>
                <th>Type</th>
                <th>Enforcement Pattern / Parameter</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              ${p.rules.map(r => `
                <tr>
                  <td style="font-family:var(--font-mono); color:var(--accent-cyan);">${r.rule_id}</td>
                  <td><strong>${r.name}</strong></td>
                  <td><span class="badge badge-benign">${r.rule_type}</span></td>
                  <td style="font-family:var(--font-mono); font-size:0.75rem; color:var(--text-secondary); max-width:300px; word-break:break-all;">
                    ${r.pattern || 'None'}
                  </td>
                  <td><span class="badge badge-blocked">${r.action.toUpperCase()}</span></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `).join('');
  } catch (err) {
    console.error('Failed to load blue team policies:', err);
  }
}

window.togglePolicy = async function(policyId) {
  try {
    await apiRequest(`/api/blue-team/policies/${policyId}/toggle`, { method: 'PATCH' });
    loadBlueTeamWorkspace();
  } catch (err) {
    alert(`Could not toggle policy: ${err.message}`);
  }
};

// ================= Proof Mode & Controls Matrix (PR-3) =================
async function loadProofModeMatrix() {
  try {
    const matrix = await apiRequest('/api/security-tests/proof-mode');
    state.proofModeMatrix = matrix;

    // Header & Banner Badges
    const headerStatus = document.getElementById('header-proof-status');
    if (headerStatus) {
      headerStatus.textContent = `${matrix.passing_tests_count} Tested / ${matrix.assumed_controls_count} Assumed`;
    }

    const passBadge = document.getElementById('proof-matrix-passing-badge');
    if (passBadge) {
      passBadge.textContent = `${matrix.passing_tests_count} / ${matrix.tested_controls_count} Tested Mechanisms Passing`;
    }

    const assumedBadge = document.getElementById('proof-matrix-assumed-badge');
    if (assumedBadge) {
      assumedBadge.textContent = `${matrix.assumed_controls_count} Documented Limitations Disclosed`;
    }

    // Render Section A (Tested)
    const testedTbody = document.getElementById('proof-mode-tested-tbody');
    if (testedTbody) {
      const testedControls = matrix.controls.filter(c => c.is_tested);
      testedTbody.innerHTML = testedControls.map(c => `
        <tr>
          <td style="font-family:var(--font-mono); font-weight:700; color:var(--accent-cyan); font-size:0.78rem;">${c.control_id}</td>
          <td><strong>${c.name}</strong><div style="font-size:0.75rem; color:var(--text-secondary); margin-top:0.15rem;">${c.description}</div></td>
          <td><span style="font-family:var(--font-mono); font-size:0.75rem; color:var(--text-muted);">${c.control_id}</span></td>
          <td>
            <span class="badge ${c.status === 'tested_passing' ? 'badge-blocked' : 'badge-exploited'}">
              ${c.status === 'tested_passing' ? '✓ TESTED & PASSING' : '✗ TESTED & FAILING'}
            </span>
          </td>
          <td style="font-size:0.78rem; color:var(--text-secondary); line-height:1.5;">${c.evidence_or_assumption}</td>
        </tr>
      `).join('');
    }

    // Render Section B (Assumed / Residual Risks)
    const assumedTbody = document.getElementById('proof-mode-assumed-tbody');
    if (assumedTbody) {
      const assumedControls = matrix.controls.filter(c => !c.is_tested);
      assumedTbody.innerHTML = assumedControls.map(c => `
        <tr>
          <td style="font-family:var(--font-mono); font-weight:700; color:#fbbf24; font-size:0.78rem;">${c.control_id}</td>
          <td><strong>${c.name}</strong><div style="font-size:0.75rem; color:var(--text-secondary); margin-top:0.15rem;">${c.description}</div></td>
          <td><span class="badge badge-assumed">ASSUMED & UNTESTED</span></td>
          <td style="font-size:0.78rem; color:#fef3c7; line-height:1.5; background:rgba(245,158,11,0.03);">${c.evidence_or_assumption}</td>
        </tr>
      `).join('');
    }
  } catch (err) {
    console.error('Failed to load proof mode matrix:', err);
  }
}

// ================= Canary Secrets & Decoy Tokens (PR-2) =================
async function loadCanaries() {
  try {
    const [canaries, trips] = await Promise.all([
      apiRequest('/api/canaries'),
      apiRequest('/api/canaries/trips'),
    ]);
    state.canaryTokens = canaries;
    state.canaryTrips = trips;

    const container = document.getElementById('canaries-container');
    if (container) {
      container.innerHTML = canaries.map(c => `
        <div class="canary-card">
          <div class="canary-header">
            <span class="canary-name">${c.name}</span>
            <span class="badge ${c.tripped ? 'badge-exploited' : 'badge-blocked'}">
              ${c.tripped ? `🚨 TRIPPED (${c.trip_count}x)` : '✓ INTACT'}
            </span>
          </div>
          <div style="font-size:0.78rem; color:var(--text-secondary); margin-bottom:0.5rem;">
            ${c.description}
          </div>
          <div style="font-size:0.72rem; color:var(--text-muted);">
            Workspace: <strong style="color:var(--text-primary);">${c.workspace_location}</strong> | File: <code>${c.file_name}</code>
          </div>
          <div class="canary-hash" title="SHA-256 fingerprint stored in audit trail (raw token is never logged)">
            SHA-256: ${c.token_hash}
          </div>
        </div>
      `).join('');
    }

    const tripsTbody = document.getElementById('canary-trips-tbody');
    if (tripsTbody) {
      if (trips.length === 0) {
        tripsTbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:1.25rem; color:var(--text-muted);">No canary trip attempts recorded. Click "Simulate Unauthorized Canary Probe" above to test detection.</td></tr>';
      } else {
        tripsTbody.innerHTML = trips.slice().reverse().map(t => `
          <tr>
            <td style="font-family:var(--font-mono); color:var(--accent-cyan); font-size:0.75rem;">${t.trip_id}</td>
            <td><strong>${t.token_name}</strong></td>
            <td><span class="badge badge-benign">${t.target_workspace}</span></td>
            <td><span class="badge badge-timeout">${t.attempted_by_role}</span></td>
            <td style="font-size:0.75rem; color:var(--text-muted);">${new Date(t.timestamp).toLocaleTimeString()}</td>
            <td><span class="badge badge-blocked">BLOCKED & LOGGED (403)</span></td>
          </tr>
        `).join('');
      }
    }
  } catch (err) {
    console.error('Failed to load canaries:', err);
  }
}

// ================= Repeatable Evaluation & Comparison (PR-5) =================
window.rerunRunFromHistory = async function(runId) {
  if (state.activeRole !== 'operator') {
    alert('Only Operators can execute evaluation reruns. Please switch to Operator in header.');
    return;
  }
  try {
    const rerun = await apiRequest(`/api/eval/runs/${runId}/rerun`, { method: 'POST' });
    state.activeRun = rerun;
    renderActiveRun(rerun);
    await loadRunsHistory();
    await loadAuditTrail();
    alert(`✅ Rerun completed! Run ID: ${rerun.id}\nConfig Fingerprint: ${rerun.config_fingerprint.substring(0, 16)}...`);
  } catch (err) {
    alert(`Rerun failed: ${err.message}`);
  }
};

window.openCompareModal = function(prefillBaselineId) {
  const baseSelect = document.getElementById('compare-baseline-select');
  const rerunSelect = document.getElementById('compare-rerun-select');
  if (!baseSelect || !rerunSelect) return;

  const options = state.runs.map(r => `<option value="${r.id}" title="${r.id} - ${r.name} (${r.model_id})">${r.id} - ${r.name} (${r.model_id})</option>`).join('');
  baseSelect.innerHTML = options;
  rerunSelect.innerHTML = options;

  if (prefillBaselineId) {
    baseSelect.value = prefillBaselineId;
    // Pre-select an alternate rerun if exists
    const alternate = state.runs.find(r => r.id !== prefillBaselineId);
    if (alternate) rerunSelect.value = alternate.id;
  }

  document.getElementById('modal-compare-runs').classList.add('open');

  // If two options selected, trigger automatically
  if (baseSelect.value && rerunSelect.value && baseSelect.value !== rerunSelect.value) {
    document.getElementById('btn-trigger-compare').click();
  }
};

function renderComparisonResult(comp) {
  const summaryBox = document.getElementById('compare-summary-box');
  summaryBox.style.display = 'block';

  const fpStatus = document.getElementById('compare-fingerprint-status');
  if (comp.config_fingerprint_match) {
    fpStatus.textContent = 'MATCH (Deterministic Identical Configuration)';
    fpStatus.style.color = '#34d399';
  } else {
    fpStatus.textContent = 'DIVERGENT CONFIGURATION (Model/Policy/Tests Differ)';
    fpStatus.style.color = '#fb7185';
  }

  document.getElementById('compare-test-set-ver').textContent = comp.test_set_version;
  document.getElementById('compare-reproducibility-pct').textContent = `${comp.reproducibility_percentage}% (${comp.matched_outcomes}/${comp.total_tests} matched)`;

  const tbody = document.getElementById('compare-results-tbody');
  tbody.innerHTML = comp.items.map(item => `
    <tr>
      <td style="font-family:var(--font-mono); font-size:0.75rem;">
        <strong>${item.test_id}</strong>
        <div style="font-size:0.72rem; color:var(--text-secondary);">${item.test_name}</div>
      </td>
      <td><span style="font-size:0.75rem; text-transform:capitalize;">${item.category}</span></td>
      <td><span class="badge ${item.baseline_outcome === 'vulnerability_exploited' ? 'badge-exploited' : 'badge-blocked'}">${item.baseline_outcome}</span></td>
      <td><span class="badge ${item.rerun_outcome === 'vulnerability_exploited' ? 'badge-exploited' : 'badge-blocked'}">${item.rerun_outcome}</span></td>
      <td>
        <span class="${item.outcomes_match ? 'diff-match' : 'diff-divergent'}">
          ${item.outcomes_match ? '✓ IDENTICAL' : '⚠ DIVERGENT'}
        </span>
      </td>
      <td style="font-family:var(--font-mono); font-size:0.75rem;">${item.baseline_latency_ms} ms</td>
      <td style="font-family:var(--font-mono); font-size:0.75rem;">${item.rerun_latency_ms} ms</td>
      <td style="font-family:var(--font-mono); font-size:0.75rem; color:${item.latency_delta_ms > 0 ? '#fbbf24' : '#34d399'};">
        ${item.latency_delta_ms > 0 ? '+' : ''}${item.latency_delta_ms} ms
      </td>
    </tr>
  `).join('');
}

// ================= Evidence Report Modal (PR-6) =================
window.openEvidenceReportModal = async function(runId) {
  state.currentReportRunId = runId;
  try {
    const res = await fetch(`/api/eval/runs/${runId}/evidence-report?format=markdown`, {
      headers: { 'X-Bayora-Role': state.activeRole, 'X-Bayora-User': state.activeUser },
    });
    const markdown = await res.text();
    document.getElementById('evidence-report-pre').textContent = markdown;
    document.getElementById('modal-evidence-report').classList.add('open');
  } catch (err) {
    alert(`Could not load evidence report: ${err.message}`);
  }
};

function downloadFile(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

