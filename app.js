// Identity Shield Frontend Controller

document.addEventListener("DOMContentLoaded", () => {
  initApp();
});

let currentAliases = [];
let detectedNetworkUrl = window.location.origin;

function initApp() {
  loadNetworkInfo();
  loadStats();
  loadAliases();
  loadAuditLogs();
  setupEventListeners();
}

async function loadNetworkInfo() {
  const display = document.getElementById("network-ip-display");
  try {
    const res = await fetch("/api/network-info");
    if (!res.ok) throw new Error("Network info not available");
    const data = await res.json();
    detectedNetworkUrl = data.networkUrl || window.location.origin;
    if (display) {
      display.textContent = `📶 LAN: ${detectedNetworkUrl}`;
      display.title = data.connectAnyDeviceInstructions || "Open this URL on any device on your Wi-Fi";
    }
  } catch (err) {
    if (display) {
      display.textContent = `📶 Network: ${window.location.host}`;
    }
  }
}

function fallbackCopyTextToClipboard(text) {
  const textArea = document.createElement("textarea");
  textArea.value = text;
  textArea.style.position = "fixed";
  textArea.style.top = "-9999px";
  textArea.style.left = "-9999px";
  textArea.setAttribute("readonly", "");
  document.body.appendChild(textArea);
  textArea.select();
  textArea.setSelectionRange(0, 99999);
  let successful = false;
  try {
    successful = document.execCommand("copy");
  } catch (err) {
    successful = false;
  }
  document.body.removeChild(textArea);
  return successful;
}

function copyNetworkUrl() {
  if (navigator.vibrate) navigator.vibrate(30);
  if (navigator.share) {
    navigator
      .share({
        title: "Identity Shield Console",
        text: "Open Identity Shield on your phone or tablet on the same Wi-Fi:",
        url: detectedNetworkUrl,
      })
      .catch(() => {
        copyToClipboard(detectedNetworkUrl);
      });
  } else {
    copyToClipboard(detectedNetworkUrl);
  }
}

function setupEventListeners() {
  // Generate Form
  const genForm = document.getElementById("generate-form");
  if (genForm) {
    genForm.addEventListener("submit", handleGenerate);
  }

  // Tier select change (adjust TTL input requirement)
  const tierSelect = document.getElementById("gen-tier");
  const ttlInput = document.getElementById("gen-ttl");
  if (tierSelect && ttlInput) {
    tierSelect.addEventListener("change", (e) => {
      if (e.target.value === "ephemeral") {
        ttlInput.value = 14;
        ttlInput.disabled = false;
      } else if (e.target.value === "core") {
        ttlInput.value = "";
        ttlInput.disabled = true;
      } else {
        ttlInput.value = "";
        ttlInput.disabled = true;
      }
    });
  }

  // Simulator Form
  const simForm = document.getElementById("simulator-form");
  if (simForm) {
    simForm.addEventListener("submit", handleSimulateTrace);
  }

  // High-performance debounced search input
  const searchInput = document.getElementById("vault-search");
  if (searchInput) {
    searchInput.addEventListener("input", debounce(filterTable, 120));
  }

  const tierFilter = document.getElementById("filter-tier");
  if (tierFilter) {
    tierFilter.addEventListener("change", filterTable);
  }

  const statusFilter = document.getElementById("filter-status");
  if (statusFilter) {
    statusFilter.addEventListener("change", filterTable);
  }

  // Global Keyboard Shortcuts
  document.addEventListener("keydown", (e) => {
    // Press '/' or 'Ctrl+K' to quickly jump to search
    if (
      (e.key === "/" && document.activeElement.tagName !== "INPUT" && document.activeElement.tagName !== "TEXTAREA") ||
      ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k")
    ) {
      e.preventDefault();
      if (searchInput) {
        searchInput.focus();
        searchInput.select();
      }
    }
    // Press 'Escape' to close active modals
    if (e.key === "Escape") {
      closeAliasQrModal();
      const qrModal = document.getElementById("mobile-qr-modal");
      if (qrModal && !qrModal.classList.contains("hidden")) {
        qrModal.classList.add("hidden");
      }
    }
  });

  // Tabs
  const tabBtns = document.querySelectorAll(".tab-btn");
  tabBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      tabBtns.forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach((c) => c.classList.remove("active"));

      btn.classList.add("active");
      const targetId = btn.getAttribute("data-tab");
      const targetContent = document.getElementById(targetId);
      if (targetContent) targetContent.classList.add("active");
    });
  });
}

// Debounce helper
function debounce(fn, delay = 120) {
  let timer = null;
  return function (...args) {
    clearTimeout(timer);
    timer = setTimeout(() => fn.apply(this, args), delay);
  };
}

// API Calls
async function loadStats() {
  try {
    const res = await fetch("/api/stats");
    const data = await res.json();

    document.getElementById("stat-total").textContent = data.total_identities;
    document.getElementById("stat-active").textContent = data.active;
    document.getElementById("stat-ephemeral").textContent = data.ephemeral;
    document.getElementById("stat-leaks").textContent = data.leaks_detected;

    // Calculate Exposure Risk Threat Index
    const leaks = data.leaks_detected || 0;
    const commercial = data.commercial !== undefined ? data.commercial : ((data.tier_breakdown && data.tier_breakdown.commercial) || 0);
    const ephemeral = data.ephemeral || 0;

    // Formula: Leaks * 28 + commercial * 4 + ephemeral * 2
    const rawRisk = (leaks * 28) + (commercial * 4) + (ephemeral * 2);
    const riskScore = Math.min(100, Math.max(0, rawRisk));

    const riskValEl = document.getElementById("stat-risk");
    const riskSubEl = document.getElementById("stat-risk-sub");
    const gaugeCircle = document.getElementById("risk-gauge-circle");
    const riskCard = document.getElementById("metric-risk-card");
    const hudStatus = document.getElementById("hud-threat-status");

    if (riskValEl) {
      riskValEl.textContent = `${riskScore}%`;
    }

    // Toggle card threat color accent
    if (riskCard) {
      riskCard.classList.remove("success", "warning", "danger");
      if (riskScore <= 20) {
        riskCard.classList.add("success");
      } else if (riskScore <= 55) {
        riskCard.classList.add("warning");
      } else {
        riskCard.classList.add("danger");
      }
    }

    // Animate Circular SVG Gauge
    if (gaugeCircle) {
      const circumference = 188.5;
      const offset = circumference - (riskScore / 100) * circumference;
      gaugeCircle.style.strokeDashoffset = offset;

      if (riskScore <= 20) {
        gaugeCircle.style.stroke = "var(--accent-emerald)";
        gaugeCircle.style.filter = "drop-shadow(0 0 6px rgba(16, 185, 129, 0.4))";
        if (riskSubEl) {
          riskSubEl.textContent = "Threat Index: Minimal";
          riskSubEl.style.color = "var(--accent-emerald)";
        }
      } else if (riskScore <= 55) {
        gaugeCircle.style.stroke = "var(--accent-amber)";
        gaugeCircle.style.filter = "drop-shadow(0 0 6px rgba(245, 158, 11, 0.4))";
        if (riskSubEl) {
          riskSubEl.textContent = "Threat Index: Moderate";
          riskSubEl.style.color = "var(--accent-amber)";
        }
      } else {
        gaugeCircle.style.stroke = "var(--accent-rose)";
        gaugeCircle.style.filter = "drop-shadow(0 0 6px rgba(244, 63, 94, 0.4))";
        if (riskSubEl) {
          riskSubEl.textContent = "Threat Index: High Exposure";
          riskSubEl.style.color = "var(--accent-rose)";
        }
      }
    }

    if (hudStatus) {
      if (leaks > 0) {
        hudStatus.innerHTML = `CORRELATION PROTECTION: <b style="color:var(--accent-rose)">${leaks} THREAT(S) NEUTRALIZED</b>`;
      } else {
        hudStatus.innerHTML = `CORRELATION PROTECTION: <b style="color:var(--accent-emerald)">100% ARMED</b>`;
      }
    }
  } catch (err) {
    console.error("Failed to load metrics:", err);
  }
}

async function loadAliases() {
  try {
    const res = await fetch("/api/aliases");
    currentAliases = await res.json();
    renderAliases(currentAliases);
    populateSimulatorAliasOptions(currentAliases);
    populateIntelAliasOptions(currentAliases);
    updateTopologyGraph(currentAliases);
  } catch (err) {
    console.error("Failed to load aliases:", err);
    showToast("Error loading vault identities", "danger");
  }
}

let currentSortKey = "id";
let currentSortAsc = false;

function sortTable(key) {
  if (currentSortKey === key) {
    currentSortAsc = !currentSortAsc;
  } else {
    currentSortKey = key;
    currentSortAsc = true;
  }

  // Update sort icon indicators
  document.querySelectorAll(".sort-icon").forEach((el) => (el.textContent = "⇅"));
  const activeIcon = document.getElementById(`sort-${key}`);
  if (activeIcon) {
    activeIcon.textContent = currentSortAsc ? "▲" : "▼";
  }

  currentAliases.sort((a, b) => {
    let valA = a[key];
    let valB = b[key];

    if (key === "expires_at") {
      if (valA === null && valB === null) return 0;
      if (valA === null) return currentSortAsc ? 1 : -1;
      if (valB === null) return currentSortAsc ? -1 : 1;
      const timeA = new Date(valA).getTime();
      const timeB = new Date(valB).getTime();
      return currentSortAsc ? timeA - timeB : timeB - timeA;
    }

    if (valA === null || valA === undefined) valA = "";
    if (valB === null || valB === undefined) valB = "";

    if (typeof valA === "string") valA = valA.toLowerCase();
    if (typeof valB === "string") valB = valB.toLowerCase();

    if (valA < valB) return currentSortAsc ? -1 : 1;
    if (valA > valB) return currentSortAsc ? 1 : -1;
    return 0;
  });

  filterTable();
}

function renderAliases(aliases, query = "") {
  const tbody = document.getElementById("vault-tbody");
  const mobileContainer = document.getElementById("vault-mobile-cards");
  const countBadge = document.getElementById("vault-count-badge");

  if (countBadge) {
    countBadge.textContent = `${aliases.length} ${aliases.length === 1 ? "entry" : "entries"}`;
  }

  if (tbody) {
    if (aliases.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="6" style="text-align: center; color: var(--text-dim); padding: 36px 16px;">
            <div style="font-size: 24px; margin-bottom: 8px;">🔍</div>
            <div style="font-weight: 600; color: var(--text-muted); font-size: 14px;">No matching identities found</div>
            <div style="font-size: 12px; margin-top: 4px;">Try adjusting your filters or generate a new alias on the left.</div>
          </td>
        </tr>
      `;
    } else {
      tbody.innerHTML = aliases
        .map((item) => {
          const tierBadge = `<span class="badge badge-tier-${item.tier}">${item.tier}</span>`;
          let statusBadge = `<span class="badge badge-${item.status.toLowerCase()}">${item.status}</span>`;
          let expiryText = item.expires_at ? new Date(item.expires_at).toLocaleDateString() : "Permanent";

          let actionBtns = `
            <div class="action-btn-group">
              <button class="action-icon-btn btn-copy" onclick="copyToClipboard('${escapeHtml(item.alias_email)}')" title="Copy Email">📋</button>
              <button class="action-icon-btn btn-qr" onclick="openAliasQrModal('${escapeHtml(item.alias_email)}')" title="Scan on Phone">📱</button>
              <button class="action-icon-btn btn-test" onclick="prefillSimulator('${escapeHtml(item.alias_email)}', '${escapeHtml(item.service_domain || "")}')" title="Test in Sandbox">🧪</button>
              ${
                item.status === "ACTIVE"
                  ? `<button class="btn btn-danger btn-sm" style="padding: 3px 8px; font-size: 11px;" onclick="handleRevoke('${escapeHtml(item.alias_email)}')">Kill Switch</button>`
                  : `<button class="btn btn-secondary btn-sm" style="font-size: 10px; padding: 2px 6px;" onclick="openGdprModal('${escapeHtml(item.alias_email)}')">⚖️ Notice</button>`
              }
            </div>
          `;

          return `
            <tr>
              <td>
                <div class="service-name-cell">${highlightSearch(item.service_name, query)}</div>
                ${item.service_domain ? `<div class="service-domain-sub">🌐 ${highlightSearch(item.service_domain, query)}</div>` : ""}
              </td>
              <td>${tierBadge}</td>
              <td>
                <div class="alias-pill" onclick="copyToClipboard('${escapeHtml(item.alias_email)}')" title="Click to copy relay address">
                  <span>${highlightSearch(item.alias_email, query)}</span>
                  <span class="alias-copy-icon">📋</span>
                </div>
                <div style="font-size: 10px; color: var(--text-dim); margin-top: 3px;">
                  ↳ forwards to: <code>${escapeHtml(item.target_forward_email)}</code>
                </div>
              </td>
              <td>${statusBadge}</td>
              <td style="font-size: 12px; color: var(--text-muted);">${expiryText}</td>
              <td style="text-align: right;">${actionBtns}</td>
            </tr>
          `;
        })
        .join("");
    }
  }

  // Render Smartphone Card Feed
  if (mobileContainer) {
    if (aliases.length === 0) {
      mobileContainer.innerHTML = `
        <div style="text-align: center; color: var(--text-dim); padding: 24px; font-size: 13px;">
          No identities registered yet. Tap <strong>New</strong> below to create your first protected alias.
        </div>
      `;
    } else {
      mobileContainer.innerHTML = aliases
        .map((item) => {
          const tierBadge = `<span class="badge badge-tier-${item.tier}">${item.tier}</span>`;
          const statusBadge = `<span class="badge badge-${item.status.toLowerCase()}">${item.status}</span>`;
          const expiryText = item.expires_at ? new Date(item.expires_at).toLocaleDateString() : "Permanent";
          const actionBtn =
            item.status === "ACTIVE"
              ? `<button class="btn btn-danger btn-sm" style="min-height:34px;padding:4px 10px;" onclick="handleRevoke('${escapeHtml(item.alias_email)}')">⚡ Kill</button>`
              : `<button class="btn btn-secondary btn-sm" style="font-size:11px;min-height:32px;padding:4px 8px;" onclick="openGdprModal('${escapeHtml(item.alias_email)}')">⚖️ GDPR</button>`;

          return `
            <div class="mobile-card">
              <div class="mobile-card-top">
                <div>
                  <div class="mobile-card-title">${highlightSearch(item.service_name, query)}</div>
                  ${item.service_domain ? `<div class="mobile-card-domain">${highlightSearch(item.service_domain, query)}</div>` : ""}
                </div>
                <div style="display:flex;gap:6px;align-items:center;">
                  ${tierBadge}
                  ${statusBadge}
                </div>
              </div>

              <div class="mobile-card-alias-box" onclick="copyToClipboard('${escapeHtml(item.alias_email)}')">
                <span class="mobile-card-alias-text">${highlightSearch(item.alias_email, query)}</span>
                <span class="mobile-card-copy-hint">📋 Copy</span>
              </div>

              <div class="mobile-card-bottom">
                <span style="font-size:11px;color:var(--text-dim);">${expiryText}</span>
                <div style="display:flex;gap:6px;align-items:center;">
                  <button class="action-icon-btn btn-qr" onclick="openAliasQrModal('${escapeHtml(item.alias_email)}')" title="Show QR Code">📱</button>
                  <button class="action-icon-btn btn-test" onclick="prefillSimulator('${escapeHtml(item.alias_email)}', '${escapeHtml(item.service_domain || "")}')" title="Test in Sandbox">🧪</button>
                  ${actionBtn}
                </div>
              </div>
            </div>
          `;
        })
        .join("");
    }
  }
}

function populateSimulatorAliasOptions(aliases) {
  const select = document.getElementById("sim-alias-select");
  if (!select) return;

  if (!aliases || aliases.length === 0) {
    select.innerHTML = `<option value="">No registered aliases found</option>`;
    return;
  }

  select.innerHTML = aliases
    .map((a) => {
      const isRevoked = a.status === "REVOKED";
      const label = isRevoked
        ? `⛔ ${escapeHtml(a.service_name)} (${escapeHtml(a.alias_email)}) [Revoked]`
        : `🛡️ ${escapeHtml(a.service_name)} (${escapeHtml(a.alias_email)})`;
      return `<option value="${escapeHtml(a.alias_email)}" data-service="${escapeHtml(a.service_name)}" data-domain="${escapeHtml(a.service_domain || "")}" data-status="${escapeHtml(a.status)}">
        ${label}
      </option>`;
    })
    .join("");
}

function populateIntelAliasOptions(aliases) {
  const select = document.getElementById("intel-alias-select");
  if (!select) return;

  if (!aliases || aliases.length === 0) {
    select.innerHTML = `<option value="">No registered aliases found</option>`;
    return;
  }

  select.innerHTML = aliases
    .map((a) => {
      const isRevoked = a.status === "REVOKED";
      const icon = isRevoked ? "⚠️" : (a.tier === "core" ? "🏛️" : (a.tier === "commercial" ? "💳" : "🎟️"));
      return `<option value="${escapeHtml(a.alias_email)}">
        ${icon} ${escapeHtml(a.service_name)} — ${escapeHtml(a.alias_email)}
      </option>`;
    })
    .join("");
}

async function handleThreatIntelScan() {
  const select = document.getElementById("intel-alias-select");
  const resultDiv = document.getElementById("intel-scan-result");
  const btn = document.getElementById("btn-run-intel-scan");
  if (!select || !select.value) {
    showToast("Please select an alias to scan", "warning");
    return;
  }

  const aliasEmail = select.value;
  if (btn) btn.disabled = true;
  if (resultDiv) {
    resultDiv.style.display = "block";
    resultDiv.innerHTML = `<div style="text-align:center;padding:12px;color:var(--accent-cyan);font-size:12px;">
      <span class="pulse-dot"></span> Scanning dark web dumps & data broker identity graphs...
    </div>`;
  }

  try {
    const res = await fetch("/api/threat-intel/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ alias_email: aliasEmail }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || "Scan failed");
    }

    const data = await res.json();
    const scoreColor = data.exposure_level === "CRITICAL" ? "var(--accent-rose)" : (data.exposure_level === "ELEVATED" ? "var(--accent-amber)" : "var(--accent-emerald)");
    const badgeBg = data.exposure_level === "CRITICAL" ? "rgba(244,63,94,0.15)" : (data.exposure_level === "ELEVATED" ? "rgba(245,158,11,0.15)" : "rgba(16,185,129,0.15)");

    const brokerList = data.matched_broker_networks.map(b => `
      <li style="margin-bottom:4px;display:flex;justify-content:space-between;align-items:center;">
        <span>🔍 <b>${escapeHtml(b.name)}</b> <span style="font-size:10px;color:var(--text-dim);">(${escapeHtml(b.vector)})</span></span>
        <span class="badge" style="font-size:9px;background:rgba(255,255,255,0.08);">${escapeHtml(b.risk)}</span>
      </li>
    `).join("");

    resultDiv.innerHTML = `
      <div style="background:rgba(0,0,0,0.4);border:1px solid ${scoreColor};border-radius:6px;padding:12px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
          <span style="font-size:12px;font-weight:700;color:var(--text-main);">Exposure Threat Level:</span>
          <span class="badge" style="background:${badgeBg};color:${scoreColor};border:1px solid ${scoreColor};font-weight:700;">
            ${escapeHtml(data.exposure_level)} (${data.exposure_score}%)
          </span>
        </div>
        <p style="font-size:11px;color:var(--text-muted);margin-bottom:8px;">
          <b>Target:</b> <code>${escapeHtml(data.alias_email)}</code> (${escapeHtml(data.service_name)})
        </p>
        <div style="font-size:11px;color:var(--text-dim);margin-bottom:8px;">
          <b>Correlated Broker Networks (${data.matched_broker_networks.length}):</b>
          <ul style="list-style:none;padding-left:0;margin-top:4px;">
            ${brokerList}
          </ul>
        </div>
        <div style="font-size:11px;padding:6px 8px;border-radius:4px;background:rgba(255,255,255,0.03);color:var(--text-muted);margin-bottom:10px;">
          💡 <b>Action Plan:</b> ${escapeHtml(data.recommendation)}
        </div>
        <div style="display:flex;gap:6px;flex-wrap:wrap;">
          <button class="btn btn-sm btn-secondary" style="font-size:11px;padding:4px 8px;" onclick="openGdprModal('${escapeHtml(data.alias_email)}')">
            ⚖️ Dispatch GDPR Art. 17 Notice
          </button>
          ${data.status === "ACTIVE" ? `
            <button class="btn btn-sm btn-danger" style="font-size:11px;padding:4px 8px;" onclick="handleRevoke('${escapeHtml(data.alias_email)}')">
              ⚡ Emergency Kill-Switch
            </button>
          ` : ""}
        </div>
      </div>
    `;

    logSocEvent(
      data.exposure_level === "CRITICAL" ? "danger" : "info",
      "INTEL_SCAN",
      `Threat Intel Scan for <code>${escapeHtml(data.alias_email)}</code>: <b>${escapeHtml(data.exposure_level)}</b> (${data.exposure_score}% exposure).`
    );
  } catch (err) {
    resultDiv.innerHTML = `<div style="color:var(--accent-rose);font-size:12px;padding:8px;">Scan error: ${escapeHtml(err.message)}</div>`;
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function handlePpidProofLab() {
  const emailInput = document.getElementById("ppid-lab-email");
  const resultDiv = document.getElementById("ppid-lab-result");
  const email = (emailInput && emailInput.value.trim()) || "jane.doe@personal.me";

  if (resultDiv) {
    resultDiv.style.display = "block";
    resultDiv.innerHTML = `<span class="pulse-dot"></span> Computing Double-Salted Blinded Hashes & Orthogonal PPIDs...`;
  }

  try {
    const res = await fetch("/api/crypto/ppid-proof", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: email }),
    });
    const data = await res.json();

    resultDiv.innerHTML = `
      <div style="color:var(--accent-cyan);margin-bottom:6px;"><b>✓ MATHEMATICAL ZERO-KNOWLEDGE PROOF GENERATED</b></div>
      <div style="margin-bottom:4px;"><b>Original PII:</b> <span style="color:var(--text-main);">${escapeHtml(data.canonical_email)}</span></div>
      <div style="margin-bottom:4px;"><b>Blinded Hash:</b> <span style="color:var(--accent-purple);word-break:break-all;">${escapeHtml(data.blinded_hash)}</span></div>
      <div style="margin-bottom:4px;"><b>Account UUID:</b> <span style="color:var(--text-muted);">${escapeHtml(data.account_uuid)}</span></div>
      <hr style="border-color:rgba(255,255,255,0.08);margin:8px 0;">
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:8px;">
        <div style="background:rgba(0,229,255,0.04);padding:6px;border-radius:4px;border:1px solid rgba(0,229,255,0.2);">
          <b>${escapeHtml(data.client_a.name)}:</b><br>
          <code style="color:var(--accent-cyan);font-size:10px;">${escapeHtml(data.client_a.ppid)}</code>
        </div>
        <div style="background:rgba(139,92,246,0.04);padding:6px;border-radius:4px;border:1px solid rgba(139,92,246,0.2);">
          <b>${escapeHtml(data.client_b.name)}:</b><br>
          <code style="color:var(--accent-purple);font-size:10px;">${escapeHtml(data.client_b.ppid)}</code>
        </div>
      </div>
      <div style="color:var(--accent-emerald);font-size:11px;">
        🛡️ <b>Collusion Linkable:</b> ${data.collusion_linkable ? "YES (FAILED)" : "NO (100% UNLINKABLE)"}<br>
        <span style="color:var(--text-dim);">${escapeHtml(data.mathematical_guarantee)}</span>
      </div>
    `;
    logSocEvent("info", "CRYPTO_LAB", `PPID Orthogonal proof computed for <code>${escapeHtml(email)}</code>.`);
  } catch (err) {
    if (resultDiv) {
      resultDiv.innerHTML = `<span style="color:var(--accent-rose);">Error computing proof: ${escapeHtml(err.message)}</span>`;
    }
  }
}

async function handleGenerate(e) {
  e.preventDefault();
  const serviceName = document.getElementById("gen-service").value.trim();
  const serviceDomain = document.getElementById("gen-domain").value.trim() || null;
  const tier = document.getElementById("gen-tier").value;
  const targetEmail = document.getElementById("gen-target").value.trim() || "user@example.com";
  const ttlDays = document.getElementById("gen-ttl").value || null;

  if (!serviceName) {
    showToast("Please provide a service name", "warning");
    return;
  }

  try {
    const res = await fetch("/api/aliases", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        service_name: serviceName,
        service_domain: serviceDomain,
        tier: tier,
        target_forward_email: targetEmail,
        ttl_days: ttlDays ? parseInt(ttlDays, 10) : null,
      }),
    });

    if (!res.ok) {
      const errData = await res.json();
      throw new Error(errData.error || "Failed to create alias");
    }

    const newAlias = await res.json();
    showToast(`Protected alias generated for ${serviceName}`, "success");
    logSocEvent("success", "HMAC_GEN", `Generated alias <code>${escapeHtml(newAlias.alias_email)}</code> for <strong>${escapeHtml(serviceName)}</strong>`);

    // Reset fields
    document.getElementById("gen-service").value = "";
    document.getElementById("gen-domain").value = "";

    await loadStats();
    await loadAliases();
  } catch (err) {
    showToast(err.message, "danger");
  }
}

async function handleRevoke(aliasEmail) {
  if (!confirm(`Trigger kill-switch for ${aliasEmail}? Forwarding will be permanently stopped.`)) {
    return;
  }

  try {
    const res = await fetch(`/api/aliases/${encodeURIComponent(aliasEmail)}/revoke`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason: "KILL_SWITCH_WEB_DASHBOARD" }),
    });

    if (!res.ok) {
      const errData = await res.json();
      throw new Error(errData.error || "Failed to revoke");
    }

    showToast(`Kill switch activated for ${aliasEmail}`, "warning");
    logSocEvent("warning", "KILL_SWITCH", `Terminated routing bridge for <code>${escapeHtml(aliasEmail)}</code>`);
    await loadStats();
    await loadAliases();
  } catch (err) {
    showToast(err.message, "danger");
  }
}

async function handleResetDemo() {
  if (!confirm("Reset Identity Vault to clean demonstration state?\n\nThis will restore realistic identities across all 3 tiers and fresh audit logs.")) {
    return;
  }

  try {
    const res = await fetch("/api/reset-demo", { method: "POST" });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || "Reset failed");
    }

    showToast("Vault reset to fresh demonstration state!", "success");
    logSocEvent("info", "BOOT", "Demonstration vault state restored across Core, Commercial, and Ephemeral pods.");
    await loadStats();
    await loadAliases();
    await loadAuditLogs();
  } catch (err) {
    showToast("Failed to reset: " + err.message, "danger");
  }
}

async function handleSimulateTrace(e) {
  e.preventDefault();
  const aliasSelect = document.getElementById("sim-alias-select");
  const senderEmail = document.getElementById("sim-sender-email").value.trim();
  const autoRevoke = document.getElementById("sim-auto-revoke").checked;
  const resultBox = document.getElementById("sim-result");

  if (!aliasSelect.value || !senderEmail) {
    showToast("Select an alias and enter a test sender email", "warning");
    return;
  }

  try {
    const res = await fetch("/api/trace", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        alias_email: aliasSelect.value,
        sender_email: senderEmail,
        auto_revoke: autoRevoke,
      }),
    });

    const data = await res.json();
    resultBox.className = "sim-result";

    if (data.verdict === "FORWARD_ALLOWED") {
      resultBox.classList.add("success");
      resultBox.innerHTML = `
        <strong>✓ AUTHORIZED SENDER MATCH</strong>
        <p style="margin-top: 4px;">Inbound email from <code>${escapeHtml(senderEmail)}</code> matches registered service <strong>${escapeHtml(data.service)}</strong>.</p>
        <p style="font-size: 11px; margin-top: 4px; color: var(--text-dim);">Safe to forward to: ${escapeHtml(data.forward_to)}</p>
      `;
      logSocEvent("info", "RELAY_OK", `Inbound verified: <strong>${escapeHtml(senderEmail)}</strong> authorized for ${escapeHtml(data.service)}`);
    } else if (data.verdict === "POTENTIAL_LEAK_OR_RESALE") {
      resultBox.classList.add("danger");
      resultBox.innerHTML = `
        <strong>🚨 DATA LEAK OR BROKER RESELL DETECTED!</strong>
        <p style="margin-top: 4px;">Sender <code>${escapeHtml(data.sender)}</code> is not correlated with registered service <strong>${escapeHtml(data.registered_service)}</strong>.</p>
        <p style="font-size: 11px; margin-top: 6px;">Status: <strong>${data.forwarding_action === "KILLED" ? "Kill-switch triggered automatically. Address revoked." : "Flagged for user review."}</strong></p>
      `;
      logSocEvent("danger", "LEAK_BLOCKED", `Data broker leak from <strong>${escapeHtml(senderEmail)}</strong> blocked! ${data.forwarding_action === "KILLED" ? "Kill-switch activated." : ""}`);
      updateTopologyGraph(currentAliases, true);
    } else {
      resultBox.classList.add("warning");
      resultBox.innerHTML = `
        <strong>⚠️ NOTICE: ${escapeHtml(data.verdict)}</strong>
        <p style="margin-top: 4px;">${escapeHtml(data.message)}</p>
      `;
      logSocEvent("warning", "NOTICE", escapeHtml(data.message));
    }

    await loadStats();
    await loadAliases();
  } catch (err) {
    showToast(err.message, "danger");
  }
}

function filterTable() {
  const rawSearch = document.getElementById("vault-search").value || "";
  const searchTerm = rawSearch.toLowerCase();
  const tierTerm = document.getElementById("filter-tier").value;
  const statusTerm = document.getElementById("filter-status").value;

  const filtered = currentAliases.filter((a) => {
    const matchesSearch =
      a.service_name.toLowerCase().includes(searchTerm) ||
      a.alias_email.toLowerCase().includes(searchTerm) ||
      (a.service_domain && a.service_domain.toLowerCase().includes(searchTerm));
    const matchesTier = !tierTerm || a.tier === tierTerm;
    const matchesStatus = !statusTerm || a.status === statusTerm;
    return matchesSearch && matchesTier && matchesStatus;
  });

  renderAliases(filtered, rawSearch.trim());
}

function copyToClipboard(text) {
  if (navigator.vibrate) {
    navigator.vibrate(40);
  }

  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(
      () => showToast("Copied to clipboard!", "success"),
      () => {
        if (fallbackCopyTextToClipboard(text)) {
          showToast("Copied to clipboard!", "success");
        } else {
          showToast("Could not copy to clipboard", "danger");
        }
      }
    );
  } else {
    if (fallbackCopyTextToClipboard(text)) {
      showToast("Copied to clipboard!", "success");
    } else {
      showToast("Could not copy to clipboard", "danger");
    }
  }
}

// QR Code Smartphone Pairing Modal
function openQrModal() {
  const modal = document.getElementById("qr-modal");
  const container = document.getElementById("qr-container");
  if (!modal) return;

  const targetUrl = detectedNetworkUrl || window.location.href;
  if (container && window.IdentityShieldQR) {
    IdentityShieldQR.render(targetUrl, container, 180);
  }

  modal.classList.remove("hidden");
}

function closeQrModal(e) {
  if (e && e.target !== e.currentTarget && !e.target.classList.contains("modal-close-btn") && !e.target.closest(".modal-close-btn")) {
    return;
  }
  const modal = document.getElementById("qr-modal");
  if (modal) {
    modal.classList.add("hidden");
  }
}

// GDPR Article 17 Erasure Notice Modal
function openGdprModal(aliasEmail) {
  const modal = document.getElementById("gdpr-modal");
  const preview = document.getElementById("gdpr-letter-text");
  if (!modal) return;

  const aliasData = currentAliases.find((a) => a.alias_email === aliasEmail);
  const serviceName = aliasData ? aliasData.service_name : "Service Provider";
  const serviceDomain = aliasData && aliasData.service_domain ? aliasData.service_domain : "[Data Controller]";
  const today = new Date().toISOString().split("T")[0];

  const notice = 
`Subject: Formal Data Erasure Request (GDPR Art. 17 / CCPA) — Identity Shield Alias [${aliasEmail}]

To: Data Protection Officer / Privacy Compliance (${serviceDomain})
Date: ${today}

Dear Privacy Officer / Compliance Team for ${serviceName},

I am writing to formally exercise my right to erasure (Right to be Forgotten) pursuant to Article 17 of the General Data Protection Regulation (EU GDPR 2016/679), California Consumer Privacy Act (CCPA/CPRA § 1798.105), and applicable data protection regulations.

1. SPECIFIC IDENTIFIER TO BE PURGED:
   - Account / Sign-up Email: ${aliasEmail}
   - Designating Entity: ${serviceName}

2. STATUTORY DEMANDS:
   a) Immediately and permanently erase all personal records, account profiles, behavioral logs, device fingerprints, and interaction records linked with "${aliasEmail}" across all production environments, cold storage, and backup systems.
   b) In accordance with GDPR Art. 17(2), notify any third-party processors, ad exchanges, affiliate networks, or marketing brokers with whom this email was shared or sold to synchronously delete all records.
   c) Provide formal written confirmation within thirty (30) calendar days verifying that erasure has been executed.

NOTE: The cryptographic inbound relay channel for "${aliasEmail}" has been terminated via Identity Shield Kill-Switch. Any subsequent unsolicited communications received at this vector will serve as documented evidence of unlawful processing and will be escalated to national data protection authorities.

Sincerely,
Authorized Privacy Holder of Identity: ${aliasEmail}`;

  if (preview) {
    preview.value = notice;
  }

  modal.classList.remove("hidden");
}

function closeGdprModal(e) {
  if (e && e.target !== e.currentTarget && !e.target.classList.contains("modal-close-btn") && !e.target.closest(".modal-close-btn")) {
    return;
  }
  const modal = document.getElementById("gdpr-modal");
  if (modal) {
    modal.classList.add("hidden");
  }
}

function copyGdprNotice() {
  const preview = document.getElementById("gdpr-letter-text");
  if (!preview) return;
  copyToClipboard(preview.value);
  showToast("GDPR Article 17 Notice copied to clipboard!", "success");
}

function switchMobileTab(sectionId, btnElement) {
  if (navigator.vibrate) {
    navigator.vibrate(25);
  }

  // Update active state on bottom navigation
  document.querySelectorAll(".mobile-nav-item").forEach((b) => b.classList.remove("active"));
  if (btnElement) {
    btnElement.classList.add("active");
  }

  // Smooth scroll to the target card
  const target = document.getElementById(sectionId);
  if (target) {
    const yOffset = -20;
    const y = target.getBoundingClientRect().top + window.pageYOffset + yOffset;
    window.scrollTo({ top: y, behavior: "smooth" });
  }
}

function showToast(message, type = "info") {
  let container = document.getElementById("toast-container");
  if (!container) {
    container = document.createElement("div");
    container.id = "toast-container";
    container.className = "toast-container";
    document.body.appendChild(container);
  }

  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  container.appendChild(toast);

  setTimeout(() => {
    toast.remove();
  }, 3500);
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Search Highlighting
function highlightSearch(text, query) {
  if (!text) return "";
  if (!query || !query.trim()) return escapeHtml(text);

  const q = query.trim();
  const lowerText = text.toLowerCase();
  const lowerQuery = q.toLowerCase();

  let result = "";
  let startIndex = 0;
  let matchIndex;

  while ((matchIndex = lowerText.indexOf(lowerQuery, startIndex)) !== -1) {
    result += escapeHtml(text.slice(startIndex, matchIndex));
    result += `<mark class="search-highlight">${escapeHtml(text.slice(matchIndex, matchIndex + q.length))}</mark>`;
    startIndex = matchIndex + q.length;
  }
  result += escapeHtml(text.slice(startIndex));
  return result;
}

// Interactive Topology Visualizer
function updateTopologyGraph(aliases, simulatedBreach = false) {
  const brokerNode = document.getElementById("topo-rogue-broker");
  const brokerLink = document.getElementById("topo-link-broker");

  if (brokerNode) {
    if (simulatedBreach) {
      brokerNode.style.filter = "drop-shadow(0 0 14px var(--accent-rose))";
      if (brokerLink) brokerLink.classList.add("blocked");
      setTimeout(() => {
        brokerNode.style.filter = "";
      }, 5000);
    }
  }
}

// SOC Live Event Stream Logger
function logSocEvent(type, tag, message) {
  const feed = document.getElementById("soc-event-feed");
  if (!feed) return;

  const now = new Date();
  const timeStr = now.toTimeString().split(" ")[0];

  const tagClassMap = {
    info: "tag-cyan",
    success: "tag-emerald",
    warning: "tag-amber",
    danger: "tag-rose",
  };

  const tagClass = tagClassMap[type] || "tag-cyan";

  const item = document.createElement("div");
  item.className = `soc-item soc-${type}`;
  item.innerHTML = `
    <span class="soc-timestamp">${timeStr}</span>
    <span class="soc-tag ${tagClass}">${escapeHtml(tag)}</span>
    <div class="soc-text">${message}</div>
  `;

  feed.prepend(item);

  // Cap at 25 events
  while (feed.children.length > 25) {
    feed.removeChild(feed.lastChild);
  }
}

// Hydrate historical audit logs from backend
async function loadAuditLogs() {
  try {
    const res = await fetch("/api/logs?limit=15");
    if (!res.ok) return;
    const logs = await res.json();
    if (!Array.isArray(logs) || logs.length === 0) return;

    const feed = document.getElementById("soc-event-feed");
    if (!feed) return;

    feed.innerHTML = "";

    logs.forEach((log) => {
      let type = "info";
      let tag = log.event_type || "LOG";
      if (tag === "LEAK_DETECTED") {
        type = "danger";
        tag = "LEAK_BLOCKED";
      } else if (tag === "REVOKED") {
        type = "warning";
        tag = "KILL_SWITCH";
      } else if (tag === "GENERATED") {
        type = "success";
        tag = "HMAC_GEN";
      } else if (tag === "INBOUND_AUTHORIZED") {
        type = "info";
        tag = "RELAY_OK";
      }

      const timeStr = log.timestamp ? new Date(log.timestamp).toTimeString().split(" ")[0] : "LOG";
      const tagClassMap = {
        info: "tag-cyan",
        success: "tag-emerald",
        warning: "tag-amber",
        danger: "tag-rose",
      };

      const item = document.createElement("div");
      item.className = `soc-item soc-${type}`;
      item.innerHTML = `
        <span class="soc-timestamp">${timeStr}</span>
        <span class="soc-tag ${tagClassMap[type] || 'tag-cyan'}">${escapeHtml(tag)}</span>
        <div class="soc-text">${escapeHtml(log.details || log.event_type)}</div>
      `;
      feed.appendChild(item);
    });
  } catch (err) {
    console.debug("Historical audit log hydration skipped:", err);
  }
}

// Leak Simulator Fast Pre-fill
function prefillSimulator(aliasEmail, domain = "") {
  const select = document.getElementById("sim-alias-select");
  const senderInput = document.getElementById("sim-sender-email");
  if (select) {
    select.value = aliasEmail;
  }
  if (senderInput) {
    const testDomain = domain || "unsolicited-broker.net";
    senderInput.value = `promotions@${testDomain}`;
    senderInput.focus();
  }
  const simCard = document.getElementById("section-simulator");
  if (simCard) {
    const yOffset = -20;
    const y = simCard.getBoundingClientRect().top + window.pageYOffset + yOffset;
    window.scrollTo({ top: y, behavior: "smooth" });
  }
  showToast(`Pre-filled ${aliasEmail} in Leak Simulator`, "info");
}

// Individual Alias QR Code Modal
let activeModalAlias = "";

function openAliasQrModal(aliasEmail) {
  const modal = document.getElementById("alias-qr-modal");
  const container = document.getElementById("alias-qr-container");
  const title = document.getElementById("alias-qr-title");
  if (!modal) return;

  activeModalAlias = aliasEmail;
  if (title) {
    title.textContent = `📱 Scan Alias: ${aliasEmail}`;
  }

  if (container && window.IdentityShieldQR) {
    IdentityShieldQR.render(aliasEmail, container, 180);
  }

  modal.classList.remove("hidden");
}

function closeAliasQrModal(e) {
  if (e && e.target !== e.currentTarget && !e.target.classList.contains("modal-close-btn") && !e.target.closest(".modal-close-btn")) {
    return;
  }
  const modal = document.getElementById("alias-qr-modal");
  if (modal) {
    modal.classList.add("hidden");
  }
}

function copyActiveAliasFromModal() {
  if (!activeModalAlias) return;
  copyToClipboard(activeModalAlias);
  showToast(`Copied ${activeModalAlias} to clipboard!`, "success");
}

// Reset Demo State (Parity with Node & Python)
async function handleResetDemo() {
  if (!confirm("Are you sure you want to reset all identities to the fresh demonstration state?")) return;
  try {
    const res = await fetch("/api/reset-demo", { method: "POST" });
    if (!res.ok) throw new Error("Reset request failed");
    showToast("Vault reset to fresh demonstration state", "success");
    await loadStats();
    await loadAliases();
    await loadAuditLogs();
  } catch (err) {
    showToast(`Reset error: ${err.message}`, "danger");
  }
}

// Manual Purge Expired Identities
async function handlePurgeExpired() {
  try {
    const res = await fetch("/api/purge-expired", { method: "POST" });
    if (!res.ok) throw new Error("Purge request failed");
    const data = await res.json();
    showToast(`Purged ${data.purged_count} overdue identities`, "info");
    await loadStats();
    await loadAliases();
    await loadAuditLogs();
  } catch (err) {
    showToast(`Purge error: ${err.message}`, "danger");
  }
}
