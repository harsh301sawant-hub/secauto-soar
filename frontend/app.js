let incidents = [];
let selectedIncident = null;
let map = null;
let currentMarker = null;

// Initialize Live Attack Map via Leaflet
function initMap() {
  if (map) return;
  map = L.map('attack-map', {
    center: [20.5937, 78.9629], // Default center on India
    zoom: 4,
    zoomControl: false,
    attributionControl: false
  });

  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    maxZoom: 18,
  }).addTo(map);
}

function updateMapMarker(lat, lon, title, originText) {
  if (!map) initMap();
  if (!lat || !lon) return;

  if (currentMarker) {
    map.removeLayer(currentMarker);
  }

  const redIcon = L.divIcon({
    className: 'custom-pin',
    html: `<div class="w-4 h-4 bg-red-500 rounded-full border-2 border-white shadow-lg animate-ping"></div><div class="w-3 h-3 bg-red-600 rounded-full border-2 border-white -mt-3.5 ml-0.5"></div>`,
    iconSize: [16, 16]
  });

  currentMarker = L.marker([lat, lon], { icon: redIcon }).addTo(map);
  map.flyTo([lat, lon], 7, { duration: 1.5 });
  
  currentMarker.bindPopup(`
    <div style="color: #0b0f19; font-size: 11px; font-weight: bold;">
      <div>🎯 ${title}</div>
      <div style="color: #0369a1;">Location: ${originText}</div>
    </div>
  `).openPopup();
}

// Fetch who opened the URL right on page load!
async function detectVisitorIdentity() {
  try {
    const res = await fetch('/api/whoami');
    const me = await res.json();
    
    appendLog("VISITOR", `Client detected: ${me.ip} (${me.city}, ${me.country}) - ISP: ${me.isp}`);
    document.getElementById('map-target-status').textContent = `Your Live IP: ${me.ip} • ${me.city}, ${me.country}`;
    
    // Center map on the actual visitor right away!
    if (me.lat && me.lon) {
      updateMapMarker(me.lat, me.lon, "Your Live Connection", `${me.city}, ${me.country} (${me.isp})`);
    }
  } catch (e) {
    console.error("Could not fetch visitor identity:", e);
  }
}

// WebSocket telemetry
function initWebSocket() {
  try {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const host = window.location.host || "127.0.0.1:8000";
    const wsUrl = `${protocol}//${host}/ws`;
    const socket = new WebSocket(wsUrl);

    socket.onopen = () => {
      appendLog("SYSTEM", "WebSocket connected. Real-time IP tracker active.");
    };

    socket.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === "NEW_INCIDENT") {
          handleNewIncident(data.incident);
        } else if (data.type === "PLAYBOOK_EXECUTED") {
          handlePlaybookExecuted(data.result);
        }
      } catch (e) {
        console.error("WS Parse error:", e);
      }
    };

    socket.onclose = () => {
      setTimeout(initWebSocket, 3000);
    };
  } catch (err) {
    console.error("WS Init error:", err);
  }
}

async function loadData() {
  try {
    const [incRes, blockRes] = await Promise.all([
      fetch('/api/incidents'),
      fetch('/api/blocked-ips')
    ]);
    
    if (!incRes.ok || !blockRes.ok) return;

    incidents = await incRes.json();
    const blocks = await blockRes.json();

    document.getElementById('metric-total').textContent = incidents.length;
    document.getElementById('metric-blocked').textContent = blocks.length;
    document.getElementById('metric-active').textContent = incidents.filter(i => i.status === 'ACTIVE').length;

    renderIncidentList();

    if (incidents.length > 0 && !selectedIncident) {
      selectIncident(incidents[0].incident_id);
    }
  } catch (err) {
    console.error("Error loading data:", err);
  }
}

function renderIncidentList() {
  const container = document.getElementById('incident-container');
  if (!container) return;

  document.getElementById('incident-counter').textContent = `${incidents.length} events`;

  if (incidents.length === 0) {
    container.innerHTML = `
      <div class="card-panel p-5 rounded-xl text-center text-gray-500 text-xs py-12">
        <i class="fa-solid fa-shield-cat text-3xl mb-3 text-gray-600"></i>
        <p>No active incidents detected yet. Test an attack above!</p>
      </div>`;
    return;
  }

  container.innerHTML = incidents.map(inc => {
    const isCrit = inc.severity === 'CRITICAL';
    const isMitigated = inc.status === 'MITIGATED';
    const badgeColor = isCrit ? 'text-red-400 bg-red-500/10 border-red-500/20' : 'text-amber-400 bg-amber-500/10 border-amber-500/20';
    const isSelected = selectedIncident && selectedIncident.incident_id === inc.incident_id;

    return `
      <div onclick="selectIncident('${inc.incident_id}')" class="card-panel p-4 rounded-xl cursor-pointer hover:border-blue-500/50 transition border ${isSelected ? 'border-blue-500 bg-gray-900/50' : 'border-gray-800'}">
        <div class="flex justify-between items-start mb-1.5">
          <span class="text-[10px] font-bold px-2 py-0.5 rounded border ${badgeColor}">${inc.severity}</span>
          <span class="text-[10px] ${isMitigated ? 'text-emerald-400 font-semibold' : 'text-amber-400 font-semibold'}">${inc.status}</span>
        </div>
        <h4 class="text-xs font-bold text-white mb-1">${inc.attack_type}</h4>
        <p class="text-[11px] text-gray-400 font-mono truncate mb-2">Real IP: ${inc.source_ip} • Target: ${inc.target_user}</p>
        <div class="text-[10px] text-gray-500 flex justify-between">
          <span>${inc.incident_id}</span>
          <span class="text-blue-400">View Geolocation →</span>
        </div>
      </div>
    `;
  }).join('');
}

async function selectIncident(id) {
  const inc = incidents.find(i => i.incident_id === id);
  if (!inc) return;

  selectedIncident = inc;
  renderIncidentList();

  const isCrit = inc.severity === 'CRITICAL';
  document.getElementById('active-badge').textContent = inc.severity;
  document.getElementById('active-badge').className = `text-xs font-bold px-2.5 py-0.5 rounded border ${isCrit ? 'text-red-400 bg-red-500/10 border-red-500/20' : 'text-amber-400 bg-amber-500/10 border-amber-500/20'}`;
  
  document.getElementById('active-title').textContent = `${inc.incident_id}: ${inc.attack_type}`;
  document.getElementById('active-desc').textContent = inc.details;
  document.getElementById('active-user').textContent = inc.target_user;

  try {
    const res = await fetch(`/api/intel/${inc.source_ip}`);
    const intel = await res.json();
    document.getElementById('intel-actor').textContent = intel.isp;
    document.getElementById('intel-origin').textContent = `${intel.city}, ${intel.country} (${intel.country_code})`;
    document.getElementById('intel-abuse').textContent = `IP: ${intel.ip}`;

    updateMapMarker(intel.lat, intel.lon, inc.attack_type, `${intel.city}, ${intel.country} (${intel.isp})`);
    document.getElementById('map-target-status').textContent = `Target: ${intel.city}, ${intel.country} • Lat: ${intel.lat.toFixed(2)}, Lon: ${intel.lon.toFixed(2)}`;
  } catch (e) {
    console.error(e);
  }

  const btn = document.getElementById('btn-remediate');
  if (inc.status === 'MITIGATED') {
    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-circle-check"></i> Already Mitigated`;
    btn.className = "px-4 py-2 bg-gray-800 text-gray-500 rounded-lg text-xs font-bold cursor-not-allowed";
    setPipelineResolved();
  } else {
    btn.disabled = false;
    btn.innerHTML = `<i class="fa-solid fa-play"></i> Block Real IP & Mitigate`;
    btn.className = "px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-bold flex items-center gap-2 shadow-lg transition";
    resetPipeline();
  }
}

function handleNewIncident(inc) {
  incidents.unshift(inc);
  document.getElementById('metric-total').textContent = incidents.length;
  document.getElementById('metric-active').textContent = incidents.filter(i => i.status === 'ACTIVE').length;
  
  appendLog("ALERT", `[${inc.severity}] ${inc.attack_type} detected from ${inc.source_ip}! Incident: ${inc.incident_id}`);
  renderIncidentList();
  selectIncident(inc.incident_id);
}

function handlePlaybookExecuted(result) {
  const inc = incidents.find(i => i.incident_id === result.incident_id);
  if (inc) {
    inc.status = 'MITIGATED';
    document.getElementById('metric-active').textContent = incidents.filter(i => i.status === 'ACTIVE').length;
  }
  animatePipelineSteps(result.steps_executed);
}

function resetPipeline() {
  for (let i = 1; i <= 5; i++) {
    const el = document.getElementById(`step-${i}`);
    if (el) el.className = "p-3 rounded-lg bg-gray-900 border border-gray-800";
    const icon = document.getElementById(`step-icon-${i}`);
    if (icon) icon.className = "fa-solid fa-clock text-gray-600";
  }
}

function setPipelineResolved() {
  for (let i = 1; i <= 5; i++) {
    const el = document.getElementById(`step-${i}`);
    if (el) el.className = "p-3 rounded-lg bg-gray-900 border border-emerald-500/50";
    const icon = document.getElementById(`step-icon-${i}`);
    if (icon) icon.className = "fa-solid fa-circle-check text-emerald-400";
  }
}

function animatePipelineSteps(steps) {
  steps.forEach((step, idx) => {
    setTimeout(() => {
      const stepIndex = idx + 1;
      const el = document.getElementById(`step-${stepIndex}`);
      const icon = document.getElementById(`step-icon-${stepIndex}`);
      if (el) el.className = "p-3 rounded-lg bg-gray-900 border border-emerald-500/60 shadow-lg shadow-emerald-900/20";
      if (icon) icon.className = "fa-solid fa-circle-check text-emerald-400";
      appendLog("PLAYBOOK", `Step ${stepIndex} [${step.step}]: ${step.detail}`);
      
      if (stepIndex === steps.length) {
        if (selectedIncident) selectIncident(selectedIncident.incident_id);
        loadData();
      }
    }, (idx + 1) * 350);
  });
}

async function triggerActivePlaybook() {
  if (!selectedIncident || selectedIncident.status === 'MITIGATED') return;

  const btn = document.getElementById('btn-remediate');
  btn.disabled = true;
  btn.innerHTML = `<i class="fa-solid fa-spinner animate-spin"></i> Executing Steps...`;

  try {
    const res = await fetch('/api/playbook/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        incident_id: selectedIncident.incident_id,
        playbook_name: selectedIncident.auto_playbook || 'Playbook_AutoDefense.yaml',
        source_ip: selectedIncident.source_ip,
        target_user: selectedIncident.target_user
      })
    });
    const result = await res.json();
    handlePlaybookExecuted(result);
  } catch (err) {
    console.error(err);
  }
}

async function openReportModal() {
  if (!selectedIncident) {
    alert("Select an incident from the stream first!");
    return;
  }

  try {
    const res = await fetch('/api/report/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ incident_id: selectedIncident.incident_id })
    });
    const rep = await res.json();

    document.getElementById('report-modal-id').textContent = `Incident ID: ${rep.incident_id} • Severity: ${rep.threat_severity}`;
    document.getElementById('rep-cvss').textContent = `CVSS v3: ${rep.cvss_v3_score}`;
    document.getElementById('rep-tactic').textContent = `MITRE Tactic: ${rep.mitre_alignment.tactic}`;
    document.getElementById('rep-technique').textContent = `Technique: ${rep.mitre_alignment.technique}`;

    document.getElementById('rep-actor').textContent = rep.adversary_attribution.isp_asn;
    document.getElementById('rep-origin').textContent = `${rep.adversary_attribution.origin_city}, ${rep.adversary_attribution.source_country}`;

    document.getElementById('rep-target').textContent = rep.target_impact.affected_entity;
    document.getElementById('rep-abuse').textContent = `Attacker Real IP: ${selectedIncident.source_ip}`;

    document.getElementById('rep-actions').innerHTML = rep.recommended_containment.map(a => `<li>${a}</li>`).join('');

    document.getElementById('report-modal').classList.remove('hidden');
  } catch (e) {
    console.error(e);
  }
}

function closeReportModal() {
  document.getElementById('report-modal').classList.add('hidden');
}

// In-browser simulation: uses the ACTUAL user's connection IP!
async function simulateBruteForce() {
  appendLog("DEMO", "Testing brute-force attack from YOUR REAL IP connection...");

  for (let i = 1; i <= 4; i++) {
    appendLog("ATTACK", `Attempt ${i}: Sending invalid credentials...`);
    try {
      const res = await fetch('/api/simulate/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: "ciso@target-enterprise.com",
          password: `wrong_pass_${i}`
        })
      });
      const data = await res.json();
      if (data.status === "BLOCKED") {
        appendLog("BLOCKED", `Firewall Rejected: ${data.message}`);
        break;
      }
    } catch (e) {
      console.error(e);
    }
    await new Promise(r => setTimeout(r, 200));
  }
}

async function testPhishingModal() {
  const url = prompt("Enter a URL to test for Phishing / Threat Indicators:", "https://secure-login-paypal.verify-account.cc/billing");
  if (!url) return;

  appendLog("SCAN", `Scanning URL: ${url}`);
  try {
    const res = await fetch('/api/scan/phishing', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    const data = await res.json();
    alert(`Analysis Result:\n\nVerdict: ${data.verdict}\nRisk Score: ${data.risk_score}/100\n\nReasons:\n- ${data.reasons.join('\n- ')}`);
    appendLog("SCAN_RESULT", `URL flagged as [${data.verdict}] (Score: ${data.risk_score}/100)`);
  } catch (e) {
    console.error(e);
  }
}

function appendLog(tag, msg) {
  const consoleEl = document.getElementById('console-logs');
  if (!consoleEl) return;

  const time = new Date().toTimeString().split(' ')[0];
  const colors = {
    SYSTEM: 'text-gray-400',
    VISITOR: 'text-emerald-400 font-bold',
    ALERT: 'text-red-400 font-bold',
    PLAYBOOK: 'text-cyan-400',
    ATTACK: 'text-amber-400',
    BLOCKED: 'text-red-500 font-bold',
    DEMO: 'text-purple-400',
    SCAN: 'text-blue-400',
    SCAN_RESULT: 'text-cyan-400 font-semibold'
  };
  const color = colors[tag] || 'text-gray-300';
  
  consoleEl.innerHTML += `<div><span class="text-gray-600">[${time}]</span> <span class="${color}">[${tag}]</span> ${msg}</div>`;
  consoleEl.scrollTop = consoleEl.scrollHeight;
}

window.addEventListener('DOMContentLoaded', () => {
  initMap();
  detectVisitorIdentity();
  loadData();
  initWebSocket();
});
