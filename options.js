// options.js: ScopeRadar dashboard
// Part of the ScopeRadar browser extension. See LICENSE for terms.
// Original author: Muhammad Rebaal (github.com/iamzeropoison)

const DEFAULT_SUBJECT = 'Request for Security Testing Permission: Responsible Disclosure';
const DEFAULT_BODY = `Hello {domain} Security Team,

My name is {researcherName}, an independent security researcher. I could not find a public bug bounty or vulnerability disclosure program for {domain}.

I would like to request written permission to perform limited, non-destructive security testing on {domain}, strictly to identify and responsibly report any issues. I will not access, modify, or exfiltrate data beyond what is necessary to demonstrate a finding, and any results will be reported privately to you first.

If you're open to this, could you confirm:
1. Which domains/subdomains are in scope
2. Anything that is off-limits
3. Whether a reward is offered for verified findings

Thank you for your time.

Best regards,
{researcherName}
{researcherEmail}`;

const PLATFORM_NAMES = { hackerone: 'HackerOne', bugcrowd: 'Bugcrowd', intigriti: 'Intigriti', yeswehack: 'YesWeHack' };

let allPrograms = [];

document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initStarField();
  initGlobeParallax();
  loadSettings();
  loadRadarPanel();
  loadProgramsList();
  loadCvssPanel();
  refreshAIStatus();
  initChat();

  document.getElementById('btn-save-settings').addEventListener('click', saveSettings);
  document.getElementById('btn-ai-download').addEventListener('click', startAIDownload);

  document.getElementById('btn-radar-sync').addEventListener('click', runRadarSync);
  document.getElementById('btn-save-radar-settings').addEventListener('click', saveRadarSettings);
  document.getElementById('btn-radar-check').addEventListener('click', checkRadarHost);
  document.getElementById('radar-check-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') checkRadarHost(); });

  document.getElementById('program-search').addEventListener('input', renderProgramsList);
  document.getElementById('program-platform-filter').addEventListener('change', renderProgramsList);
  document.getElementById('program-bounty-only').addEventListener('change', renderProgramsList);

  document.getElementById('btn-copy-vector').addEventListener('click', copyVector);
});

/* ---------------------------------------------------------------------- */
/* Tabs                                                                    */
/* ---------------------------------------------------------------------- */

function initTabs() {
  const hashTab = (location.hash || '').replace('#', '');
  document.querySelectorAll('.tab-btn').forEach((btn) => btn.addEventListener('click', () => activateTab(btn.dataset.tab)));
  const initial = hashTab && document.querySelector(`.tab-btn[data-tab="${hashTab}"]`) ? hashTab : 'radar';
  activateTab(initial);
}
function activateTab(tab) {
  document.querySelectorAll('.tab-btn').forEach((b) => b.classList.toggle('active', b.dataset.tab === tab));
  document.querySelectorAll('.tab-panel').forEach((p) => {
    if (p.dataset.panel === tab) {
      p.style.display = 'block';
      p.classList.remove('tab-panel-visible');
      requestAnimationFrame(() => p.classList.add('tab-panel-visible'));
    } else {
      p.classList.remove('tab-panel-visible');
      p.style.display = 'none';
    }
  });
}

/* ---------------------------------------------------------------------- */
/* Hero star field (decorative)                                           */
/* ---------------------------------------------------------------------- */

function initStarField() {
  const field = document.getElementById('star-field');
  const stars = 14;
  let html = '';
  for (let i = 0; i < stars; i++) {
    const top = Math.round(Math.random() * 100);
    const left = Math.round(Math.random() * 100);
    const size = (1 + Math.random() * 2).toFixed(1);
    const delay = (Math.random() * 3).toFixed(1);
    html += `<div class="star" style="--top:${top}%; --left:${left}%; --size:${size}px; --delay:${delay}s"></div>`;
  }
  field.innerHTML = html;
}

/* ---------------------------------------------------------------------- */
/* Hero globe: mouse-parallax tilt for a bit of depth                     */
/* ---------------------------------------------------------------------- */

function initGlobeParallax() {
  const hero = document.querySelector('.hero');
  const scene = document.querySelector('.globe-scene');
  if (!hero || !scene) return;

  hero.addEventListener('mousemove', (e) => {
    const rect = hero.getBoundingClientRect();
    const cx = rect.left + rect.width * 0.22;
    const cy = rect.top + rect.height * 0.5;
    const dx = (e.clientX - cx) / rect.width;
    const dy = (e.clientY - cy) / rect.height;
    const rotY = Math.max(-10, Math.min(10, dx * 22));
    const rotX = Math.max(-8, Math.min(8, -dy * 18));
    scene.style.transform = `rotateY(${rotY}deg) rotateX(${rotX}deg)`;
  });
  hero.addEventListener('mouseleave', () => {
    scene.style.transform = '';
  });
}

/* ---------------------------------------------------------------------- */
/* Researcher settings                                                     */
/* ---------------------------------------------------------------------- */

function loadSettings() {
  chrome.storage.sync.get(['scopehoundSettings'], (result) => {
    const s = result.scopehoundSettings || {};
    document.getElementById('researcherName').value = s.researcherName || '';
    document.getElementById('researcherEmail').value = s.researcherEmail || '';
    document.getElementById('subjectTemplate').value = s.subjectTemplate || DEFAULT_SUBJECT;
    document.getElementById('bodyTemplate').value = s.bodyTemplate || DEFAULT_BODY;
  });
}
function saveSettings() {
  const settings = {
    researcherName: document.getElementById('researcherName').value.trim(),
    researcherEmail: document.getElementById('researcherEmail').value.trim(),
    subjectTemplate: document.getElementById('subjectTemplate').value.trim() || DEFAULT_SUBJECT,
    bodyTemplate: document.getElementById('bodyTemplate').value.trim() || DEFAULT_BODY,
  };
  chrome.storage.sync.set({ scopehoundSettings: settings }, () => {
    const confirm = document.getElementById('save-confirm');
    confirm.textContent = 'Saved.';
    setTimeout(() => (confirm.textContent = ''), 2000);
  });
}

/* ---------------------------------------------------------------------- */
/* On-device AI status (no key, ever)                                     */
/* ---------------------------------------------------------------------- */

async function refreshAIStatus() {
  const box = document.getElementById('ai-status-box');
  const dlBtn = document.getElementById('btn-ai-download');
  box.textContent = 'Checking availability...';
  box.className = 'ai-status-box';
  const status = await scopehoundAIStatus();
  box.textContent = status.label;
  box.className = 'ai-status-box ' + (status.state === 'available' ? 'ok' : status.state === 'downloadable' || status.state === 'downloading' ? 'warn' : 'bad');
  dlBtn.style.display = status.state === 'downloadable' ? 'inline-block' : 'none';
  return status;
}
async function startAIDownload() {
  const btn = document.getElementById('btn-ai-download');
  btn.disabled = true; btn.textContent = 'Downloading...';
  const result = await scopehoundAIDownload();
  btn.disabled = false; btn.textContent = 'Start one-time download';
  if (!result.ok) { document.getElementById('ai-status-box').textContent = `Couldn't start download: ${result.error}`; return; }
  await refreshAIStatus();
}

/* ---------------------------------------------------------------------- */
/* AI Assistant: chat tab                                                 */
/* ---------------------------------------------------------------------- */

let chatSession = null;

function initChat() {
  document.getElementById('btn-chat-send').addEventListener('click', sendChatMessage);
  document.getElementById('chat-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendChatMessage(); }
  });
  document.getElementById('btn-chat-reset').addEventListener('click', resetChat);
}

function appendChatBubble(role, text) {
  const win = document.getElementById('chat-window');
  const div = document.createElement('div');
  div.className = `chat-bubble ${role}`;
  div.textContent = text;
  win.appendChild(div);
  win.scrollTop = win.scrollHeight;
  return div;
}

async function sendChatMessage() {
  const input = document.getElementById('chat-input');
  const text = input.value.trim();
  if (!text) return;

  const status = await refreshAIStatus();
  if (status.state === 'unsupported' || status.state === 'unavailable') return;
  if (status.state === 'downloadable') { startAIDownload(); return; }
  if (status.state === 'downloading') return;

  appendChatBubble('user', text);
  input.value = '';
  const sendBtn = document.getElementById('btn-chat-send');
  sendBtn.disabled = true;
  const pending = appendChatBubble('assistant pending', 'Thinking...');

  try {
    if (!chatSession) {
      chatSession = await scopehoundCreateSession(SCOPERADAR_CHAT_SYSTEM_PROMPT);
      if (chatSession.error) { pending.textContent = `AI error: ${chatSession.error}`; pending.classList.remove('pending'); chatSession = null; sendBtn.disabled = false; return; }
    }
    const reply = await chatSession.prompt(text);
    pending.textContent = reply || '(empty response, try rephrasing)';
    pending.classList.remove('pending');
  } catch (err) {
    pending.textContent = `AI error: ${err.message || err}`;
    pending.classList.remove('pending');
  } finally {
    sendBtn.disabled = false;
  }
}

function resetChat() {
  if (chatSession && chatSession.destroy) chatSession.destroy();
  chatSession = null;
  const win = document.getElementById('chat-window');
  win.innerHTML = '';
  appendChatBubble('assistant', 'New conversation. Ask me anything about scoping, triage, CVSS, or writing up a finding.');
}

/* ---------------------------------------------------------------------- */
/* Scope Radar panel                                                       */
/* ---------------------------------------------------------------------- */

function loadRadarPanel() {
  chrome.storage.local.get(['radarMeta', 'radarSettings', 'radarFeed'], (r) => {
    const settings = r.radarSettings || { intervalHours: 24, notify: true };
    document.getElementById('radar-interval').value = String(settings.intervalHours ?? 24);
    document.getElementById('radar-notify').checked = settings.notify !== false;
    renderRadarStats(r.radarMeta);
    renderFeed(r.radarFeed || []);
  });
}

function renderRadarStats(meta) {
  const box = document.getElementById('radar-stats');
  if (!meta || !meta.updatedAt) {
    box.innerHTML = `<p class="hint" style="margin:0">Not synced yet. Click <strong>Sync now</strong> to download the public scope database (a few MB, one-time).</p>`;
    return;
  }
  const totals = meta.totals || { programs: 0, assets: 0 };
  const boxes = [
    { n: totals.programs, l: 'Programs indexed' },
    { n: totals.assets, l: 'Scope assets' },
    { n: timeAgo(meta.updatedAt), l: 'Last synced', raw: true },
  ];
  box.innerHTML = boxes.map((b) => `<div class="stat-box"><div class="stat-num" style="${b.raw ? 'font-size:15px' : ''}">${b.raw ? escapeHtml(String(b.n)) : Number(b.n).toLocaleString()}</div><div class="stat-label">${escapeHtml(b.l)}</div></div>`).join('');
  if (meta.lastError) box.innerHTML += `<div class="stat-error">${escapeHtml(meta.lastError)}</div>`;
}

function timeAgo(ts) {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
}

function runRadarSync() {
  const btn = document.getElementById('btn-radar-sync');
  btn.disabled = true;
  btn.textContent = 'Syncing...';
  const poll = setInterval(() => {
    chrome.storage.local.get('radarMeta', (r) => { if (r.radarMeta && r.radarMeta.stage) btn.textContent = r.radarMeta.stage; });
  }, 400);
  chrome.runtime.sendMessage({ action: 'radarSync' }, () => {
    clearInterval(poll);
    btn.disabled = false;
    btn.textContent = 'Sync now';
    loadRadarPanel();
    loadProgramsList();
  });
}

function saveRadarSettings() {
  const radarSettings = { intervalHours: Number(document.getElementById('radar-interval').value), notify: document.getElementById('radar-notify').checked };
  chrome.storage.local.set({ radarSettings });
}

function renderFeed(feed) {
  const box = document.getElementById('radar-feed');
  if (!feed.length) { box.innerHTML = '<p class="hint" style="margin:0">No scope changes recorded yet. They appear here after your first two syncs (the first sync just builds the baseline).</p>'; return; }
  const typeLabel = { new_program: 'NEW PROGRAM', new_scope: 'NEW SCOPE', program_closed: 'CLOSED' };
  box.innerHTML = feed.map((e) => `
    <div class="feed-item ${e.watched ? 'watched' : ''}">
      <div class="feed-head">
        <span class="feed-title">${escapeHtml(e.name || 'Unnamed')}${e.watched ? ' <span class="feed-tag watched-tag">tracked</span>' : ''} <span class="feed-tag ${e.type}">${typeLabel[e.type] || e.type}</span></span>
        <span class="feed-meta">${escapeHtml(PLATFORM_NAMES[e.platform] || e.platform)} · ${timeAgo(e.ts)}</span>
      </div>
      ${e.url ? `<a href="${escapeHtml(e.url)}" target="_blank" class="hint-link" style="font-size:11.5px">${escapeHtml(e.url)}</a>` : ''}
      ${e.assets && e.assets.length ? `<div class="feed-assets">${e.assets.map(escapeHtml).join(', ')}${e.total > e.assets.length ? ` +${e.total - e.assets.length} more` : ''}</div>` : ''}
    </div>`).join('');
}

function checkRadarHost() {
  const input = document.getElementById('radar-check-input');
  const host = input.value.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  const box = document.getElementById('radar-check-result');
  if (!host) return;
  chrome.storage.local.get('radarParts', ({ radarParts }) => {
    const parts = radarParts || {};
    const hasData = Object.keys(parts).length > 0;
    if (!hasData) { box.innerHTML = '<p class="hint" style="margin-top:10px">Sync the scope database first.</p>'; return; }
    const m = ScopeRadar.matchHost(parts, host);
    const state = ScopeRadar.radarState(m, true);
    let html = '<div class="match-mini">';
    if (state === 'in_scope') html += `<strong style="color:#86EFAC">IN SCOPE</strong>` + m.inScope.map(rowHtml).join('');
    else if (state === 'out_of_scope') html += `<strong style="color:#FCA5A5">OUT OF SCOPE</strong>` + m.outOfScope.map(rowHtml).join('');
    else if (state === 'related') html += `<strong style="color:#FDBA74">Company has a program, host not listed</strong>` + m.related.map(rowHtml).join('');
    else html += `<span style="color:#94A3B8">No match found for ${escapeHtml(host)} or ${escapeHtml(m.root)}.</span>`;
    html += '</div>';
    box.innerHTML = html;
  });
}
function rowHtml(m) {
  return `<div style="margin-top:8px;font-size:12.5px"><a href="${escapeHtml(m.url)}" target="_blank" style="color:#7DD3FC">${escapeHtml(m.name)}</a> · ${escapeHtml(PLATFORM_NAMES[m.platform] || m.platform)}${m.bounty ? ' · pays bounty' : ' · VDP only'}</div>`;
}

/* ---------------------------------------------------------------------- */
/* All synced programs: searchable list                                  */
/* ---------------------------------------------------------------------- */

const PROGRAM_LIST_CAP = 300;

function loadProgramsList() {
  chrome.runtime.sendMessage({ action: 'getAllPrograms' }, (resp) => {
    allPrograms = (resp && resp.programs) || [];
    document.getElementById('program-count-pill').textContent = allPrograms.length ? `${allPrograms.length.toLocaleString()} total` : 'not synced';
    document.getElementById('program-count-pill').className = 'pill-lg ' + (allPrograms.length ? 'ok' : 'neutral');
    renderProgramsList();
  });
}

function renderProgramsList() {
  const search = document.getElementById('program-search').value.trim().toLowerCase();
  const platform = document.getElementById('program-platform-filter').value;
  const bountyOnly = document.getElementById('program-bounty-only').checked;
  const box = document.getElementById('program-list');
  const note = document.getElementById('program-list-note');

  if (!allPrograms.length) {
    box.innerHTML = '';
    note.textContent = 'No programs synced yet. Click "Sync now" above.';
    return;
  }

  let rows = allPrograms;
  if (search) rows = rows.filter((p) => p.name.toLowerCase().includes(search));
  if (platform) rows = rows.filter((p) => p.platform === platform);
  if (bountyOnly) rows = rows.filter((p) => p.bounty);

  const total = rows.length;
  const shown = rows.slice(0, PROGRAM_LIST_CAP);

  box.innerHTML = shown.map((p) => `
    <div class="program-row">
      <a href="${escapeHtml(p.url)}" target="_blank">${escapeHtml(p.name)}</a>
      <div class="program-row-meta">
        ${p.bounty ? `<span class="program-bounty-tag">bounty${p.maxPayout ? ` up to ${escapeHtml(p.currency || '')} ${Number(p.maxPayout).toLocaleString()}` : ''}</span>` : ''}
        <span class="program-platform-tag">${escapeHtml(PLATFORM_NAMES[p.platform] || p.platform)}</span>
      </div>
    </div>`).join('');

  note.textContent = total > PROGRAM_LIST_CAP
    ? `Showing first ${PROGRAM_LIST_CAP} of ${total.toLocaleString()} matches. Narrow your search to see more precisely.`
    : `${total.toLocaleString()} program${total === 1 ? '' : 's'} match${total === 1 ? 'es' : ''}.`;
}

/* ---------------------------------------------------------------------- */
/* CVSS calculator                                                         */
/* ---------------------------------------------------------------------- */

const CVSS_METRICS = [
  { key: 'AV', label: 'Attack Vector', opts: [['N', 'Network'], ['A', 'Adjacent'], ['L', 'Local'], ['P', 'Physical']] },
  { key: 'AC', label: 'Attack Complexity', opts: [['L', 'Low'], ['H', 'High']] },
  { key: 'PR', label: 'Privileges Required', opts: [['N', 'None'], ['L', 'Low'], ['H', 'High']] },
  { key: 'UI', label: 'User Interaction', opts: [['N', 'None'], ['R', 'Required']] },
  { key: 'S', label: 'Scope', opts: [['U', 'Unchanged'], ['C', 'Changed']] },
  { key: 'C', label: 'Confidentiality', opts: [['N', 'None'], ['L', 'Low'], ['H', 'High']] },
  { key: 'I', label: 'Integrity', opts: [['N', 'None'], ['L', 'Low'], ['H', 'High']] },
  { key: 'A', label: 'Availability', opts: [['N', 'None'], ['L', 'Low'], ['H', 'High']] },
];
let cvssMetrics = { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'N', I: 'N', A: 'N' };

function loadCvssPanel() {
  const grid = document.getElementById('cvss-grid');
  grid.innerHTML = CVSS_METRICS.map((m) => `
    <div class="cvss-metric" data-key="${m.key}">
      <div class="cvss-metric-label">${escapeHtml(m.label)}</div>
      <div class="cvss-opts">${m.opts.map(([v, l]) => `<button type="button" class="cvss-opt" data-val="${v}">${escapeHtml(l)}</button>`).join('')}</div>
    </div>`).join('');

  grid.querySelectorAll('.cvss-metric').forEach((row) => {
    const key = row.dataset.key;
    row.querySelectorAll('.cvss-opt').forEach((btn) => {
      btn.addEventListener('click', () => { cvssMetrics[key] = btn.dataset.val; renderCvssResult(); syncCvssButtons(); });
    });
  });
  syncCvssButtons();
  renderCvssResult();
}
function syncCvssButtons() {
  document.querySelectorAll('.cvss-metric').forEach((row) => {
    const key = row.dataset.key;
    row.querySelectorAll('.cvss-opt').forEach((btn) => btn.classList.toggle('selected', btn.dataset.val === cvssMetrics[key]));
  });
}
function renderCvssResult() {
  const r = ScopeCVSS.cvss31(cvssMetrics);
  const scoreEl = document.getElementById('cvss-score');
  scoreEl.textContent = r.score.toFixed(1);
  scoreEl.className = `cvss-score sev-${r.severity}`;
  document.getElementById('cvss-severity').textContent = r.severity;
  document.getElementById('cvss-vector').textContent = r.vector;
}
function copyVector() {
  navigator.clipboard.writeText(document.getElementById('cvss-vector').textContent).then(() => {
    const btn = document.getElementById('btn-copy-vector');
    const orig = btn.textContent; btn.textContent = 'Copied'; setTimeout(() => (btn.textContent = orig), 1500);
  });
}

function escapeHtml(text) {
  const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
  return String(text).replace(/[&<>"']/g, (m) => map[m]);
}
