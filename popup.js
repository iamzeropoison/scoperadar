// popup.js: ScopeRadar
// Part of the ScopeRadar browser extension. See LICENSE for terms.
// Original author: Muhammad Rebaal (github.com/iamzeropoison)

let currentDomain = '';
let currentContact = '';
let trackerEntry = null;
let lastLookup = null;

document.addEventListener('DOMContentLoaded', init);

async function init() {
  await getCurrentDomain();
  runAutoCheck();
  await checkScopeBanner();

  document.getElementById('btn-compose').addEventListener('click', composeOutreachEmail);
  document.getElementById('btn-save').addEventListener('click', saveTrackerEntry);
  document.getElementById('btn-recon').addEventListener('click', runRecon);
  document.getElementById('btn-safeharbor').addEventListener('click', runSafeHarborCheck);
  document.getElementById('btn-ai-polish').addEventListener('click', polishEmailWithAI);
  document.getElementById('btn-radar-sync').addEventListener('click', triggerRadarSync);
  document.getElementById('status-select').addEventListener('change', onStatusChange);
  document.getElementById('open-dashboard').addEventListener('click', (e) => {
    e.preventDefault();
    chrome.runtime.openOptionsPage();
  });
}

async function getCurrentDomain() {
  try {
    const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    if (tabs && tabs.length) {
      currentDomain = new URL(tabs[0].url).hostname;
      document.getElementById('domain-info').textContent = `Current domain: ${currentDomain}`;
    }
  } catch {
    document.getElementById('domain-info').textContent = 'Unable to detect current domain';
  }
}

/* ---------------------------------------------------------------------- */
/* Detection + Scope Radar                                                 */
/* ---------------------------------------------------------------------- */

function runAutoCheck() {
  updateStatusUI('loading', 'Checking for bug bounty programs...');
  chrome.runtime.sendMessage({ action: 'runLookup' }, (response) => {
    if (chrome.runtime.lastError) {
      updateStatusUI('danger', 'Error connecting to extension');
      showOutreach();
      return;
    }
    handleLookupResponse(response);
  });
}

function handleLookupResponse(response) {
  if (!response || response.error) {
    updateStatusUI('danger', 'Error occurred', response ? response.error : '');
    showOutreach();
    return;
  }

  lastLookup = response.data;
  const { data } = response;
  renderRadar(data.radar);
  renderSecurityTxt(data.secTxt);
  renderOosBanner(data.radar);

  const outOfScope = data.radar && data.radar.state === 'out_of_scope';

  if (data.found) {
    updateStatusUI('success', 'Bug bounty program found!', `Found ${data.programs.length} reference(s) for ${currentDomain}`);
    displayResults(data.programs, 'Confirmed Programs');
    showPolicySection(data);
    hideOutreach();
  } else if (data.possible) {
    updateStatusUI('warn', 'Possible program (unverified)', `${currentDomain} mentions bounty/VDP language, but no confirmed link`);
    displayResults(data.programs, 'Unverified signals');
    showPolicySection(data);
    currentContact = data.contact || `security@${currentDomain}`;
    showOutreach({ soften: true });
    loadTrackerEntryIntoForm();
  } else if (outOfScope) {
    updateStatusUI('danger', 'This host is out of scope', `${data.radar.outOfScope[0].name} explicitly excludes it. Do not test.`);
    document.getElementById('results').style.display = 'none';
    hideOutreach();
  } else {
    updateStatusUI('error', 'No public program found', `${currentDomain} has no obvious bug bounty / VDP`);
    document.getElementById('results').style.display = 'none';
    currentContact = data.contact || `security@${currentDomain}`;
    showOutreach({ soften: false });
    loadTrackerEntryIntoForm();
  }
}

function updateStatusUI(status, message, subtitle) {
  const indicator = document.getElementById('status-indicator');
  indicator.classList.remove('loading', 'success', 'error', 'warn', 'danger');
  indicator.classList.add(status);
  const icons = {
    loading: '<div class="loading-spinner"></div>',
    success: `<svg class="success-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22,4 12,14.01 9,11.01"/></svg>`,
    warn: `<svg class="error-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v4M12 17h.01M10.29 3.86l-8.18 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.89-3.14l-8.18-14a2 2 0 0 0-3.42 0z"/></svg>`,
    danger: `<svg class="error-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`,
    error: `<svg class="error-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="13"/><line x1="12" y1="16" x2="12" y2="16.01"/></svg>`,
  };
  indicator.innerHTML = icons[status] || icons.error;
  document.getElementById('status').textContent = message;
  if (subtitle) document.getElementById('domain-info').textContent = subtitle;
}

function renderOosBanner(radar) {
  const banner = document.getElementById('oos-banner');
  if (radar && radar.state === 'out_of_scope') {
    const m = radar.outOfScope[0];
    banner.style.display = 'block';
    banner.innerHTML = `<strong>${escapeHtml(currentDomain)}</strong> is explicitly listed as <strong>out of scope</strong> for ${escapeHtml(m.name)} (${escapeHtml(platformName(m.platform))}). Testing this would violate the program's rules. Don't.`;
  } else {
    banner.style.display = 'none';
  }
}

function platformName(p) {
  const names = { hackerone: 'HackerOne', bugcrowd: 'Bugcrowd', intigriti: 'Intigriti', yeswehack: 'YesWeHack' };
  return names[p] || p;
}

function renderRadar(radar) {
  const card = document.getElementById('radar-card');
  const body = document.getElementById('radar-body');
  const pill = document.getElementById('radar-pill');
  const syncRow = document.getElementById('radar-sync-row');

  if (!radar) { card.style.display = 'none'; return; }
  card.style.display = 'block';

  if (!radar.hasData) {
    pill.className = 'pill neutral';
    pill.textContent = 'NOT SYNCED';
    body.innerHTML = `<div class="match-note">Scope database hasn't been synced yet. This checks the curated list only. Sync pulls the public HackerOne/Bugcrowd/Intigriti/YesWeHack scope lists (~1500+ programs) so ScopeRadar can tell you exactly what's in scope.</div>`;
    syncRow.style.display = 'block';
    document.getElementById('radar-sync-note').textContent = '';
    return;
  }
  syncRow.style.display = 'none';

  const rows = [];
  if (radar.inScope.length) {
    pill.className = 'pill good'; pill.textContent = 'IN SCOPE';
    radar.inScope.forEach((m) => rows.push(matchRow(m, 'ok')));
  } else if (radar.outOfScope.length) {
    pill.className = 'pill bad'; pill.textContent = 'OUT OF SCOPE';
    radar.outOfScope.forEach((m) => rows.push(matchRow(m, 'risk')));
  } else if (radar.related.length) {
    pill.className = 'pill warn'; pill.textContent = 'COMPANY HAS A PROGRAM';
    rows.push(`<div class="match-note">${escapeHtml(radar.root)} runs a program, but <strong>${escapeHtml(radar.host)}</strong> isn't listed in its scope. Don't assume it's covered. Check the policy or ask.</div>`);
    radar.related.forEach((m) => rows.push(matchRow(m, null)));
  } else {
    pill.className = 'pill neutral'; pill.textContent = 'NO MATCH';
    rows.push(`<div class="match-note">No public program lists ${escapeHtml(radar.host)} or ${escapeHtml(radar.root)} in its scope (across ${'HackerOne, Bugcrowd, Intigriti, YesWeHack'}).</div>`);
  }
  body.innerHTML = rows.join('');
}

function matchRow(m, tagKind) {
  const tags = [];
  if (m.bounty) tags.push('<span class="tag money">pays bounty</span>');
  else tags.push('<span class="tag">VDP only</span>');
  if (m.maxPayout) tags.push(`<span class="tag money">up to ${m.currency || ''} ${Number(m.maxPayout).toLocaleString()}</span>`);
  if (m.responseEfficiency != null) tags.push(`<span class="tag">${m.responseEfficiency}% response rate</span>`);
  if (tagKind === 'ok') tags.push(`<span class="tag ok">${escapeHtml(m.via || 'matched')}${m.pathScoped ? ' · path-scoped' : ''}</span>`);
  if (tagKind === 'risk') tags.push(`<span class="tag risk">${escapeHtml(m.via || 'excluded')}</span>`);
  return `<div class="match">
    <div class="match-name"><a href="${escapeHtml(m.url)}" target="_blank">${escapeHtml(m.name || 'Unnamed program')}</a><span class="match-platform">${escapeHtml(platformName(m.platform))}</span></div>
    <div class="tags">${tags.join('')}</div>
  </div>`;
}

async function triggerRadarSync() {
  const btn = document.getElementById('btn-radar-sync');
  const note = document.getElementById('radar-sync-note');
  btn.disabled = true; btn.textContent = 'Syncing (this can take a bit the first time)...';
  chrome.runtime.sendMessage({ action: 'radarSync' }, (resp) => {
    btn.disabled = false; btn.textContent = 'Sync scope database now';
    if (!resp) { note.textContent = 'Sync failed. Try again.'; return; }
    if (resp.errors && resp.errors.length) note.textContent = `Synced with some errors: ${resp.errors.join(' · ')}`;
    else note.textContent = `Synced. ${resp.events ? `(${resp.events} scope change${resp.events > 1 ? 's' : ''} found)` : ''}`;
    runAutoCheck();
  });
}

function displayResults(programs, title) {
  document.getElementById('results-title').textContent = title;
  const resultsSection = document.getElementById('results');
  document.getElementById('details').innerHTML = programs
    .map((p) => `<div class="program-item"><div class="program-platform">${escapeHtml(p.platform || 'Unknown')}</div><a href="${escapeHtml(p.link)}" target="_blank" class="program-link">${escapeHtml(p.link)}</a></div>`)
    .join('');
  resultsSection.style.display = 'block';
}

/* ---------------------------------------------------------------------- */
/* Safe harbor                                                             */
/* ---------------------------------------------------------------------- */

function showPolicySection(data) {
  const section = document.getElementById('policy-section');
  const link = (data.programs.find((p) => p.confidence === 'high') || data.programs[0] || {}).link;
  if (!link) { section.style.display = 'none'; return; }
  section.style.display = 'block';
  section.dataset.url = link;
  document.getElementById('safeharbor-result').style.display = 'none';
}

function runSafeHarborCheck() {
  const section = document.getElementById('policy-section');
  const url = section.dataset.url;
  const btn = document.getElementById('btn-safeharbor');
  const box = document.getElementById('safeharbor-result');
  if (!url) return;

  btn.disabled = true; btn.textContent = 'Reading policy...';
  chrome.runtime.sendMessage({ action: 'checkSafeHarbor', url }, (resp) => {
    btn.disabled = false; btn.textContent = 'Check policy for safe-harbor language';
    box.style.display = 'block';
    if (!resp || resp.error) {
      box.innerHTML = `<div class="sh-head">Couldn't check: ${escapeHtml((resp && resp.error) || 'unknown error')}</div>`;
      return;
    }
    const info = { explicit: 'Safe-harbor language found', mixed: 'Safe harbor AND legal-action language (read carefully)', weak: 'Mentions good faith, but no explicit legal protection', negative: 'Reserves the right to take legal action', none: 'No safe-harbor language found', unknown: 'Not enough policy text to judge' }[resp.level] || resp.level;
    box.innerHTML = `<div class="sh-head">${escapeHtml(info)}</div>` +
      resp.evidence.map((e) => `<div class="sh-evidence ${escapeHtml(e.kind)}">"${escapeHtml(e.text)}"</div>`).join('') +
      `<div class="tiny">Keyword-based heuristic, not legal advice. Always read the full policy yourself.</div>`;
  });
}

/* ---------------------------------------------------------------------- */
/* security.txt                                                           */
/* ---------------------------------------------------------------------- */

function renderSecurityTxt(secTxt) {
  const section = document.getElementById('sectxt');
  if (!secTxt || !(secTxt.contact || secTxt.policy || secTxt.expires)) { section.style.display = 'none'; return; }
  section.style.display = 'block';
  const rows = [['Contact', secTxt.contact], ['Policy', secTxt.policy], ['Expires', secTxt.expires], ['Encryption', secTxt.encryption], ['Preferred languages', secTxt.preferredLanguages], ['Acknowledgments', secTxt.acknowledgments]].filter(([, v]) => v);
  document.getElementById('sectxt-fields').innerHTML = rows.map(([k, v]) => `<div><span class="k">${escapeHtml(k)}:</span>${escapeHtml(v)}</div>`).join('');
  const badge = document.getElementById('sectxt-expiry-badge');
  if (secTxt.expired === true) { badge.style.display = 'inline-block'; badge.className = 'pill bad'; badge.textContent = 'EXPIRED'; }
  else if (secTxt.expired === false) { badge.style.display = 'inline-block'; badge.className = 'pill good'; badge.textContent = 'CURRENT'; }
  else badge.style.display = 'none';
}

/* ---------------------------------------------------------------------- */
/* Passive recon (crt.sh)                                                 */
/* ---------------------------------------------------------------------- */

function runRecon() {
  const btn = document.getElementById('btn-recon');
  const box = document.getElementById('recon-results');
  btn.disabled = true; btn.textContent = 'Searching public certificate records...';
  box.style.display = 'block'; box.innerHTML = '<div>Loading...</div>';

  chrome.runtime.sendMessage({ action: 'getSubdomains', domain: currentDomain }, (resp) => {
    btn.disabled = false; btn.textContent = 'Find subdomains (passive, public records)';
    const subs = (resp && resp.subdomains) || [];
    if (!subs.length) { box.innerHTML = '<div>No records found via crt.sh.</div>'; return; }
    box.innerHTML = subs.slice(0, 40).map((s) => `<div>${escapeHtml(s)}</div>`).join('') +
      `<div class="recon-note">${subs.length} total found via certificate-transparency logs. public records only. No contact made with the target. Only test what's in an approved scope.</div>`;
  });
}

/* ---------------------------------------------------------------------- */
/* Outreach + spam guard + tracker                                        */
/* ---------------------------------------------------------------------- */

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

function showOutreach(opts) {
  document.getElementById('outreach').style.display = 'block';
  document.getElementById('contact-email').value = currentContact;
  const softened = opts && opts.soften;
  document.getElementById('outreach-title').textContent = softened ? 'Unverified: confirm before testing' : 'No public program: request permission';
  document.getElementById('outreach-sub').textContent = softened
    ? "This site mentions bounty/VDP language but ScopeRadar couldn't confirm a program link. Draft a request to confirm scope and permission before testing."
    : 'Draft a permission-request email before doing any testing. Nothing is sent automatically.';
  prefillEmailFields();
}
function hideOutreach() { document.getElementById('outreach').style.display = 'none'; }

async function prefillEmailFields() {
  const settings = await getResearcherSettings();
  document.getElementById('email-subject').value = fillTemplate(settings.subjectTemplate, settings);
  document.getElementById('email-body').value = fillTemplate(settings.bodyTemplate, settings);
}

async function loadTrackerEntryIntoForm() {
  chrome.runtime.sendMessage({ action: 'getTracker' }, (resp) => {
    const tracker = (resp && resp.tracker) || {};
    trackerEntry = tracker[currentDomain] || null;
    if (trackerEntry) {
      document.getElementById('contact-email').value = trackerEntry.contact || currentContact;
      document.getElementById('notes').value = trackerEntry.notes || '';
      document.getElementById('status-select').value = trackerEntry.status || 'not_contacted';
      if (trackerEntry.reminderDays) document.getElementById('reminder-days').value = String(trackerEntry.reminderDays);
      if (trackerEntry.draftSubject) document.getElementById('email-subject').value = trackerEntry.draftSubject;
      if (trackerEntry.draftBody) document.getElementById('email-body').value = trackerEntry.draftBody;
    }
    renderSpamGuard();
    onStatusChange();
  });
}

function renderSpamGuard() {
  const box = document.getElementById('spam-guard');
  if (!trackerEntry || !trackerEntry.emailsSent) { box.style.display = 'none'; return; }
  const days = trackerEntry.lastRequestedAt ? Math.floor((Date.now() - trackerEntry.lastRequestedAt) / 86400000) : null;
  box.style.display = 'block';
  box.innerHTML = `You've already reached out to <strong>${escapeHtml(currentDomain)}</strong> ${trackerEntry.emailsSent} time(s)${days !== null ? `, last ${days} day(s) ago` : ''}. Avoid re-sending too soon.`;
}

function onStatusChange() {
  const gate = document.getElementById('consent-gate');
  const isTesting = document.getElementById('status-select').value === 'testing';
  gate.style.display = isTesting ? 'block' : 'none';
  if (!isTesting) document.getElementById('consent-checkbox').checked = (trackerEntry && trackerEntry.consentConfirmed) || false;
}

async function composeOutreachEmail() {
  const contact = document.getElementById('contact-email').value.trim() || currentContact;
  const subject = document.getElementById('email-subject').value.trim();
  const body = document.getElementById('email-body').value.trim();
  const mailto = `mailto:${encodeURIComponent(contact)}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;

  chrome.tabs.create({ url: mailto });
  document.getElementById('status-select').value = 'requested';
  onStatusChange();

  chrome.runtime.sendMessage({ action: 'recordOutreachSent', domain: currentDomain }, (resp) => {
    trackerEntry = resp && resp.entry ? resp.entry : trackerEntry;
    renderSpamGuard();
  });
  await saveTrackerEntry();
}

async function polishEmailWithAI() {
  const statusEl = document.getElementById('ai-status');
  const btn = document.getElementById('btn-ai-polish');
  const bodyField = document.getElementById('email-body');

  const status = await scopehoundAIStatus();
  statusEl.classList.remove('error');

  if (status.state === 'unsupported' || status.state === 'unavailable') {
    statusEl.textContent = status.label;
    statusEl.classList.add('error');
    return;
  }
  if (status.state === 'downloadable') {
    statusEl.textContent = 'One-time setup needed. Starting the on-device model download...';
    btn.disabled = true;
    const dl = await scopehoundAIDownload();
    btn.disabled = false;
    if (!dl.ok) { statusEl.textContent = `Couldn't start the download: ${dl.error || 'unknown error'}`; statusEl.classList.add('error'); return; }
    statusEl.textContent = 'Download started. This can take a few minutes the first time. Try again shortly.';
    return;
  }
  if (status.state === 'downloading') {
    statusEl.textContent = status.label;
    return;
  }

  btn.disabled = true;
  statusEl.textContent = 'Polishing with on-device AI...';

  const prompt = `Rewrite the following permission-request email to a company's security team so it reads professionally, concisely, and politely. Keep it truthful to the original content. Don't invent new claims. Keep the researcher's name/email/domain exactly as given. Return only the improved email body text.

Domain: ${currentDomain}

Original draft:
${bodyField.value}`;

  const result = await scopehoundCallAI(prompt);
  btn.disabled = false;
  if (result.error) { statusEl.textContent = `AI error: ${result.error}`; statusEl.classList.add('error'); return; }
  bodyField.value = result.text;
  statusEl.textContent = 'Polished. Review before sending.';
}

function fillTemplate(template, settings) {
  return template
    .replaceAll('{domain}', currentDomain)
    .replaceAll('{researcherName}', settings.researcherName || 'Independent Security Researcher')
    .replaceAll('{researcherEmail}', settings.researcherEmail || '');
}

function getResearcherSettings() {
  return new Promise((resolve) => {
    chrome.storage.sync.get(['scopehoundSettings'], (result) => {
      resolve(result.scopehoundSettings || { researcherName: '', researcherEmail: '', subjectTemplate: 'Request for Security Testing Permission: Responsible Disclosure', bodyTemplate: DEFAULT_BODY });
    });
  });
}

async function saveTrackerEntry() {
  const status = document.getElementById('status-select').value;
  const consentBox = document.getElementById('consent-checkbox');
  if (status === 'testing' && !consentBox.checked) {
    alert('Please confirm you have written permission before marking this as "Testing".');
    return;
  }
  const entry = {
    domain: currentDomain,
    contact: document.getElementById('contact-email').value.trim(),
    status,
    notes: document.getElementById('notes').value.trim(),
    consentConfirmed: consentBox.checked,
    draftSubject: document.getElementById('email-subject').value,
    draftBody: document.getElementById('email-body').value,
  };
  chrome.runtime.sendMessage({ action: 'upsertTrackerEntry', entry }, () => {});
  const reminderDays = document.getElementById('reminder-days').value;
  if (reminderDays) chrome.runtime.sendMessage({ action: 'scheduleReminder', domain: currentDomain, days: Number(reminderDays) }, () => {});
}

async function checkScopeBanner() {
  chrome.runtime.sendMessage({ action: 'getTracker' }, (resp) => {
    const tracker = (resp && resp.tracker) || {};
    const entry = tracker[currentDomain];
    const banner = document.getElementById('scope-banner');
    if (entry && entry.status === 'approved' && entry.notes) {
      document.getElementById('scope-banner-text').textContent = entry.notes;
      banner.style.display = 'block';
    } else banner.style.display = 'none';
  });
}

function escapeHtml(text) {
  const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
  return String(text).replace(/[&<>"']/g, (m) => map[m]);
}
