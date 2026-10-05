// background.js: ScopeRadar (service worker)
// Part of the ScopeRadar browser extension. See LICENSE for terms.
// Original author: Muhammad Rebaal (github.com/iamzeropoison)
//
// Detection • Scope Radar (public bounty database sync + diff alerts) •
// safe-harbor check, passive recon, and outreach tracker.
//
// This file NEVER sends email automatically and NEVER performs active
// scanning/exploitation. Network use is limited to: plain GET/HEAD requests
// for files meant to be public (security.txt, a policy page), crt.sh public
// certificate records, and the public bounty-targets-data dataset.
//
// PRIVACY: the automatic tab badge uses LOCAL data only (radar index +
// curated list). It makes no requests to the sites you browse. Deeper
// network checks run only when you open the popup or use the right-click menu.

'use strict';

importScripts('radar.js', 'safeharbor.js');

const DATASET_BASE = 'https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/';
const RADAR_ALARM = 'scopehound-radar-sync';
const CACHE_TTL_MS = 10 * 60 * 1000;
const FEED_MAX = 300;
const domainCache = new Map(); // domain -> { result, ts }

/* ---------------------------------------------------------------------- */
/* Curated self-hosted programs (not on HackerOne/Bugcrowd/etc.)          */
/* ---------------------------------------------------------------------- */

const KNOWN_PROGRAMS = {
  'google.com': 'https://bughunters.google.com/',
  'youtube.com': 'https://bughunters.google.com/',
  'android.com': 'https://bughunters.google.com/',
  'chromium.org': 'https://bughunters.google.com/',
  'apple.com': 'https://security.apple.com/bounty/',
  'microsoft.com': 'https://www.microsoft.com/en-us/msrc/bounty',
  'xbox.com': 'https://www.microsoft.com/en-us/msrc/bounty',
  'mozilla.org': 'https://www.mozilla.org/en-US/security/bug-bounty/',
  'facebook.com': 'https://www.facebook.com/whitehat',
  'meta.com': 'https://bugbounty.meta.com/',
  'instagram.com': 'https://bugbounty.meta.com/',
  'whatsapp.com': 'https://bugbounty.meta.com/',
  'github.com': 'https://bounty.github.com/',
  'samsung.com': 'https://security.samsungmobile.com/',
  'intel.com': 'https://www.intel.com/content/www/us/en/security-center/default.html',
};

// Hostname prefixes that strongly indicate the page itself IS a program page.
const PROGRAM_PREFIXES = ['bughunters.', 'bugbounty.', 'bug-bounty.', 'vdp.', 'responsibledisclosure.', 'whitehat.', 'hackerone.', 'bugcrowd.', 'yeswehack.', 'intigriti.', 'synack.'];
// Weaker hint (security.stackexchange.com is not a VDP), flagged unverified.
const WEAK_PREFIXES = ['security.', 'trust.'];

const CONTENT_KEYWORDS =
  /bug\s*bounty|vulnerability reward program|\bvrp\b|responsible disclosure|vulnerability disclosure|coordinated (?:vulnerability )?disclosure|report a (?:security )?vulnerability/i;

const PLATFORM_HOSTS = /(^|\.)(hackerone\.com|bugcrowd\.com|intigriti\.com|yeswehack\.com|synack\.com|hackenproof\.com)$/i;

function isPlatformProgramLink(link) {
  try {
    const u = new URL(link);
    return PLATFORM_HOSTS.test(u.hostname) && u.pathname.length > 1;
  } catch {
    return false;
  }
}

function platformLabel(platform) {
  return (ScopeRadar.ADAPTERS[platform] && ScopeRadar.ADAPTERS[platform].label) || platform;
}

/* ---------------------------------------------------------------------- */
/* Lifecycle: install / startup / alarms / context menu                   */
/* ---------------------------------------------------------------------- */

chrome.runtime.onInstalled.addListener((details) => {
  createContextMenus();
  ensureRadarAlarm();
  if (details.reason === 'install') syncRadar({ manual: false }).catch(() => {});
});
chrome.runtime.onStartup.addListener(() => ensureRadarAlarm());
ensureRadarAlarm(); // service workers restart often; alarm creation is idempotent

function createContextMenus() {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({ id: 'sh-check-link', title: 'ScopeRadar: check this link’s scope', contexts: ['link'] });
    chrome.contextMenus.create({ id: 'sh-check-page', title: 'ScopeRadar: check this site’s scope', contexts: ['page'] });
  });
}

chrome.contextMenus.onClicked.addListener((info, tab) => {
  try {
    const target = info.menuItemId === 'sh-check-link' ? info.linkUrl : (tab && tab.url) || info.pageUrl;
    if (!target) return;
    const host = new URL(target).hostname;
    if (isExtensionUrl(target)) return;
    quickCheck(host).catch((err) => console.error('ScopeRadar quick check failed', err));
  } catch {}
});

async function quickCheck(host) {
  const res = await performLookup(host, null, { network: true });
  const d = res.data;
  const r = d.radar;
  let title = 'ScopeRadar';
  let message;
  if (r.state === 'in_scope') {
    const m = r.inScope[0];
    message = `${host} is in scope: ${platformLabel(m.platform)} · ${m.name}${m.bounty ? ' (pays bounties)' : ' (VDP)'}`;
  } else if (r.state === 'out_of_scope') {
    message = `${host} is explicitly out of scope for ${r.outOfScope[0].name}. Do not test it.`;
  } else if (d.found) {
    message = `Program found for ${host}: ${d.programs[0].platform}`;
  } else if (r.state === 'related') {
    message = `${r.root} has a program (${r.related[0].name}) but ${host} isn’t listed in its scope.`;
  } else if (r.state === 'nodata') {
    message = `${host}: no program found in local checks. (Scope database not synced yet, open the dashboard to sync.)`;
  } else {
    message = `No public bug bounty / VDP found for ${host}.`;
  }
  chrome.notifications.create(`scopehound-check-${Date.now()}`, { type: 'basic', iconUrl: 'icons/icon128.png', title, message, priority: 1 });
}

chrome.notifications.onClicked.addListener((id) => {
  if (id.startsWith('scopehound-radar')) chrome.tabs.create({ url: chrome.runtime.getURL('options.html#radar') });
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === RADAR_ALARM) {
    syncRadar({ manual: false }).catch(() => {});
    return;
  }
  if (alarm.name.startsWith('scopehound-followup:')) {
    const domain = alarm.name.split(':')[1];
    chrome.notifications.create(`scopehound-followup-${domain}-${Date.now()}`, {
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: 'ScopeRadar: follow-up reminder',
      message: `It's been a while since you reached out to ${domain}. Consider a polite follow-up.`,
      priority: 1,
    });
  }
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local') return;
  if (changes.radarParts) {
    radarPartsCache = null;
    domainCache.clear();
  }
  if (changes.radarSettings) ensureRadarAlarm();
});

/* ---------------------------------------------------------------------- */
/* Scope Radar: local index, sync, diff                                   */
/* ---------------------------------------------------------------------- */

let radarPartsCache = null;

async function getRadarParts() {
  if (!radarPartsCache) {
    const { radarParts } = await chrome.storage.local.get('radarParts');
    radarPartsCache = radarParts || {};
  }
  return radarPartsCache;
}

async function radarMatch(domain) {
  const parts = await getRadarParts();
  const hasData = Object.keys(parts).length > 0;
  const match = ScopeRadar.matchHost(parts, domain);
  return Object.assign({ state: ScopeRadar.radarState(match, hasData), hasData }, match);
}

// Flattens every synced platform's program list into one array, for the
// dashboard's browsable "all programs" view.
async function listRadarPrograms() {
  const parts = await getRadarParts();
  const programs = [];
  ScopeRadar.PLATFORMS.forEach((platform) => {
    const part = parts[platform];
    if (!part) return;
    part.programs.forEach((p) => {
      if (!p || !p.u) return;
      programs.push({ platform, name: p.n || '(unnamed)', url: p.u, bounty: !!p.b, maxPayout: p.mx || null, currency: p.cu || null });
    });
  });
  programs.sort((a, b) => a.name.localeCompare(b.name));
  return { programs, total: programs.length, hasData: Object.keys(parts).length > 0 };
}

async function getAllProgramsList() {
  const parts = await getRadarParts();
  const list = [];
  Object.keys(parts).forEach((platform) => {
    const part = parts[platform];
    (part.programs || []).forEach((p) => {
      if (!p || !p.u) return;
      const name = String(p.n || p.u).replace(/\s+/g, ' ').trim();
      list.push({ platform, name, url: p.u, bounty: !!p.b, maxPayout: p.mx || null, currency: p.cu || null });
    });
  });
  list.sort((a, b) => (a.name || '').localeCompare(b.name || ''));
  return { programs: list };
}

async function ensureRadarAlarm() {
  try {
    const { radarSettings } = await chrome.storage.local.get('radarSettings');
    const hours = radarSettings && radarSettings.intervalHours !== undefined ? radarSettings.intervalHours : 24;
    const existing = await chrome.alarms.get(RADAR_ALARM);
    if (!hours) {
      if (existing) await chrome.alarms.clear(RADAR_ALARM);
      return;
    }
    if (!existing || existing.periodInMinutes !== hours * 60) {
      await chrome.alarms.create(RADAR_ALARM, { delayInMinutes: 5, periodInMinutes: hours * 60 });
    }
  } catch (err) {
    console.error('ScopeRadar: alarm setup failed', err);
  }
}

async function setRadarMeta(patch) {
  const { radarMeta } = await chrome.storage.local.get('radarMeta');
  await chrome.storage.local.set({ radarMeta: Object.assign({}, radarMeta, patch) });
}

let syncPromise = null;
function syncRadar(opts) {
  if (!syncPromise) syncPromise = doRadarSync(opts || {}).finally(() => { syncPromise = null; });
  return syncPromise;
}

async function doRadarSync() {
  // Keep the service worker alive during a long download on slow networks.
  const keepAlive = setInterval(() => chrome.runtime.getPlatformInfo(() => {}), 20000);
  try {
    await setRadarMeta({ syncing: true, stage: 'Starting…', lastError: null });
    const { radarParts = {}, radarMeta = {}, radarFeed = [], radarSettings = {} } = await chrome.storage.local.get(['radarParts', 'radarMeta', 'radarFeed', 'radarSettings']);

    const etags = Object.assign({}, radarMeta.etags);
    const newParts = Object.assign({}, radarParts);
    const hadBaseline = Object.keys(radarParts).length > 0;
    const events = [];
    const errors = [];
    let updatedAny = false;

    for (const platform of ScopeRadar.PLATFORMS) {
      const label = platformLabel(platform);
      try {
        await setRadarMeta({ stage: `Downloading ${label}…` });
        const headers = {};
        if (etags[platform] && radarParts[platform]) headers['If-None-Match'] = etags[platform];
        const resp = await fetch(`${DATASET_BASE}${platform}_data.json`, { headers });
        if (resp.status === 304) continue; // unchanged since last sync
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

        await setRadarMeta({ stage: `Indexing ${label}…` });
        const raw = await resp.json();
        const part = ScopeRadar.buildPart(platform, raw);
        if (hadBaseline && radarParts[platform]) events.push(...ScopeRadar.diffParts(radarParts[platform], part));
        newParts[platform] = part;
        etags[platform] = resp.headers.get('etag') || null;
        updatedAny = true;
      } catch (err) {
        errors.push(`${label}: ${err.message}`);
      }
    }

    if (updatedAny) await chrome.storage.local.set({ radarParts: newParts });

    const counts = {};
    let programs = 0;
    let assets = 0;
    ScopeRadar.PLATFORMS.forEach((p) => {
      if (!newParts[p]) return;
      counts[p] = { programs: newParts[p].programs.length, assets: ScopeRadar.countAssets(newParts[p]) };
      programs += counts[p].programs;
      assets += counts[p].assets;
    });

    // Feed + notifications (never on the very first baseline sync)
    if (events.length) await recordRadarEvents(events, radarFeed, radarSettings);

    await setRadarMeta({
      syncing: false,
      stage: '',
      etags,
      counts,
      totals: { programs, assets },
      lastError: errors.length ? errors.join(' • ') : null,
      updatedAt: errors.length && !updatedAny && !hadBaseline ? null : Date.now(),
      baseline: !hadBaseline && updatedAny,
    });
    return { ok: !errors.length, errors, events: events.length };
  } catch (err) {
    await setRadarMeta({ syncing: false, stage: '', lastError: err.message });
    return { ok: false, errors: [err.message], events: 0 };
  } finally {
    clearInterval(keepAlive);
  }
}

async function recordRadarEvents(events, feed, settings) {
  const tracker = await getTracker();
  const watchedRoots = new Set(Object.keys(tracker).map((d) => ScopeRadar.getRootDomain(d)));
  const now = Date.now();

  const stamped = events.map((e, i) => {
    const roots = e.assets.map((a) => ScopeRadar.getRootDomain(a.replace(/^\*\./, '')));
    return Object.assign({ id: `${now}-${i}`, ts: now, watched: roots.some((r) => watchedRoots.has(r)) }, e);
  });

  const updated = stamped.concat(feed).slice(0, FEED_MAX);
  await chrome.storage.local.set({ radarFeed: updated });

  if (settings.notify === false) return;
  const newPrograms = stamped.filter((e) => e.type === 'new_program').length;
  const newScope = stamped.filter((e) => e.type === 'new_scope').length;
  const parts = [];
  if (newPrograms) parts.push(`${newPrograms} new program${newPrograms > 1 ? 's' : ''}`);
  if (newScope) parts.push(`new scope on ${newScope} program${newScope > 1 ? 's' : ''}`);
  if (parts.length) {
    chrome.notifications.create(`scopehound-radar-${now}`, { type: 'basic', iconUrl: 'icons/icon128.png', title: 'ScopeRadar Radar', message: `${parts.join(' · ')}. Open the dashboard to see them.`, priority: 1 });
  }
  stamped.filter((e) => e.watched).slice(0, 3).forEach((e, i) => {
    chrome.notifications.create(`scopehound-radar-watched-${now}-${i}`, {
      type: 'basic', iconUrl: 'icons/icon128.png', title: 'A domain you track changed',
      message: `${e.type === 'new_program' ? 'New program' : 'New scope'}: ${platformLabel(e.platform)} · ${e.name}${e.assets.length ? ': ' + e.assets.slice(0, 2).join(', ') : ''}`, priority: 2,
    });
  });
}

/* ---------------------------------------------------------------------- */
/* Tab lifecycle -> badge (LOCAL data only, no requests to visited sites) */
/* ---------------------------------------------------------------------- */

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab && tab.url && tab.active) handleTab(tab.url, tabId);
});

chrome.tabs.onActivated.addListener((activeInfo) => {
  chrome.tabs.get(activeInfo.tabId).then((tab) => { if (tab && tab.url) handleTab(tab.url, activeInfo.tabId); }).catch(() => {});
});

function handleTab(url, tabId) {
  try {
    if (isExtensionUrl(url) || !/^https?:/i.test(url)) { clearBadge(tabId); return; }
    updateBadgeForDomain(new URL(url).hostname, tabId).catch((err) => console.error('ScopeRadar:', err));
  } catch { clearBadge(tabId); }
}

function isExtensionUrl(url) {
  return url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('moz-extension://') || url.startsWith('edge://') || url.startsWith('about:');
}

function clearBadge(tabId) { chrome.action.setBadgeText({ text: '', tabId }).catch(() => {}); }

async function updateBadgeForDomain(domain, tabId) {
  try { await chrome.tabs.get(tabId); } catch { return; }
  const local = await localLookup(domain);
  const radar = local.radar;
  let kind = 'none';
  if (local.programs.some((p) => p.confidence === 'high')) kind = 'found';
  else if (radar.state === 'out_of_scope' || radar.state === 'related') kind = 'partial';
  else if (radar.state === 'nodata') kind = 'nodata';
  await paintBadge(kind, tabId);
}

async function paintBadge(kind, tabId) {
  const styles = {
    found: ['IN', '#10B981', 'ScopeRadar: program found / in scope'],
    partial: ['!', '#F97316', 'ScopeRadar: company has a program, but this host is not in its scope'],
    nodata: ['?', '#64748B', 'ScopeRadar: scope database not synced yet (open the dashboard)'],
    none: ['NO', '#F59E0B', 'ScopeRadar: no known program (open for deeper checks / outreach)'],
  };
  const [text, color, title] = styles[kind];
  try {
    await chrome.tabs.get(tabId);
    await chrome.action.setBadgeText({ text, tabId });
    await chrome.action.setBadgeBackgroundColor({ color, tabId });
    await chrome.action.setTitle({ title, tabId });
  } catch {}
}

/* ---------------------------------------------------------------------- */
/* Messaging                                                              */
/* ---------------------------------------------------------------------- */

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || !msg.action) return false;

  const handlers = {
    runLookup: () => runLookupForActiveTab(),
    getTracker: () => getTracker().then((tracker) => ({ tracker })),
    upsertTrackerEntry: () => upsertTrackerEntry(msg.entry).then(() => ({ ok: true })),
    deleteTrackerEntry: () => deleteTrackerEntry(msg.domain).then(() => ({ ok: true })),
    getSubdomains: () => fetchSubdomains(msg.domain).then((subdomains) => ({ subdomains })),
    listRadarPrograms: () => listRadarPrograms(),
    scheduleReminder: () => scheduleReminder(msg.domain, msg.days).then(() => ({ ok: true })),
    recordOutreachSent: () => recordOutreachSent(msg.domain).then((entry) => ({ entry })),
    radarSync: () => syncRadar({ manual: true }),
    getAllPrograms: () => getAllProgramsList(),
    checkSafeHarbor: () => checkSafeHarbor(msg.url),
  };

  if (handlers[msg.action]) {
    handlers[msg.action]().then(sendResponse).catch((err) => sendResponse({ error: err.message }));
    return true;
  }
  return false;
});

async function runLookupForActiveTab() {
  const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  if (!tabs || !tabs.length || !tabs[0].url) throw new Error('No active tab found');
  const domain = new URL(tabs[0].url).hostname;
  return performLookup(domain, tabs[0].id, { network: true });
}

/* ---------------------------------------------------------------------- */
/* Detection                                                              */
/* ---------------------------------------------------------------------- */

// Local-only: radar index + curated list + URL patterns. Zero network.
async function localLookup(domain) {
  const radar = await radarMatch(domain);
  const programs = [];

  radar.inScope.forEach((m) => {
    programs.push({
      platform: `${platformLabel(m.platform)} · ${m.name}`, link: m.url, scope: domain, confidence: 'high',
      meta: { source: 'radar' },
    });
  });

  const root = ScopeRadar.getRootDomain(domain);
  if (KNOWN_PROGRAMS[root]) programs.push({ platform: 'Known program (curated list)', link: KNOWN_PROGRAMS[root], scope: domain, confidence: 'high' });
  if (PROGRAM_PREFIXES.some((p) => domain.startsWith(p))) programs.push({ platform: 'Program page (URL pattern)', link: `https://${domain}/`, scope: domain, confidence: 'high' });
  else if (WEAK_PREFIXES.some((p) => domain.startsWith(p))) programs.push({ platform: 'Security-related subdomain (unverified)', link: `https://${domain}/`, scope: domain, confidence: 'low' });

  return { radar, programs };
}

async function performLookup(domain, tabId, opts) {
  const network = !!(opts && opts.network);
  try {
    const { radar, programs } = await localLookup(domain);

    let secTxtRaw = null;
    if (network) {
      secTxtRaw = await fetchWithTimeout([`https://${domain}/.well-known/security.txt`, `https://${domain}/security.txt`], 5000);
      if (secTxtRaw) programs.push(...parseSecurityTxtPolicy(secTxtRaw, domain));

      if (!programs.some((p) => p.confidence === 'high')) {
        if (tabId != null) {
          const signal = await getRenderedPageSignal(tabId);
          if (signal) programs.push(...parseRenderedSignal(signal, domain));
        }
        if (!programs.length) {
          const html = await fetchWithTimeout([`https://${domain}/`], 8000);
          if (html) programs.push(...parseHomepageHtml(html, domain));
        }
      }
    }

    const unique = dedupePrograms(programs);
    const confirmed = unique.filter((p) => p.confidence === 'high');
    return {
      message: confirmed.length ? `Program found for ${domain}` : `No confirmed program for ${domain}`,
      data: {
        found: confirmed.length > 0,
        possible: !confirmed.length && unique.length > 0,
        programs: unique,
        domain,
        radar,
        contact: extractContact(secTxtRaw) || `security@${domain}`,
        secTxt: secTxtRaw ? parseSecurityTxtFull(secTxtRaw) : null,
      },
    };
  } catch (err) {
    throw new Error(`Lookup failed: ${err.message}`);
  }
}

async function getRenderedPageSignal(tabId) {
  try {
    const injections = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => ({
        text: document.body ? document.body.innerText.slice(0, 60000) : '',
        links: Array.from(document.querySelectorAll('a[href]')).map((a) => a.href).slice(0, 500),
      }),
    });
    return injections && injections[0] ? injections[0].result : null;
  } catch { return null; }
}

function parseRenderedSignal(signal, domain) {
  const programs = [];
  const { text, links } = signal;
  (links || []).forEach((link) => {
    if (isPlatformProgramLink(link)) programs.push({ platform: 'Link on page', link, scope: domain, confidence: 'high' });
  });
  if (text && CONTENT_KEYWORDS.test(text)) programs.push({ platform: 'Page mentions bug bounty / VDP (unverified)', link: `https://${domain}/`, scope: domain, confidence: 'low' });
  return programs;
}

function parseHomepageHtml(html, domain) {
  const programs = [];
  const hrefRegex = /href=["']([^"']+)["']/gi;
  let m;
  while ((m = hrefRegex.exec(html)) !== null) {
    let link = m[1];
    if (link.startsWith('/')) link = `https://${domain}${link}`;
    if (isPlatformProgramLink(link)) programs.push({ platform: 'Homepage link', link, scope: domain, confidence: 'high' });
  }
  if (CONTENT_KEYWORDS.test(html)) programs.push({ platform: 'Homepage mentions bug bounty / VDP (unverified)', link: `https://${domain}/`, scope: domain, confidence: 'low' });
  return programs;
}

async function fetchWithTimeout(urls, timeoutMs) {
  for (const url of urls) {
    try {
      const controller = new AbortController();
      const t = setTimeout(() => controller.abort(), timeoutMs);
      const resp = await fetch(url, { method: 'GET', signal: controller.signal });
      clearTimeout(t);
      if (resp.ok) return await resp.text();
    } catch {}
  }
  return null;
}

/* -------- security.txt -------- */

function secField(txt, name) {
  const m = txt.match(new RegExp(`^\\s*${name}\\s*:\\s*(.+)$`, 'im'));
  return m ? m[1].trim() : null;
}

function parseSecurityTxtPolicy(txt, domain) {
  const programs = [];
  txt.split(/\r?\n/).forEach((line) => {
    const m = line.match(/^\s*Policy\s*:\s*(https?:\/\/\S+)/i) || line.match(/^\s*Hiring\s*:\s*(https?:\/\/\S+)/i);
    if (m) programs.push({ platform: 'security.txt Policy', link: m[1], scope: domain, confidence: 'high' });
  });
  return programs;
}

function extractContact(txt) {
  if (!txt) return null;
  const mail = txt.match(/^\s*Contact\s*:\s*mailto:([^\s]+)/im);
  if (mail) return mail[1];
  const url = txt.match(/^\s*Contact\s*:\s*(https?:\/\/\S+)/im);
  return url ? url[1] : null;
}

function parseSecurityTxtFull(txt) {
  const expiresRaw = secField(txt, 'Expires');
  let expired = null;
  if (expiresRaw) {
    const d = new Date(expiresRaw);
    if (!isNaN(d.getTime())) expired = d.getTime() < Date.now();
  }
  return {
    contact: secField(txt, 'Contact'),
    policy: secField(txt, 'Policy'),
    expires: expiresRaw,
    expired,
    encryption: secField(txt, 'Encryption'),
    acknowledgments: secField(txt, 'Acknowledgments') || secField(txt, 'Acknowledgements'),
    preferredLanguages: secField(txt, 'Preferred-Languages'),
    canonical: secField(txt, 'Canonical'),
  };
}

/* -------- platform probing (only when nothing else found) -------- */

function dedupePrograms(list) {
  const map = new Map();
  for (const p of list) {
    let key;
    try { key = new URL(p.link).href.replace(/\/$/, ''); } catch { key = p.link; }
    const cur = map.get(key);
    if (!cur || (cur.confidence === 'low' && p.confidence === 'high')) map.set(key, p);
  }
  return Array.from(map.values());
}

/* ---------------------------------------------------------------------- */
/* Safe-harbor check                                                      */
/* ---------------------------------------------------------------------- */

async function checkSafeHarbor(url) {
  if (!url) throw new Error('No policy URL to check');
  let text = null;

  // If the policy is the page you're on, read the rendered DOM (works for SPAs).
  try {
    const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    const tab = tabs && tabs[0];
    if (tab && tab.url && tab.id != null && new URL(tab.url).hostname === new URL(url).hostname) {
      const sig = await getRenderedPageSignal(tab.id);
      if (sig && sig.text) text = sig.text;
    }
  } catch {}

  if (!text || text.length < 300) {
    const html = await fetchWithTimeout([url], 10000);
    if (html) text = ScopeSafeHarbor.htmlToText(html);
  }

  const result = ScopeSafeHarbor.analyzeText(text);
  return Object.assign({ source: url }, result);
}

/* ---------------------------------------------------------------------- */
/* Passive OSINT recon: certificate transparency (crt.sh)                */
/* ---------------------------------------------------------------------- */

async function fetchSubdomains(domain) {
  try {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), 12000);
    const resp = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, { signal: controller.signal });
    clearTimeout(t);
    if (!resp.ok) return [];
    const data = await resp.json();
    const set = new Set();
    data.forEach((row) => {
      String(row.name_value || '').split('\n').forEach((n) => {
        const name = n.trim().toLowerCase();
        if (name && name.endsWith(domain) && !name.includes('*')) set.add(name);
      });
    });
    return Array.from(set).sort().slice(0, 200);
  } catch (err) {
    console.error('ScopeRadar: crt.sh lookup failed', err);
    return [];
  }
}

/* ---------------------------------------------------------------------- */
/* Follow-up reminders                                                    */
/* ---------------------------------------------------------------------- */

async function scheduleReminder(domain, days) {
  const alarmName = `scopehound-followup:${domain}`;
  await chrome.alarms.clear(alarmName);
  await chrome.alarms.create(alarmName, { delayInMinutes: days * 24 * 60 });
  await upsertTrackerEntry({ domain, reminderDays: days, reminderSetAt: Date.now() });
}

/* ---------------------------------------------------------------------- */
/* Outreach tracker (chrome.storage.local)                                */
/* ---------------------------------------------------------------------- */

async function getTracker() {
  const { scopehoundTracker } = await chrome.storage.local.get('scopehoundTracker');
  return scopehoundTracker || {};
}

async function upsertTrackerEntry(entry) {
  if (!entry || !entry.domain) throw new Error('Tracker entry needs a domain');
  const tracker = await getTracker();
  const prev = tracker[entry.domain];
  tracker[entry.domain] = Object.assign({}, prev, entry, { updatedAt: Date.now() });
  await chrome.storage.local.set({ scopehoundTracker: tracker });

  return tracker[entry.domain];
}

async function deleteTrackerEntry(domain) {
  const tracker = await getTracker();
  delete tracker[domain];
  await chrome.storage.local.set({ scopehoundTracker: tracker });
  await chrome.alarms.clear(`scopehound-followup:${domain}`);
}

async function recordOutreachSent(domain) {
  const tracker = await getTracker();
  const existing = tracker[domain] || { domain };
  const updated = Object.assign({}, existing, { domain, emailsSent: (existing.emailsSent || 0) + 1, lastRequestedAt: Date.now(), updatedAt: Date.now() });
  tracker[domain] = updated;
  await chrome.storage.local.set({ scopehoundTracker: tracker });
  return updated;
}
