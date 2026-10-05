// safeharbor.js: ScopeRadar "Safe Harbor detector"
// Part of the ScopeRadar browser extension. See LICENSE for terms.
// Original author: Muhammad Rebaal (github.com/iamzeropoison)
//
// Scans a vulnerability-disclosure / bounty policy's text for legal-protection
// ("safe harbor") language, and ALSO for the opposite: language reserving the
// right to take legal action, so a researcher can see at a glance whether a
// program promises not to come after good-faith testing.
//
// This is a keyword heuristic. It can miss phrasing and can be fooled by
// context. It is NOT legal advice: always read the full policy yourself.

(function (root) {
  'use strict';

  const STRONG = [
    /safe[\s-]?harbou?r/i,
    /(?:will|would|shall)\s+not\s+(?:pursue|initiate|bring|recommend|take|seek|file|commence|start)\b[^.]{0,80}\b(?:legal|civil|criminal|law[\s-]?enforcement|lawsuit)/i,
    /(?:will|would|shall)\s+not\s+(?:prosecute|sue)\b/i,
    /\bno\s+(?:legal|civil|criminal)\s+(?:action|proceedings?|claims?)\b/i,
    /(?:consider(?:ed)?|deem(?:ed)?|regard(?:ed)?|treated?)\b[^.]{0,60}\bauthori[sz]ed\b/i,
    /disclose\.io/i,
    /gold\s+standard/i,
    /\b(?:CFAA|Computer\s+Fraud\s+and\s+Abuse\s+Act)\b/i,
  ];

  const WEAK = [/good[\s-]faith/i, /legal\s+(?:protection|safe)/i, /\bauthori[sz]ed\s+(?:testing|research|access|conduct)\b/i];

  const NEGATIVE = [
    /reserve[sd]?\s+the\s+right\s+to\s+(?:pursue|take|initiate|seek|bring)\b[^.]{0,60}(?:legal|civil|criminal)/i,
    /(?:may|will|shall|can|could)\s+(?:pursue|take|initiate|seek|bring)\s+[^.]{0,30}(?:legal|civil|criminal)\s+(?:action|remed|proceedings?)/i,
    /(?:will|may|shall)\s+(?:prosecute|sue)\b/i,
    /(?:violat|breach)[^.]{0,60}(?:prosecut|legal\s+action|criminal)/i,
  ];

  function htmlToText(html) {
    return String(html || '')
      .replace(/<(script|style|noscript)\b[\s\S]*?<\/\1>/gi, ' ')
      .replace(/<[^>]+>/g, ' ')
      .replace(/&nbsp;/gi, ' ')
      .replace(/&amp;/gi, '&')
      .replace(/&quot;/gi, '"')
      .replace(/&#0?39;|&apos;/gi, "'")
      .replace(/&lt;/gi, '<')
      .replace(/&gt;/gi, '>')
      .replace(/\s+/g, ' ')
      .trim();
  }

  function collect(text, patterns, kind, evidence, used) {
    let hits = 0;
    patterns.forEach((re) => {
      const m = re.exec(text);
      if (!m) return;
      hits++;
      const start = m.index;
      if (used.some(([a, b]) => start >= a - 40 && start <= b + 40)) return; // avoid near-duplicate snippets
      const from = Math.max(0, start - 70);
      const to = Math.min(text.length, start + m[0].length + 70);
      used.push([from, to]);
      evidence.push({ kind, text: `${from > 0 ? '…' : ''}${text.slice(from, to).trim()}${to < text.length ? '…' : ''}` });
    });
    return hits;
  }

  /**
   * @returns {{level: 'explicit'|'mixed'|'weak'|'negative'|'none'|'unknown',
   *            evidence: {kind: string, text: string}[], chars: number}}
   */
  function analyzeText(rawText) {
    const text = String(rawText || '').replace(/\s+/g, ' ').trim();
    if (text.length < 300) return { level: 'unknown', evidence: [], chars: text.length };

    const evidence = [];
    // De-duplicate overlapping snippets only within the same kind, so a
    // "mixed" policy always surfaces BOTH its protective and its threatening line.
    const strong = collect(text, STRONG, 'strong', evidence, []);
    const negative = collect(text, NEGATIVE, 'negative', evidence, []);
    const weak = collect(text, WEAK, 'weak', evidence, []);

    let level = 'none';
    if (strong && negative) level = 'mixed';
    else if (strong) level = 'explicit';
    else if (negative) level = 'negative';
    else if (weak) level = 'weak';

    return { level, evidence: evidence.slice(0, 5), chars: text.length };
  }

  const LEVEL_INFO = {
    explicit: { label: 'Safe-harbor language found', tone: 'good' },
    mixed: { label: 'Safe harbor AND legal-action language (read carefully)', tone: 'warn' },
    weak: { label: 'Mentions good-faith research, but no explicit legal protection', tone: 'warn' },
    negative: { label: 'Reserves the right to take legal action', tone: 'bad' },
    none: { label: 'No safe-harbor language found in this text', tone: 'warn' },
    unknown: { label: 'Not enough policy text to judge', tone: 'neutral' },
  };

  const api = { analyzeText, htmlToText, LEVEL_INFO };
  root.ScopeSafeHarbor = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof self !== 'undefined' ? self : this);
