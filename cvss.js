// cvss.js: CVSS v3.1 Base Score calculator (FIRST.org specification)
// Part of the ScopeRadar browser extension. See LICENSE for terms.
// Original author: Muhammad Rebaal (github.com/iamzeropoison)
// https://www.first.org/cvss/v3.1/specification-document
//
// Base metrics only (the score researchers put in a report). Temporal /
// environmental metrics are intentionally out of scope.

(function (root) {
  'use strict';

  const WEIGHTS = {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
    AC: { L: 0.77, H: 0.44 },
    UI: { N: 0.85, R: 0.62 },
    CIA: { H: 0.56, L: 0.22, N: 0 },
    PR: {
      U: { N: 0.85, L: 0.62, H: 0.27 }, // Scope Unchanged
      C: { N: 0.85, L: 0.68, H: 0.5 }, // Scope Changed
    },
  };

  const LABELS = {
    AV: { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' },
    AC: { L: 'Low', H: 'High' },
    PR: { N: 'None', L: 'Low', H: 'High' },
    UI: { N: 'None', R: 'Required' },
    S: { U: 'Unchanged', C: 'Changed' },
    C: { N: 'None', L: 'Low', H: 'High' },
    I: { N: 'None', L: 'Low', H: 'High' },
    A: { N: 'None', L: 'Low', H: 'High' },
  };

  // Spec Appendix A: round up to one decimal, avoiding floating point error.
  function roundUp(input) {
    const int = Math.round(input * 100000);
    if (int % 10000 === 0) return int / 100000;
    return (Math.floor(int / 10000) + 1) / 10;
  }

  function severity(score) {
    if (score === 0) return 'None';
    if (score < 4.0) return 'Low';
    if (score < 7.0) return 'Medium';
    if (score < 9.0) return 'High';
    return 'Critical';
  }

  function isValid(m) {
    return !!m && ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'].every((k) => LABELS[k] && LABELS[k][m[k]]);
  }

  function cvss31(m) {
    if (!isValid(m)) throw new Error('Invalid CVSS metrics');
    const changed = m.S === 'C';

    const iss = 1 - (1 - WEIGHTS.CIA[m.C]) * (1 - WEIGHTS.CIA[m.I]) * (1 - WEIGHTS.CIA[m.A]);
    const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
    const exploitability = 8.22 * WEIGHTS.AV[m.AV] * WEIGHTS.AC[m.AC] * WEIGHTS.PR[changed ? 'C' : 'U'][m.PR] * WEIGHTS.UI[m.UI];

    let score = 0;
    if (impact > 0) {
      score = changed ? roundUp(Math.min(1.08 * (impact + exploitability), 10)) : roundUp(Math.min(impact + exploitability, 10));
    }

    return {
      score,
      severity: severity(score),
      vector: `CVSS:3.1/AV:${m.AV}/AC:${m.AC}/PR:${m.PR}/UI:${m.UI}/S:${m.S}/C:${m.C}/I:${m.I}/A:${m.A}`,
      impact: Math.round(impact * 10) / 10,
      exploitability: Math.round(exploitability * 10) / 10,
    };
  }

  function parseVector(str) {
    if (typeof str !== 'string') return null;
    const m = {};
    str.split('/').forEach((part) => {
      const [k, v] = part.split(':');
      if (k && v && k !== 'CVSS') m[k.trim().toUpperCase()] = v.trim().toUpperCase();
    });
    return isValid(m) ? m : null;
  }

  const api = { cvss31, parseVector, severity, roundUp, LABELS };
  root.ScopeCVSS = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof self !== 'undefined' ? self : this);
