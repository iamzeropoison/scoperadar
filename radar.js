// radar.js: the scope-matching engine behind ScopeRadar
// Part of the ScopeRadar browser extension. See LICENSE for terms.
// Original author: Muhammad Rebaal (github.com/iamzeropoison)
//
// Turns the public bounty-targets-data dumps (HackerOne, Bugcrowd, Intigriti,
// YesWeHack) into a compact per-platform index that can answer:
//   • Is this host IN scope of a known public program? (exact / wildcard)
//   • Is it explicitly OUT of scope? (out-of-scope beats in-scope when it is
//     at least as specific)
//   • Does the same company have a program even if this host isn't listed?
// and can diff two syncs to surface NEW programs and NEW scope assets.
//
// Pure logic, no chrome.* calls. Works in the service worker (importScripts),
// in extension pages (<script>), and in Node for tests.

(function (root) {
  'use strict';

  /* -------------------------------------------------------------------- */
  /* Host helpers                                                          */
  /* -------------------------------------------------------------------- */

  // Common multi-part public suffixes so root-domain detection isn't naive.
  // (Not the full Public Suffix List, a pragmatic subset.)
  const MULTI_TLDS = new Set([
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'ltd.uk', 'plc.uk',
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
    'co.nz', 'org.nz', 'net.nz',
    'co.in', 'net.in', 'org.in', 'ac.in', 'gov.in', 'firm.in',
    'com.pk', 'org.pk', 'net.pk', 'edu.pk', 'gov.pk',
    'com.bd', 'com.lk', 'com.np',
    'com.br', 'com.mx', 'com.ar', 'com.co', 'com.pe', 'com.ve', 'com.uy',
    'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'go.jp',
    'co.kr', 'or.kr', 'go.kr',
    'co.za', 'org.za', 'gov.za',
    'com.sg', 'com.my', 'com.ph', 'com.vn', 'co.id', 'co.th', 'com.hk', 'com.tw', 'com.cn', 'net.cn', 'org.cn',
    'com.tr', 'com.sa', 'com.eg', 'com.ng', 'co.ke', 'co.il', 'com.ua', 'com.pl', 'com.ru',
    'co.ae', 'com.qa', 'com.kw',
  ]);

  // Reserved documentation domains (RFC 2606), programs sometimes list these
  // as out-of-scope examples; they're never real targets.
  const RESERVED_ROOTS = new Set(['example.com', 'example.org', 'example.net']);

  function normalizeHost(h) {
    return String(h || '').trim().toLowerCase().replace(/\.$/, '');
  }

  function getRootDomain(hostname) {
    const host = normalizeHost(hostname);
    const parts = host.split('.');
    if (parts.length <= 2) return host;
    const lastTwo = parts.slice(-2).join('.');
    if (MULTI_TLDS.has(lastTwo)) return parts.slice(-3).join('.');
    return lastTwo;
  }

  function isIp(s) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(s);
  }

  // Generic third-party hosts that appear in "OTHER"/"source code"/"app store"
  // style assets. If a program lists a GitHub repo, that does NOT put
  // github.com in scope, so these are ignored unless the asset is explicitly
  // typed as a web URL / wildcard.
  const GENERIC_HOSTS = new Set([
    'github.com', 'gist.github.com', 'gitlab.com', 'bitbucket.org', 'sourceforge.net',
    'play.google.com', 'apps.apple.com', 'itunes.apple.com', 'testflight.apple.com',
    'chrome.google.com', 'chromewebstore.google.com', 'addons.mozilla.org',
    'microsoftedge.microsoft.com', 'apps.microsoft.com',
    'npmjs.com', 'www.npmjs.com', 'pypi.org', 'rubygems.org', 'crates.io', 'packagist.org',
    'hub.docker.com', 'marketplace.visualstudio.com', 'marketplace.atlassian.com',
    'twitter.com', 'x.com', 'facebook.com', 'linkedin.com', 'youtube.com', 'instagram.com',
    'docs.google.com', 'drive.google.com', 'medium.com', 'wordpress.org', 'etherscan.io',
  ]);

  /**
   * Extract host patterns from a raw scope identifier.
   * Returns [{ host, wildcard, path }]. `trusted` = the platform typed this
   * asset as a web URL / wildcard (so generic hosts are allowed).
   */
  function extractPatterns(raw, trusted) {
    const inputs = Array.isArray(raw) ? raw : [raw];
    const out = [];
    inputs.forEach((one) => {
      if (!one || typeof one !== 'string') return;
      one.split(/[\s,;|]+/).forEach((tok) => {
        let s = tok.trim().toLowerCase();
        if (!s || s.includes('@')) return;

        let hasPath = false;
        s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, ''); // scheme
        const cut = s.search(/[/?#]/);
        if (cut !== -1) {
          const rest = s.slice(cut);
          hasPath = rest.replace(/^\/+$/, '') !== '' && rest !== '/';
          s = s.slice(0, cut);
        }
        s = s.replace(/:\d+$/, '').replace(/\.$/, '');
        if (!s) return;

        let wildcard = false;
        if (s.startsWith('*')) {
          wildcard = true;
          s = s.replace(/^\*+\.?/, '');
        }
        if (s.includes('*')) {
          const i = s.lastIndexOf('*.');
          if (i === -1) return;
          s = s.slice(i + 2);
          wildcard = true;
        }
        if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(s)) return; // hostname with a dot
        if (isIp(s)) return;
        if (!/[a-z]{2,}$/.test(s)) return; // TLD-ish (drops "e.g", "i.e")
        if (!trusted && GENERIC_HOSTS.has(s)) return;

        out.push({ host: s, wildcard, path: hasPath });
      });
    });
    return out;
  }

  /* -------------------------------------------------------------------- */
  /* Platform adapters (map each dataset's schema to a common shape)       */
  /* -------------------------------------------------------------------- */

  const H1_TRUSTED = new Set(['URL', 'WILDCARD']);
  const H1_USABLE = new Set(['URL', 'WILDCARD', 'API', 'OTHER']);

  const ADAPTERS = {
    hackerone: {
      label: 'HackerOne',
      program(p) {
        if (!p || !p.url) return null;
        return {
          n: p.name || p.handle, u: p.url, b: p.offers_bounties ? 1 : 0,
          re: typeof p.response_efficiency_percentage === 'number' ? p.response_efficiency_percentage : null,
        };
      },
      assets(p) {
        const t = p.targets || {};
        const conv = (list, oos) =>
          (list || [])
            .filter((a) => H1_USABLE.has(a.asset_type) && (oos || a.eligible_for_submission !== false))
            .map((a) => ({ raw: a.asset_identifier, trusted: H1_TRUSTED.has(a.asset_type), bounty: oos ? false : !!a.eligible_for_bounty }));
        return { in: conv(t.in_scope, false), out: conv(t.out_of_scope, true) };
      },
    },

    bugcrowd: {
      label: 'Bugcrowd',
      program(p) {
        if (!p || !p.url) return null;
        const max = typeof p.max_payout === 'number' ? p.max_payout : 0;
        return { n: p.name, u: p.url, b: max > 0 ? 1 : 0, mx: max || null, cu: 'USD', sh: p.safe_harbor || null };
      },
      assets(p) {
        const t = p.targets || {};
        const ok = new Set(['website', 'api', 'other']);
        const bounty = typeof p.max_payout === 'number' && p.max_payout > 0;
        const conv = (list, oos) =>
          (list || [])
            .filter((a) => ok.has(a.type))
            .map((a) => ({ raw: [a.uri, a.target], trusted: a.type === 'website', bounty: oos ? false : bounty }));
        return { in: conv(t.in_scope, false), out: conv(t.out_of_scope, true) };
      },
    },

    intigriti: {
      label: 'Intigriti',
      program(p) {
        if (!p || !p.url) return null;
        const max = p.max_bounty && typeof p.max_bounty.value === 'number' ? p.max_bounty.value : 0;
        return { n: p.name, u: p.url, b: max > 0 ? 1 : 0, mx: max || null, cu: (p.max_bounty && p.max_bounty.currency) || null };
      },
      assets(p) {
        const t = p.targets || {};
        const ok = new Set(['url', 'wildcard', 'other', 'api']);
        const bounty = !!(p.max_bounty && p.max_bounty.value > 0);
        const conv = (list, oos) =>
          (list || [])
            .filter((a) => ok.has(a.type))
            .map((a) => ({ raw: a.endpoint, trusted: a.type === 'url' || a.type === 'wildcard', bounty: oos ? false : bounty }));
        return { in: conv(t.in_scope, false), out: conv(t.out_of_scope, true) };
      },
    },

    yeswehack: {
      label: 'YesWeHack',
      program(p) {
        if (!p || !p.id || p.disabled) return null;
        const max = typeof p.max_bounty === 'number' ? p.max_bounty : 0;
        return { n: p.name, u: `https://yeswehack.com/programs/${p.id}`, b: max > 0 ? 1 : 0, mx: max || null, cu: null };
      },
      assets(p) {
        const t = p.targets || {};
        const ok = new Set(['web-application', 'api', 'wildcard', 'other', 'application']);
        const bounty = typeof p.max_bounty === 'number' && p.max_bounty > 0;
        const conv = (list, oos) =>
          (list || [])
            .filter((a) => ok.has(a.type))
            .map((a) => ({ raw: a.target, trusted: a.type === 'web-application' || a.type === 'wildcard', bounty: oos ? false : bounty }));
        return { in: conv(t.in_scope, false), out: conv(t.out_of_scope, true) };
      },
    },
  };

  const PLATFORMS = Object.keys(ADAPTERS);

  /* -------------------------------------------------------------------- */
  /* Index building                                                        */
  /* Entry encoding (int):  (programIdx << 2) | (bountyEligible ? 2 : 0)   */
  /*                                          | (pathScoped ? 1 : 0)       */
  /* -------------------------------------------------------------------- */

  function pushUnique(map, key, val) {
    const arr = map[key] || (map[key] = []);
    if (arr.indexOf(val) === -1) arr.push(val);
  }

  function buildPart(platform, rawList) {
    const adapter = ADAPTERS[platform];
    if (!adapter) throw new Error(`Unknown platform: ${platform}`);
    const part = { platform, programs: [], exact: {}, wild: {}, oExact: {}, oWild: {}, roots: {} };

    (Array.isArray(rawList) ? rawList : []).forEach((raw) => {
      const prog = adapter.program(raw);
      if (!prog) return;
      const idx = part.programs.push(prog) - 1;
      const { in: ins, out: outs } = adapter.assets(raw);

      const add = (asset, oos) => {
        extractPatterns(asset.raw, asset.trusted).forEach((pat) => {
          const enc = (idx << 2) | (pat.path ? 1 : 0) | (asset.bounty ? 2 : 0);
          const map = pat.wildcard ? (oos ? part.oWild : part.wild) : oos ? part.oExact : part.exact;
          pushUnique(map, pat.host, enc);
          if (!oos) pushUnique(part.roots, getRootDomain(pat.host), idx);
        });
      };
      ins.forEach((a) => add(a, false));
      outs.forEach((a) => add(a, true));
    });
    return part;
  }

  /* -------------------------------------------------------------------- */
  /* Matching                                                              */
  /* -------------------------------------------------------------------- */

  function programInfo(part, idx) {
    const p = part.programs[idx] || {};
    return { platform: part.platform, name: p.n, url: p.u, bounty: !!p.b, maxPayout: p.mx || null, currency: p.cu || null, safeHarbor: p.sh || null, responseEfficiency: p.re == null ? null : p.re };
  }

  function matchHost(parts, hostRaw) {
    const host = normalizeHost(hostRaw);
    const res = { host, root: getRootDomain(host), inScope: [], outOfScope: [], related: [] };
    if (!host || !host.includes('.') || isIp(host)) return res;
    if (RESERVED_ROOTS.has(res.root) || /\.(test|invalid|localhost|local|internal)$/.test(host)) return res;
    const labels = host.split('.');

    Object.keys(parts || {}).forEach((platform) => {
      const part = parts[platform];
      if (!part) return;

      const ins = new Map();
      const outs = new Map();
      const consider = (target, idx, spec, info) => {
        const cur = target.get(idx);
        if (!cur || spec > cur.spec) target.set(idx, Object.assign({ spec }, info));
      };
      const scan = (exactMap, wildMap, target) => {
        (exactMap[host] || []).forEach((e) =>
          consider(target, e >> 2, labels.length * 10 + 5, { via: 'exact', asset: host, path: !!(e & 1), bountyEligible: !!(e & 2) })
        );
        for (let i = 1; i <= labels.length - 2; i++) {
          const suffix = labels.slice(i).join('.');
          (wildMap[suffix] || []).forEach((e) =>
            consider(target, e >> 2, (labels.length - i) * 10, { via: 'wildcard', asset: `*.${suffix}`, path: !!(e & 1), bountyEligible: !!(e & 2) })
          );
        }
        (wildMap[host] || []).forEach((e) =>
          consider(target, e >> 2, labels.length * 10 - 1, { via: 'wildcard-apex', asset: `*.${host}`, path: !!(e & 1), bountyEligible: !!(e & 2) })
        );
      };

      scan(part.exact, part.wild, ins);
      scan(part.oExact, part.oWild, outs);

      const seen = new Set();
      outs.forEach((o, idx) => {
        const i = ins.get(idx);
        if (!i || o.spec >= i.spec) {
          res.outOfScope.push(Object.assign(programInfo(part, idx), { via: o.via, asset: o.asset }));
          seen.add(idx);
        }
      });
      ins.forEach((i, idx) => {
        if (seen.has(idx)) return;
        res.inScope.push(Object.assign(programInfo(part, idx), { via: i.via, asset: i.asset, pathScoped: i.path, bountyEligible: i.bountyEligible }));
        seen.add(idx);
      });
      (part.roots[res.root] || []).forEach((idx) => {
        if (!seen.has(idx)) {
          res.related.push(programInfo(part, idx));
          seen.add(idx);
        }
      });
    });

    res.inScope.sort((a, b) => Number(b.bountyEligible) - Number(a.bountyEligible) || Number(b.bounty) - Number(a.bounty));
    return res;
  }

  function radarState(match, hasData) {
    if (!hasData) return 'nodata';
    if (match.inScope.length) return 'in_scope';
    if (match.outOfScope.length) return 'out_of_scope';
    if (match.related.length) return 'related';
    return 'none';
  }

  /* -------------------------------------------------------------------- */
  /* Diffing two syncs of the same platform                                */
  /* -------------------------------------------------------------------- */

  function partAssetSets(part) {
    const sets = new Map(); // program url -> Set(asset strings)
    const add = (idx, s) => {
      const p = part.programs[idx];
      if (!p) return;
      if (!sets.has(p.u)) sets.set(p.u, new Set());
      sets.get(p.u).add(s);
    };
    Object.keys(part.exact).forEach((h) => part.exact[h].forEach((e) => add(e >> 2, h)));
    Object.keys(part.wild).forEach((b) => part.wild[b].forEach((e) => add(e >> 2, `*.${b}`)));
    return sets;
  }

  function diffParts(oldPart, newPart) {
    const events = [];
    if (!oldPart || !newPart) return events;
    const oldSets = partAssetSets(oldPart);
    const newSets = partAssetSets(newPart);
    const oldProgs = new Map(oldPart.programs.map((p) => [p.u, p]));
    const newProgs = new Map(newPart.programs.map((p) => [p.u, p]));
    const platform = newPart.platform;

    newProgs.forEach((p, u) => {
      const assets = Array.from(newSets.get(u) || []);
      if (!oldProgs.has(u)) {
        events.push({ type: 'new_program', platform, name: p.n, url: u, bounty: !!p.b, assets: assets.slice(0, 8), total: assets.length });
      } else {
        const before = oldSets.get(u) || new Set();
        const added = assets.filter((a) => !before.has(a));
        if (added.length) events.push({ type: 'new_scope', platform, name: p.n, url: u, bounty: !!p.b, assets: added.slice(0, 8), total: added.length });
      }
    });
    oldProgs.forEach((p, u) => {
      if (!newProgs.has(u)) events.push({ type: 'program_closed', platform, name: p.n, url: u, bounty: !!p.b, assets: [], total: 0 });
    });
    return events;
  }

  function countAssets(part) {
    let n = 0;
    Object.keys(part.exact).forEach((k) => (n += part.exact[k].length));
    Object.keys(part.wild).forEach((k) => (n += part.wild[k].length));
    return n;
  }

  const api = { PLATFORMS, ADAPTERS, MULTI_TLDS, getRootDomain, normalizeHost, extractPatterns, buildPart, matchHost, radarState, diffParts, partAssetSets, countAssets };
  root.ScopeRadar = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof self !== 'undefined' ? self : this);
