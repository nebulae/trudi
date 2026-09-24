/* Shared renderers for the TRUDI dashboard views (trace view + chain view).
 *
 * Exposes window.TrudiRender:
 *   parseDelimited(text)        CSV/TSV → {delim, header, rows, notes} | null
 *   parseMailLines(text)        read.mail "from -> to | subject" lines → rows | null
 *   parseReadCmd(cmd)           read.output / read.mail cmd → {tool, file, params}
 *   outputHtml(text, opts)      table for CSV/TSV/mail text, <pre> otherwise
 *   paramsHtml(parsed)          small parameter table for a parsed read.* cmd
 *   findingDetailHtml(e, ctx)   full finding detail (typed claim, tier, gate, lineage)
 *   fetchOutput(traceUrl, path) text of a produced-output file via the server
 *
 * Styling uses the pages' CSS variables (--bg, --fg-dim, --border, …) so both
 * views keep their look; the few classes it needs are injected once (tr-*).
 */
(function (global) {
'use strict';

const TR = {};

function esc(s) {
  if (s === undefined || s === null) return '';
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
TR.esc = esc;

const CSS = `
.tr-h { margin: 14px 0 6px 0; font-size: 11px; text-transform: uppercase;
  letter-spacing: 0.08em; color: var(--fg-dim); font-weight: 600; }
.tr-kv { display: grid; grid-template-columns: 150px minmax(0, 1fr); gap: 4px 12px; font-size: 12px; }
.tr-kv .k { color: var(--fg-dim); }
.tr-kv .v { word-break: break-word; min-width: 0; }
.tr-note { color: var(--fg-dim); font-size: 11px; margin: 2px 0; }
.tr-warn { color: var(--finding-likely, #ffa86b); font-size: 11px; margin: 2px 0; }
.tr-pre { background: var(--bg); border: 1px solid var(--border); padding: 8px 10px;
  border-radius: 4px; max-height: 360px; overflow: auto; white-space: pre-wrap;
  word-wrap: break-word; margin: 4px 0;
  font-family: "SF Mono","Menlo","Consolas",monospace; font-size: 11px; }
.tr-scroll { overflow: auto; max-height: 440px; border: 1px solid var(--border);
  border-radius: 4px; margin: 4px 0; background: var(--bg); }
table.tr-table { border-collapse: collapse; width: max-content; min-width: 100%; margin: 0; }
table.tr-table th, table.tr-table td { text-align: left; padding: 3px 7px;
  border-bottom: 1px solid var(--border); font-size: 11px; vertical-align: top;
  font-family: "SF Mono","Menlo","Consolas",monospace; }
table.tr-table th { position: sticky; top: 0; background: var(--bg-3); color: var(--fg-dim);
  font-weight: 600; white-space: nowrap; z-index: 1; }
table.tr-table td { white-space: pre-wrap; max-width: 520px; word-break: break-word; }
table.tr-table td.rn { color: var(--fg-dim); text-align: right; white-space: nowrap; }
table.tr-table tr:hover td { background: var(--bg-2); }
table.tr-params { border-collapse: collapse; margin: 4px 0; width: 100%; }
table.tr-params td { padding: 2px 8px 2px 0; font-size: 12px; vertical-align: top;
  border-bottom: 1px solid var(--border); word-break: break-word; }
table.tr-params td.k { color: var(--fg-dim); width: 90px; white-space: nowrap; }
.tr-more { margin: 2px 0 6px 0; padding: 2px 10px; font-size: 11px; cursor: pointer;
  background: var(--bg-3); color: var(--accent); border: 1px solid var(--border); border-radius: 4px; }
.tr-more:hover { background: var(--bg-hl); }
.tr-tag { display: inline-block; padding: 0 5px; margin: 1px 3px 1px 0; border: 1px solid var(--border);
  border-radius: 3px; font-size: 11px; font-family: "SF Mono","Menlo","Consolas",monospace;
  background: var(--bg-3); }
.tr-tier { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 11px; font-weight: 700; }
.tr-tier.CONFIRMED { background: rgba(255,107,107,.15); color: var(--finding-confirmed); }
.tr-tier.LIKELY { background: rgba(255,168,107,.15); color: var(--finding-likely); }
.tr-tier.SUSPECTED { background: rgba(255,216,107,.15); color: var(--finding-suspected); }
.tr-tier.UNCONFIRMED { background: rgba(138,147,166,.15); color: var(--finding-unconfirmed); }
.tr-status { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 11px; font-weight: 600; }
.tr-status.malicious { background: rgba(255,107,107,.18); color: var(--finding-confirmed); }
.tr-status.suspicious { background: rgba(255,168,107,.18); color: var(--finding-likely); }
.tr-status.observed { background: rgba(110,168,255,.15); color: var(--accent); }
.tr-status.benign { background: rgba(74,210,149,.15); color: var(--ok); }
.tr-status.unknown { background: rgba(138,147,166,.15); color: var(--fg-dim); }
.tr-verdict { font-weight: 700; }
.tr-verdict.SUPPORTED { color: var(--ok); }
.tr-verdict.CHALLENGED, .tr-verdict.CONTRADICTED { color: var(--finding-confirmed); }
.tr-verdict.UNCERTAIN, .tr-verdict.UNVERIFIABLE { color: var(--finding-suspected); }
.tr-card { border: 1px solid var(--border); border-radius: 4px; padding: 8px 10px; margin: 8px 0;
  background: var(--bg-3); }
.tr-card .tr-card-h { font-size: 12px; font-weight: 600; margin-bottom: 4px; }
.tr-link { color: var(--accent); cursor: pointer; text-decoration: underline dotted; }
`;

function injectCss() {
  if (typeof document === 'undefined' || document.getElementById('trudi-render-css')) return;
  const st = document.createElement('style');
  st.id = 'trudi-render-css';
  st.textContent = CSS;
  (document.head || document.documentElement).appendChild(st);
}
injectCss();

// ── Delimited text (CSV / TSV) ──────────────────────────────────────────────
const MAX_PARSE_RECORDS = 50000;
const TRAILER_RE = /^\s*(…|\.\.\.)?\s*\[(row cap|truncated|field truncated)[^\]]*\]\s*$/i;

function countOutsideQuotes(line, ch) {
  let n = 0, q = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"') q = !q;
    else if (c === ch && !q) n++;
  }
  return n;
}

function parseRecords(text, delim, maxRecords) {
  const out = [];
  let row = [], field = '', i = 0, q = false, fieldStart = true;
  const n = text.length;
  while (i < n) {
    const c = text[i];
    if (q) {
      if (c === '"') {
        if (text[i + 1] === '"') { field += '"'; i += 2; continue; }
        q = false; i++; continue;
      }
      field += c; i++; continue;
    }
    if (c === '"' && fieldStart) { q = true; fieldStart = false; i++; continue; }
    if (c === delim) { row.push(field); field = ''; fieldStart = true; i++; continue; }
    if (c === '\r' && text[i + 1] === '\n') { i++; continue; }
    if (c === '\n') {
      row.push(field); out.push(row);
      row = []; field = ''; fieldStart = true; i++;
      if (out.length >= maxRecords) return { records: out, capped: i < n };
      continue;
    }
    field += c; fieldStart = false; i++;
  }
  if (field !== '' || row.length) { row.push(field); out.push(row); }
  return { records: out, capped: false };
}

TR.parseDelimited = function (text) {
  if (text === undefined || text === null) return null;
  let t = String(text).replace(/^\uFEFF/, '');
  // Drop leading blank lines.
  t = t.replace(/^(\s*\n)+/, '');
  const nl = t.indexOf('\n');
  if (nl < 0) return null;                       // header only / one line
  const headerLine = t.slice(0, nl).replace(/\r$/, '');
  const tabs = countOutsideQuotes(headerLine, '\t');
  const commas = countOutsideQuotes(headerLine, ',');
  let delim = null;
  if (tabs >= 1 && tabs >= commas) delim = '\t';
  else if (commas >= 1) delim = ',';
  if (!delim) return null;
  const { records, capped } = parseRecords(t, delim, MAX_PARSE_RECORDS);
  if (records.length < 2) return null;
  const header = records[0].map(h => h.trim());
  const ncol = header.length;
  if (ncol < 2) return null;
  // A header names columns: short cells, not sentences.
  if (header.some(h => h.length > 100)) return null;
  if (header.filter(h => h === '').length > ncol / 2) return null;
  const notes = [];
  let rows = records.slice(1).filter(r => !(r.length === 1 && r[0].trim() === ''));
  while (rows.length && rows[rows.length - 1].length === 1 && TRAILER_RE.test(rows[rows.length - 1][0])) {
    notes.unshift(rows.pop()[0].trim());
  }
  if (!rows.length) return null;
  // The last row may have been cut mid-record by an output cap.
  const last = rows[rows.length - 1];
  const lastCut = last.length !== ncol || /…\s*\[(truncated|row cap)\]\s*$/.test(last[last.length - 1] || '');
  const body = lastCut ? rows.slice(0, -1) : rows;
  const consistent = body.filter(r => r.length === ncol).length;
  if (body.length === 0 && !(last.length >= 2)) return null;
  if (body.length && consistent / body.length < 0.8) return null;
  if (lastCut) notes.push('last row is cut short (output was truncated)');
  if (capped) notes.push(`only the first ${MAX_PARSE_RECORDS} records were parsed`);
  return { delim, header, rows, notes };
};

// ── read.mail result lines ──────────────────────────────────────────────────
const MAIL_RE = /^(.*?) -> (.*?) \| (.*)$/;
TR.parseMailLines = function (text) {
  if (!text) return null;
  const lines = String(text).split('\n').filter(l => l.trim() !== '');
  if (!lines.length) return null;
  const rows = [], notes = [];
  for (const l of lines) {
    const m = l.match(MAIL_RE);
    if (m) rows.push([m[1].trim(), m[2].trim(), m[3].trim()]);
    else notes.push(l.trim());
  }
  if (!rows.length || rows.length / lines.length < 0.8) return null;
  return { delim: 'mail', header: ['from', 'to', 'subject'], rows, notes };
};

// ── read.* command parsing ──────────────────────────────────────────────────
function shlexWord(s) {
  // One POSIX shell word from the start of `s` (quotes concatenate, as
  // produced by Python's shlex.quote). Returns [word, rest].
  let i = 0, out = '';
  while (i < s.length && !/\s/.test(s[i])) {
    const c = s[i];
    if (c === "'") {
      const j = s.indexOf("'", i + 1);
      if (j < 0) { out += s.slice(i + 1); i = s.length; break; }
      out += s.slice(i + 1, j); i = j + 1;
    } else if (c === '"') {
      let j = i + 1;
      while (j < s.length && s[j] !== '"') {
        if (s[j] === '\\' && j + 1 < s.length) { out += s[j + 1]; j += 2; }
        else { out += s[j]; j++; }
      }
      i = j + 1;
    } else if (c === '\\' && i + 1 < s.length) {
      out += s[i + 1]; i += 2;
    } else { out += c; i++; }
  }
  return [out, s.slice(i)];
}

const READ_CMDS = [
  { tool: 'read.output', prefix: /^read\.output\s+(?:--output|-o)\s+/, keys: ['query', 'columns', 'where'] },
  { tool: 'read.mail', prefix: /^read\.mail\s+(?:-o|--output)\s+/, keys: ['mode', 'field', 'q'] },
];

TR.parseReadCmd = function (cmd) {
  const c = String(cmd || '').trim();
  const spec = READ_CMDS.find(s => s.prefix.test(c));
  if (!spec) return null;
  let rest = c.replace(spec.prefix, '');
  const keyRe = new RegExp(`(^|\\s)(${spec.keys.join('|')})=`, 'g');
  let file = '';
  if (rest.startsWith("'") || rest.startsWith('"')) {
    [file, rest] = shlexWord(rest);
  } else {
    // Unquoted (older traces): the path runs to the first " key=" — it may
    // contain spaces.
    keyRe.lastIndex = 0;
    let m, cut = -1;
    while ((m = keyRe.exec(rest))) { if (m.index > 0) { cut = m.index; break; } }
    if (cut < 0) { file = rest.trim(); rest = ''; }
    else { file = rest.slice(0, cut).trim(); rest = rest.slice(cut); }
  }
  const params = [];
  const marks = [];
  keyRe.lastIndex = 0;
  let m;
  while ((m = keyRe.exec(rest))) marks.push({ key: m[2], start: m.index + m[0].length, at: m.index });
  for (let i = 0; i < marks.length; i++) {
    const end = i + 1 < marks.length ? marks[i + 1].at : rest.length;
    params.push([marks[i].key, rest.slice(marks[i].start, end).trim()]);
  }
  return { tool: spec.tool, file, params };
};

TR.paramsHtml = function (parsed, opts) {
  if (!parsed) return '';
  opts = opts || {};
  const rows = [['file', `<code>${esc(parsed.file)}</code>`]];
  for (const [k, v] of parsed.params) {
    let val;
    if (k === 'columns') val = v.split(',').filter(Boolean).map(x => `<span class="tr-tag">${esc(x.trim())}</span>`).join('');
    else val = `<code>${esc(v)}</code>`;
    rows.push([k, val]);
  }
  if (opts.extra) rows.push(...opts.extra);
  return `<table class="tr-params"><tbody>${rows.map(([k, v]) =>
    `<tr><td class="k">${esc(k)}</td><td>${v}</td></tr>`).join('')}</tbody></table>`;
};

// ── Tables with a row cap + "show more" ─────────────────────────────────────
const TABLES = new Map();
let tableSeq = 0;
const TABLE_KEEP = 40;

function rowsHtml(rows, from, to, ncol) {
  let h = '';
  for (let i = from; i < to; i++) {
    const r = rows[i];
    let cells = '';
    for (let j = 0; j < Math.max(ncol, r.length); j++) cells += `<td>${esc(r[j] === undefined ? '' : r[j])}</td>`;
    h += `<tr><td class="rn">${i + 1}</td>${cells}</tr>`;
  }
  return h;
}

TR.tableHtml = function (parsed, opts) {
  opts = opts || {};
  const cap = opts.cap || 100;
  const id = `trt-${++tableSeq}`;
  const shown = Math.min(cap, parsed.rows.length);
  TABLES.set(id, { parsed, shown, step: opts.step || 200 });
  while (TABLES.size > TABLE_KEEP) TABLES.delete(TABLES.keys().next().value);
  const ncol = parsed.header.length;
  const kind = parsed.delim === '\t' ? 'TSV' : parsed.delim === 'mail' ? 'messages' : 'CSV';
  const summary = parsed.delim === 'mail'
    ? `${parsed.rows.length} message${parsed.rows.length === 1 ? '' : 's'}`
    : `${kind} · ${parsed.rows.length} row${parsed.rows.length === 1 ? '' : 's'} × ${ncol} columns`;
  const more = parsed.rows.length > shown
    ? `<button class="tr-more" data-tr-table="${id}">show more (${shown} of ${parsed.rows.length})</button>` : '';
  return `<div class="tr-note">${esc(summary)}${opts.note ? ' · ' + esc(opts.note) : ''}</div>
    <div class="tr-scroll"><table class="tr-table" id="${id}">
      <thead><tr><th>#</th>${parsed.header.map(h => `<th>${esc(h)}</th>`).join('')}</tr></thead>
      <tbody>${rowsHtml(parsed.rows, 0, shown, ncol)}</tbody></table></div>${more}
    ${(parsed.notes || []).map(n => `<div class="tr-note">${esc(n)}</div>`).join('')}`;
};

if (typeof document !== 'undefined') {
  document.addEventListener('click', (ev) => {
    const b = ev.target && ev.target.closest && ev.target.closest('button.tr-more[data-tr-table]');
    if (!b) return;
    ev.stopPropagation();
    const st = TABLES.get(b.dataset.trTable);
    const tbl = document.getElementById(b.dataset.trTable);
    if (!st || !tbl) { b.remove(); return; }
    const to = Math.min(st.parsed.rows.length, st.shown + st.step);
    tbl.tBodies[0].insertAdjacentHTML('beforeend',
      rowsHtml(st.parsed.rows, st.shown, to, st.parsed.header.length));
    st.shown = to;
    if (to >= st.parsed.rows.length) b.remove();
    else b.textContent = `show more (${to} of ${st.parsed.rows.length})`;
  }, true);
}

// Text → table when it is CSV/TSV (or read.mail lines), else <pre>.
TR.outputHtml = function (text, opts) {
  opts = opts || {};
  const t = text === undefined || text === null ? '' : String(text);
  if (!t.trim()) return `<div class="tr-note">(empty)</div>`;
  const isMail = /^read\.mail\b/.test(String(opts.cmd || ''));
  const parsed = (isMail && TR.parseMailLines(t)) || TR.parseDelimited(t);
  if (parsed) return TR.tableHtml(parsed, opts);
  return `${opts.note ? `<div class="tr-note">${esc(opts.note)}</div>` : ''}<pre class="tr-pre">${esc(t)}</pre>`;
};

// ── Produced-output fetch (server endpoint) ─────────────────────────────────
const OUT_CACHE = new Map();
TR.fetchOutput = async function (traceUrl, path, maxBytes) {
  const key = `${traceUrl}|${path}|${maxBytes || ''}`;
  if (OUT_CACHE.has(key)) return OUT_CACHE.get(key);
  let tracePath = traceUrl;
  try { tracePath = new URL(traceUrl, global.location.href).pathname; } catch (_) {}
  const u = `/_dashboard/api/output?trace=${encodeURIComponent(tracePath)}&path=${encodeURIComponent(path)}`
    + (maxBytes ? `&max=${maxBytes}` : '');
  const resp = await fetch(u, { cache: 'no-store' });
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  const text = await resp.text();
  const res = {
    text,
    size: parseInt(resp.headers.get('X-Trudi-Size') || '0', 10) || text.length,
    truncated: resp.headers.get('X-Trudi-Truncated') === '1',
  };
  OUT_CACHE.set(key, res);
  if (OUT_CACHE.size > 60) OUT_CACHE.delete(OUT_CACHE.keys().next().value);
  return res;
};

// ── Finding detail ──────────────────────────────────────────────────────────
const TIER_RANK = { CONFIRMED: 3, LIKELY: 2, SUSPECTED: 1, UNCONFIRMED: 0 };

TR.reviewVerdict = function (r) {
  if (!r) return '';
  const rb = r.result_block && typeof r.result_block === 'object' ? r.result_block : null;
  const v = r.verdict || (rb && rb.verdict) || r.fact_verdict || '';
  if (v) return String(v).toUpperCase();
  const m = String(r.conclusion || '').match(/VERDICT:\s*(SUPPORTED|CHALLENGED|UNCERTAIN|CONTRADICTED|UNVERIFIABLE)/i);
  return m ? m[1].toUpperCase() : '';
};

function kvRows(rows) {
  const r = rows.filter(x => x && x[1] !== undefined && x[1] !== null && x[1] !== '');
  if (!r.length) return '';
  return `<div class="tr-kv">${r.map(([k, v]) => `<span class="k">${esc(k)}</span><span class="v">${v}</span>`).join('')}</div>`;
}

function tags(list) {
  return (list || []).map(x => `<span class="tr-tag">${esc(typeof x === 'object' ? JSON.stringify(x) : x)}</span>`).join('');
}

function isEmpty(v) {
  return v === undefined || v === null || v === '' || v === false
    || (Array.isArray(v) && !v.length)
    || (typeof v === 'object' && !Array.isArray(v) && !Object.keys(v).length);
}

// ctx: { byId: Map<cid, entry>, link(cid, label, title) → html,
//        fetchesByReview?: Map<reviewCid, fetch entries[]> }
TR.findingDetailHtml = function (e, ctx) {
  ctx = ctx || {};
  const byId = ctx.byId || new Map();
  const link = ctx.link || ((cid, label) => `#${esc(label || cid)}`);
  const cidLabel = (cid) => {
    const x = byId.get(cid);
    if (!x) return `#${cid}`;
    if (x.type === 'tool_call') {
      const bin = String(x.mcp_tool || (x.cmd || '').trim().split(/\s+/)[0] || '').split('/').pop();
      return `#${cid} ${bin}`;
    }
    if (x.type === 'reason_call') return `#${cid} ${x.tool || 'reason'}`;
    if (x.type === 'finding') return `#${cid} ${x.finding_id || 'finding'}`;
    return `#${cid} ${x.type || ''}`.trim();
  };
  const cidTitle = (cid) => {
    const x = byId.get(cid);
    return x ? String(x.cmd || x.tool || x.description || x.type || '').slice(0, 300) : 'not in this trace';
  };
  const chips = (ids) => (ids || []).filter(c => c !== undefined && c !== null && c !== '')
    .map(c => link(Number(c), cidLabel(Number(c)), cidTitle(Number(c)))).join(' ');

  const tier = String(e.confidence || '').toUpperCase();
  const claim = e.claim && typeof e.claim === 'object' ? e.claim : {};
  const out = [];

  // Identity + tier
  const achievable = String(e.tier_achievable || '').toUpperCase();
  let tierNote = '';
  if (achievable && tier in TIER_RANK && achievable in TIER_RANK) {
    if (TIER_RANK[achievable] > TIER_RANK[tier]) {
      tierNote = `<div class="tr-warn">tier headroom: recorded ${esc(tier)}; the cited artifact classes reach ${esc(achievable)}${e.tier_rule ? ` (rule ${esc(e.tier_rule)})` : ''}.</div>`;
    } else if (TIER_RANK[achievable] < TIER_RANK[tier]) {
      tierNote = `<div class="tr-warn">recorded above tier_achievable (${esc(achievable)}).</div>`;
    }
  }
  const gateCid = e.gated_by_evaluate_call_id;
  const gate = gateCid ? byId.get(gateCid) : null;
  const tc = (gate && gate.tier_contract) || {};
  const tierPath = e.tier_path || tc.tier_path || '';
  const nextTier = e.next_tier || tc.next_tier || '';
  const superseded = e.superseded_by ? byId.get(e.superseded_by) : null;
  let retraction = null;
  for (const x of byId.values()) {
    if (x.type === 'finding_retracted' && Number(x.finding_call_id) === e.call_id) { retraction = x; break; }
  }
  out.push(kvRows([
    ['finding', e.finding_id ? `<code>${esc(e.finding_id)}</code>${e.revision ? ` · revision ${esc(e.revision)}` : ''}` : ''],
    ['confidence', `<span class="tr-tier ${esc(tier)}">${esc(tier)}</span>`],
    ['tier achievable', achievable ? `<span class="tr-tier ${esc(achievable)}">${esc(achievable)}</span>${e.tier_rule ? ` <span class="tr-note">rule <code>${esc(e.tier_rule)}</code></span>` : ''}` : ''],
    ['next tier', nextTier ? esc(nextTier) : ''],
    ['answers case question', claim.answers_case_question ? '<span class="tr-tier CONFIRMED" style="background:rgba(74,210,149,.15);color:var(--ok)">✓ yes</span>' : ''],
    ['supersedes', e.supersedes ? link(Number(e.supersedes), cidLabel(Number(e.supersedes)), cidTitle(Number(e.supersedes))) : ''],
    ['superseded by', e.superseded_by ? `${link(Number(e.superseded_by), cidLabel(Number(e.superseded_by)), cidTitle(Number(e.superseded_by)))}${superseded ? ` <span class="tr-note">(${esc(String(superseded.confidence || '').toUpperCase())}) — this revision is not active</span>` : ''}` : ''],
    ['retracted', retraction ? `<span class="tr-warn">yes</span> ${link(retraction.call_id, `#${retraction.call_id}`, retraction.reason || '')} <span class="tr-note">${esc(retraction.reason || '')}</span>` : ''],
  ]));
  if (tierNote) out.push(tierNote);
  if (tierPath) out.push(`<div class="tr-note">tier path: ${esc(tierPath)}</div>`);

  out.push(`<div class="tr-h">description</div><pre class="tr-pre">${esc(e.description || '')}</pre>`);

  // Typed claim
  if (Object.keys(claim).length) {
    const skip = new Set(['claim_version', 'answers_case_question']);
    const callIdKeys = new Set(['session_binding_call_ids', 'transfer_call_ids', 'receipt_call_ids']);
    const order = ['kind', 'category', 'act', 'channel', 'actor_kind', 'actor', 'principal',
      'session_type', 'window', 'entities', 'recipients', 'threat_actor', 'techniques',
      'artifacts', 'scope', 'resolves', 'session_binding_call_ids', 'transfer_call_ids',
      'receipt_call_ids', 'rule_outs'];
    const keys = [...order.filter(k => k in claim),
      ...Object.keys(claim).filter(k => !order.includes(k) && !k.endsWith('_norm'))];
    const rows = [];
    for (const k of keys) {
      if (skip.has(k) || k.endsWith('_norm')) continue;
      const v = claim[k];
      if (isEmpty(v)) continue;
      let html;
      if (callIdKeys.has(k)) html = chips(v);
      else if (k === 'rule_outs' && Array.isArray(v)) {
        html = v.map(r => `<div>${esc(r.what || '')}: ${chips(r.call_ids || [])}</div>`).join('');
      } else if (k === 'window' && typeof v === 'object') html = esc(`${v.start || '?'} → ${v.end || '?'}`);
      else if (Array.isArray(v)) html = tags(v);
      else if (typeof v === 'object') html = `<code>${esc(JSON.stringify(v))}</code>`;
      else if (['kind', 'category', 'act', 'channel', 'actor_kind', 'session_type', 'resolves'].includes(k)) html = `<code>${esc(v)}</code>`;
      else html = esc(v);
      rows.push([k.replace(/_/g, ' '), html]);
    }
    if (rows.length) out.push(`<div class="tr-h">typed claim</div>${kvRows(rows)}`);
  }

  // Lineage + review gate
  const hyp = e.tested_hypothesis_id;
  let hypCall = null;
  if (hyp) {
    for (const x of byId.values()) {
      if (x.type === 'reason_call' && x.hypothesis_id === hyp) { hypCall = x; break; }
    }
  }
  let gateHtml = '';
  if (gateCid) {
    const v = TR.reviewVerdict(gate);
    const fetches = ((ctx.fetchesByReview && ctx.fetchesByReview.get(gateCid)) || []);
    gateHtml = `${link(gateCid, cidLabel(gateCid), cidTitle(gateCid))}${v ? ` <span class="tr-verdict ${esc(v)}">${esc(v)}</span>` : (gate ? '' : ' <span class="tr-note">(not in this trace)</span>')}`
      + (gate && gate.evidence_rounds ? ` <span class="tr-note">after ${gate.evidence_rounds} evidence round${gate.evidence_rounds > 1 ? 's' : ''}</span>` : '')
      + (fetches.length ? ` <span class="tr-note">· fetches</span> ${fetches.map(f => link(f.call_id, `#${f.call_id}`, 'evidence fetch')).join(' ')}` : '');
  }
  const gateOther = (cid) => cid ? `${link(Number(cid), cidLabel(Number(cid)), cidTitle(Number(cid)))}${byId.get(Number(cid)) && TR.reviewVerdict(byId.get(Number(cid))) ? ` <span class="tr-verdict ${esc(TR.reviewVerdict(byId.get(Number(cid))))}">${esc(TR.reviewVerdict(byId.get(Number(cid))))}</span>` : ''}` : '';
  out.push(`<div class="tr-h">evidence &amp; review</div>` + kvRows([
    ['linked call', e.linked_call_id ? link(Number(e.linked_call_id), cidLabel(Number(e.linked_call_id)), cidTitle(Number(e.linked_call_id))) : '<span class="tr-warn">no linked_call_id</span>'],
    ['input calls', chips(e.input_call_ids)],
    ['gated by evaluate', gateHtml],
    ['gated by confidence', gateOther(e.gated_by_confidence_call_id)],
    ['gated by cite check', gateOther(e.gated_by_cite_check_call_id)],
    ['gated by hypothesize', gateOther(e.gated_by_hypothesize_call_id)],
    ['tested hypothesis', hyp ? `<code>${esc(hyp)}</code>${hypCall ? ' ' + link(hypCall.call_id, cidLabel(hypCall.call_id), String((hypCall.inputs && hypCall.inputs.observation) || '').slice(0, 300)) : ''}` : ''],
    ['source', e.source ? `<code>${esc(e.source)}</code>` : ''],
    ['citation mode', e.citation_mode ? esc(e.citation_mode) : ''],
    ['lineage inferred', e.lineage_inferred ? 'yes' : ''],
    ['submission key', e.submission_key ? `<code>${esc(e.submission_key)}</code>` : ''],
    ['evidence packet', e.evidence_packet_id ? `<code title="${esc(e.evidence_packet_id)}">${esc(String(e.evidence_packet_id).slice(0, 24))}…</code>` : ''],
  ]));

  // Artifact classes → calls
  const ac = e.artifact_classes && typeof e.artifact_classes === 'object' ? e.artifact_classes : null;
  if (ac && Object.keys(ac).length) {
    out.push(`<div class="tr-h">artifact classes (tier arithmetic)</div>` +
      kvRows(Object.entries(ac).map(([k, ids]) => [k, chips(Array.isArray(ids) ? ids : [ids])])));
  }

  // ATT&CK
  const vt = Array.isArray(e.validated_techniques) ? e.validated_techniques : [];
  if (vt.length) {
    out.push(`<div class="tr-h">validated ATT&amp;CK techniques</div><table class="tr-params"><tbody>${vt.map(t =>
      `<tr><td class="k"><code>${esc(t.technique_id || '')}</code></td><td>${esc(t.name || '')} <span class="tr-note">(${esc(t.tactic || '')})</span>${t.status ? ` <span class="tr-note">[${esc(t.status)}]</span>` : ''}</td></tr>`).join('')}</tbody></table>`);
  }

  if (e.supporting_evidence) {
    out.push(`<details><summary class="tr-h" style="cursor:pointer;">supporting evidence (${String(e.supporting_evidence).length} chars)</summary><pre class="tr-pre">${esc(e.supporting_evidence)}</pre></details>`);
  }
  return out.join('\n');
};

global.TrudiRender = TR;
if (typeof module !== 'undefined' && module.exports) module.exports = TR;
})(typeof window !== 'undefined' ? window : globalThis);
