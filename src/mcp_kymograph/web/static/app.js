/* The local read-only viewer: fetches the views' JSON envelopes and builds the DOM.

   Every string from the API is hostile until shown: it is inserted as text only (vis()),
   with the characters of the Unicode categories Cc, Cf, Cs, Co and Cn made visible as a
   marked U+XXXX token. No markup is ever parsed from data, no attribute is built from data
   except through h()'s allowlist, no URL in the data becomes a link. Contract:
   src/mcp_kymograph/web/CONTRACT.md. */
(() => {
  'use strict';

  // ---- strings off the wire ------------------------------------------------------------

  // Cc controls, Cf format (zero-width, bidi overrides), Cs lone surrogates, Co private use,
  // Cn unassigned (as of the Unicode version of the browser's own tables).
  const UNSAFE = /([\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}])/u;

  const UNSAFE_ALL = new RegExp(UNSAFE.source, 'gu');

  // The token of one character, as a string.
  function cpText(ch) {
    return 'U+' + ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0');
  }

  function cpToken(ch) {
    const span = document.createElement('span');
    span.className = 'cp';
    span.textContent = cpText(ch);
    return span;
  }

  // A value as a string, for the places a node cannot go (an <option>'s label, the title of
  // the page): the same characters as in vis(), written as [U+XXXX]. Every value from the data
  // that is not shown as text goes through here, never raw.
  function visText(value) {
    return String(value).replace(UNSAFE_ALL, (c) => '[' + cpText(c) + ']');
  }

  // A value as text. In block text (a file, stderr, pretty-printed JSON) a line feed stays a
  // line break; everywhere else it is a token like every other control character.
  function vis(value, block) {
    const frag = document.createDocumentFragment();
    const parts = String(value).split(UNSAFE);
    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];
      if (part === '') continue;
      if (i % 2 === 1) {
        if (block && part === '\n') frag.appendChild(document.createTextNode('\n'));
        else frag.appendChild(cpToken(part));
      } else {
        frag.appendChild(document.createTextNode(part));
      }
    }
    return frag;
  }

  // ---- DOM ---------------------------------------------------------------------------

  // The only attributes h() sets. href only to this page's own routes (built by href()); the
  // one other link is a download of this server's own api/…/file route, made by downloadLink().
  const SAFE_ATTRS = new Set([
    'class', 'id', 'role', 'tabindex', 'type', 'scope', 'colspan', 'rowspan', 'hidden', 'for',
    'name', 'value', 'disabled', 'selected', 'open', 'lang', 'start',
  ]);

  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (v === null || v === undefined || v === false) continue;
        if (k === 'on') {
          for (const [ev, fn] of Object.entries(v)) el.addEventListener(ev, fn);
          continue;
        }
        if (k === 'href') {
          const s = String(v);
          if (!s.startsWith('#/')) throw new Error('only routes of this page are links');
          el.setAttribute('href', s);
          continue;
        }
        if (!(SAFE_ATTRS.has(k) || k.startsWith('aria-') || k.startsWith('data-'))) {
          throw new Error('attribute not allowed: ' + k);
        }
        el.setAttribute(k, v === true ? '' : String(v));
      }
    }
    add(el, kids);
    return el;
  }

  // The one other place an attribute is set (CONTRACT section 5): a state the page keeps on an
  // element it made. The name is one of five, the value one of the page's own constants (for
  // data-ready, the number of a draw); anything else throws. The attribute is written itself,
  // not through the ARIA reflection properties: Firefox before 119 has none, and the attribute
  // would not change.
  const STATE_VALUES = new Map([
    ['aria-pressed', ['true', 'false']],
    ['aria-expanded', ['true', 'false']],
    ['aria-busy', ['true', 'false']],
    ['aria-current', ['page']],
  ]);

  function setState(el, name, value) {
    const allowed = STATE_VALUES.get(name);
    const fine = allowed ? allowed.includes(value) : name === 'data-ready' && /^[0-9]{1,9}$/.test(value);
    if (!fine) throw new Error('not a state of this page: ' + visText(name) + ' = ' + visText(value));
    el.setAttribute(name, value);
  }

  function add(el, kids) {
    for (const k of [kids].flat(Infinity)) {
      if (k === null || k === undefined || k === false) continue;
      if (k instanceof Node) el.appendChild(k);
      else el.appendChild(vis(k));
    }
    return el;
  }

  function frag(...kids) { return add(document.createDocumentFragment(), kids); }

  function fromTemplate(id) {
    const node = document.getElementById(id).content.firstElementChild.cloneNode(true);
    return { node, slot: (name) => node.querySelector('[data-slot="' + name + '"]') };
  }

  // A value as JSON, written as JSON.stringify writes it except for its strings: JSON writes a
  // control character as \u0007, which is text and not the page's token. A string here keeps the
  // escapes JSON cannot do without (the quote, the backslash, the line and tab ones) and leaves
  // the rest to vis(), which makes every other invisible character a U+XXXX token. `pad` is null
  // for one line, else the indentation of the level.
  const JSON_ESCAPES = { '\\': '\\\\', '"': '\\"', '\n': '\\n', '\r': '\\r', '\t': '\\t', '\b': '\\b', '\f': '\\f' };
  function jsonString(s) { return '"' + s.replace(/[\\"\n\r\t\b\f]/g, (c) => JSON_ESCAPES[c]) + '"'; }
  function jsonOf(v, pad) {
    if (typeof v === 'string') return jsonString(v);
    if (v === null || typeof v !== 'object') return String(v);
    const pretty = pad !== null;
    const inner = pretty ? pad + '  ' : '';
    const nl = pretty ? '\n' : '';
    const below = pretty ? inner : null;
    const list = Array.isArray(v);
    const items = list ? v.map((x) => inner + jsonOf(x, below))
      : Object.keys(v).map((k) => inner + jsonString(k) + (pretty ? ': ' : ':') + jsonOf(v[k], below));
    const [open, close] = list ? ['[', ']'] : ['{', '}'];
    return items.length ? open + nl + items.join(',' + nl) + nl + (pretty ? pad : '') + close : open + close;
  }

  // A value as one line of text: structures as their JSON, nothing as a dash.
  function asText(v) {
    if (v === null || v === undefined) return null;
    if (typeof v === 'object') { try { return jsonOf(v, null); } catch (e) { return String(v); } }
    return String(v);
  }
  function mono(v) {
    if (v instanceof Node || Array.isArray(v)) return h('span', { class: 'mono wire' }, v);
    const t = asText(v);
    return t === null ? h('span', { class: 'muted' }, v === null ? 'null' : '—') : h('span', { class: 'mono wire' }, t);
  }
  function code(v) {
    const t = asText(v);
    return h('code', { class: 'wire' }, t === null ? '—' : t);
  }
  function sub(...kids) { return h('span', { class: 'sub' }, ...kids); }
  function arrow() { return h('span', { class: 'arrow', 'aria-hidden': 'true' }, '→'); }
  function dash() { return h('span', { class: 'muted' }, '—'); }

  function isObj(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }
  function isEmpty(v) {
    return v === null || v === undefined || (Array.isArray(v) && v.length === 0)
      || (isObj(v) && Object.keys(v).length === 0);
  }
  function asList(v) {
    if (Array.isArray(v)) return v;
    if (v === null || v === undefined) return [];
    if (isObj(v)) return Object.values(v);
    return [v];
  }
  // One event or several: a view may pass an event as an object or a list of them.
  function asEvents(v) {
    if (Array.isArray(v)) return v;
    if (v === null || v === undefined) return [];
    return [v];
  }
  function pick(obj, ...names) {
    if (!isObj(obj)) return undefined;
    for (const n of names) if (obj[n] !== undefined) return obj[n];
    return undefined;
  }
  // The own keys of obj but those used, into an object without a prototype: a recorded key
  // "__proto__" is a key of the copy like any other, not its prototype.
  function rest(obj, used) {
    const out = Object.create(null);
    if (!isObj(obj)) return out;
    for (const [k, v] of Object.entries(obj)) if (!used.includes(k)) out[k] = v;
    return out;
  }
  // The own keys of each object in turn, a later one's over an earlier one's, into an object
  // without a prototype, as rest() does.
  function merged(...objs) {
    const out = Object.create(null);
    for (const obj of objs) for (const [k, v] of Object.entries(obj)) out[k] = v;
    return out;
  }
  // A lookup in a fixed table by a key from the data or the URL: own properties only, so
  // "constructor" or "__proto__" find nothing.
  function own(table, key) { return typeof key === 'string' && Object.hasOwn(table, key) ? table[key] : undefined; }
  function plural(n, one, many) { return n + ' ' + (n === 1 ? one : (many || one + 's')); }

  // ---- generic rendering, for whatever a view passes that this page does not know ------

  function scalar(v) {
    if (v === null || v === undefined) return h('span', { class: 'muted' }, v === null ? 'null' : '—');
    if (typeof v === 'boolean') return h('span', { class: 'mono' }, String(v));
    if (typeof v === 'number') return mono(String(v));
    return mono(v);
  }

  function jsonText(v) {
    if (typeof v === 'string') return v;
    try { return jsonOf(v, null); } catch (e) { return String(v); }
  }

  function jsonBlock(v) {
    let text;
    try { text = jsonOf(v, ''); } catch (e) { text = String(v); }
    return h('pre', { class: 'wire' }, vis(text, true));
  }

  function textBlock(v) { return h('pre', { class: 'wire' }, vis(v, true)); }

  function val(v, depth) {
    depth = depth || 0;
    if (!Array.isArray(v) && !isObj(v)) return scalar(v);
    if (Array.isArray(v)) {
      if (v.length === 0) return h('span', { class: 'muted' }, '[]');
      if (v.every((x) => !Array.isArray(x) && !isObj(x))) {
        return h('span', { class: 'mono wire' }, v.map((x, i) => [i ? ', ' : '', x === null ? 'null' : String(x)]));
      }
      if (depth >= 2) return jsonBlock(v);
      if (v.every(isObj)) return objTable(v);
      return jsonBlock(v);
    }
    if (Object.keys(v).length === 0) return h('span', { class: 'muted' }, '{}');
    if (depth >= 3) return jsonBlock(v);
    return kv(Object.entries(v).map(([k, x]) => [k, val(x, depth + 1)]));
  }

  function kv(pairs) {
    const dl = h('dl', { class: 'kv' });
    for (const [k, v] of pairs) {
      if (v === undefined) continue;
      dl.appendChild(h('dt', null, k));
      dl.appendChild(h('dd', null, v instanceof Node ? v : val(v)));
    }
    return dl;
  }

  function cellText(v) {
    if (v === null || v === undefined) return dash();
    if (typeof v === 'boolean' || typeof v === 'number') return scalar(v);
    if (typeof v === 'string') return mono(v);
    return mono(jsonText(v));
  }

  function objTable(rows) {
    const keys = [];
    for (const r of rows) for (const k of Object.keys(r)) if (!keys.includes(k)) keys.push(k);
    return table(keys.map((k) => ({ label: k })), rows.map((r) => keys.map((k) => cellText(r[k]))));
  }

  // columns: [{label, num, cls}] ; rows: [cells] or {cells, cls}. A column's cls is one of the
  // page's own width classes (w-ref, w-time, w-pair): a minimum for the identifier the column
  // holds, so that it stays on one line where there is room.
  function table(columns, rows, opts) {
    opts = opts || {};
    const colClass = (c) => (c ? [c.num ? 'num' : null, c.cls || null].filter(Boolean).join(' ') : '') || null;
    const thead = h('thead', null, h('tr', null, columns.map((c) => h('th', { scope: 'col', class: colClass(c) }, c.label))));
    const tbody = h('tbody');
    for (const row of rows) {
      if (row instanceof Node) { tbody.appendChild(row); continue; }
      const cells = Array.isArray(row) ? row : row.cells;
      const tr = h('tr', { class: Array.isArray(row) ? null : row.cls || null });
      cells.forEach((c, i) => tr.appendChild(h('td', { class: colClass(columns[i]) }, c)));
      tbody.appendChild(tr);
    }
    return h('div', { class: 'tablewrap' }, h('table', { class: opts.cls || null }, thead, tbody));
  }

  function rowNote(span, ...kids) {
    return h('tr', { class: 'rownote' }, h('td', { colspan: span }, ...kids));
  }

  function panel(title, note, ...body) {
    const t = fromTemplate('tpl-panel');
    add(t.slot('title'), [title]);
    if (note) add(t.slot('note'), [note]); else t.slot('note').remove();
    add(t.slot('body'), body);
    return t.node;
  }

  function pageHead(eyebrow, title, lede, opts) {
    const t = fromTemplate('tpl-pagehead');
    add(t.slot('eyebrow'), [eyebrow]);
    add(t.slot('title'), [title]);
    if (opts && opts.mono) t.slot('title').classList.add('mono');
    if (lede) add(t.slot('lede'), [lede]); else t.slot('lede').remove();
    return t.node;
  }

  function others(obj, used, title) {
    const r = rest(obj, used);
    if (Object.keys(r).length === 0) return null;
    return h('details', null, h('summary', null, title || 'Other fields, as given'), val(r));
  }

  // ---- states, provenance, chips --------------------------------------------------------

  const STATES = ['complete', 'call_failed', 'incomplete', 'server_failed', 'sandbox_failed', 'refused', 'unfiled'];
  const PROVENANCES = ['reference', 'poison', 'real-world'];

  function stateClass(state) { return STATES.includes(state) ? 'st-' + state : 'st-other'; }

  function stateChip(state, extra, big) {
    return h('span', { class: 'chip ' + stateClass(state) + (big ? ' lg' : '') },
      state === null || state === undefined ? '—' : String(state),
      extra !== undefined && extra !== null ? ' · ' + extra : '');
  }

  function provTag(p) {
    if (p === null || p === undefined) return dash();
    return h('span', { class: 'tag ' + (PROVENANCES.includes(p) ? 'pv-' + p : 't-plain') }, String(p));
  }

  function tag(cls, ...kids) { return h('span', { class: 'tag ' + cls }, ...kids); }

  function causeKeys(causes) {
    const list = asList(causes);
    if (list.length === 0) return dash();
    return h('span', { class: 'chips' }, list.map((c) => code(isObj(c) ? c.cause : c)));
  }

  // The isolations this version records and those under which it observes egress, from
  // /api/about (verdict.ISOLATIONS, verdict.OBSERVED_ISOLATIONS); null until it has answered.
  let ISOLATIONS = null;
  let OBSERVED = null;

  // An isolation, and "egress not observed" for every one not observed: as the view or the
  // store says it (observed, a boolean) or, where neither does, by /api/about's list. An
  // isolation this version does not know is shown as unknown, and never as observed.
  function isolationCell(iso, observed) {
    const known = typeof iso === 'string' && (ISOLATIONS === null || ISOLATIONS.includes(iso));
    const seen = typeof observed === 'boolean' ? observed
      : OBSERVED !== null && typeof iso === 'string' ? OBSERVED.includes(iso) : null;
    const name = iso === null || iso === undefined ? h('span', { class: 'muted' }, 'not recorded')
      : known ? mono(iso) : frag(mono(iso), ' ', tag('t-missing', 'unknown isolation'));
    if (seen === true && known) return name;
    if (seen === null && known) return frag(name, h('br'), h('span', { class: 'sub' }, 'whether egress is observed is not known to this page'));
    return frag(name, h('br'), h('span', { class: 'egress-unobserved' }, 'egress not observed'));
  }

  // What kind of version a server version is, as the view or the store gives it
  // (server_version_kind) — never read from the version string.
  const VERSION_KIND = {
    content: 'content', revision: 'revision', declared: 'declared — the operator\'s word, not checked',
    mixed: 'mixed — the runs name more than one kind', unknown: 'kind unknown',
  };

  function versionKind(kind) {
    if (typeof kind !== 'string') return tag('t-missing', 'kind not given');
    const words = own(VERSION_KIND, kind);
    return tag(kind === 'content' || kind === 'revision' ? 't-plain' : 't-warn', words || kind);
  }

  function versionCell(version, kind, shorten) {
    if (version === null || version === undefined) return dash();
    return frag(mono(shorten ? short(version) : version), ' ', versionKind(kind));
  }

  function short(hash) {
    if (typeof hash !== 'string') return hash;
    return hash.length > 23 ? hash.slice(0, 19) + '…' + hash.slice(-4) : hash;
  }

  // ---- TLS, only as recorded (CONTRACT 7.3): nothing here is checked, fetched or worked out --

  // A long hex string (a certificate's SHA-256): whole, wrapping within its box.
  function hex(v) { return typeof v === 'string' ? h('span', { class: 'mono wire hex' }, v) : cellText(v); }

  // A run's or a store row's certificates, as given: a list, null (no TLS), or absent (nothing).
  function certificates(list, none) {
    if (list === undefined) return undefined;
    if (list === null) return h('span', { class: 'sub' }, none || 'no TLS');
    if (!Array.isArray(list)) return val(list);
    if (!list.length) return h('span', { class: 'muted' }, 'none recorded');
    return h('ul', { class: 'plain hexlist' }, list.map((c) => h('li', null, hex(c))));
  }

  // run_finished.http.tls: the run's set. Absent (a recording made before TLS was spoken) shows
  // nothing; null is plain HTTP, which this version speaks to a loopback address only — said so
  // only where the scheme recorded is not https, and there null is shown as no TLS recorded.
  function tlsSet(t, scheme) {
    if (t === undefined) return undefined;
    if (t === null && scheme === 'https') return frag(scalar(null), ' ', h('span', { class: 'sub' }, 'no TLS recorded for this https run'));
    if (t === null) return h('span', { class: 'sub' }, 'no TLS (plain HTTP to a loopback address)');
    if (!isObj(t)) return val(t);
    // Each list as recorded: empty is none recorded; a key absent is not shown, and a value of
    // another shape is shown as given — never made a list here.
    const v = t.versions, c = t.certificates;
    const versions = !Array.isArray(v) ? (v === undefined ? undefined : val(v))
      : v.length ? h('span', { class: 'chips' }, v.map((x) => code(x))) : h('span', { class: 'muted' }, 'none recorded');
    return h('div', { class: 'stack tls' },
      kv([
        ['versions', versions],
        ['certificates (SHA-256)', Array.isArray(c) ? certificates(c) : c === undefined ? undefined : val(c)],
      ]),
      tag('t-plain', 'as presented, not checked here'),
      others(t, ['versions', 'certificates']));
  }

  // One exchange's http_request.tls: its connection's version and certificate. null and absent
  // show nothing.
  function exchangeTls(t) {
    if (t === undefined || t === null) return '';
    if (!isObj(t)) return cellText(t);
    return frag(code(t.version), h('br'), hex(t.certificate_sha256), others(t, ['version', 'certificate_sha256']));
  }

  // The variables OpenSSL reads to find the trust store, as run_started.trust_store_env names them.
  const TRUST_STORE_VARIABLES = ['SSL_CERT_FILE', 'SSL_CERT_DIR'];

  // run_started.trust_store_env: which variable was set, never a value (none is recorded).
  // null (not an https run) and absent show nothing.
  function trustStore(e) {
    if (e === undefined || e === null) return undefined;
    if (!isObj(e)) return val(e);
    const set = TRUST_STORE_VARIABLES.filter((n) => e[n] === true);
    const odd = Object.fromEntries(Object.entries(e).filter(([k, x]) => !TRUST_STORE_VARIABLES.includes(k) || typeof x !== 'boolean'));
    return frag(
      set.length ? [set.map((n, i) => [i ? ', ' : '', code(n)]), ' set', h('br'), sub('the trust store these variables name; their values are not recorded')]
        : h('span', null, 'the machine\'s trust store, as OpenSSL found it'),
      Object.keys(odd).length ? h('details', null, h('summary', null, 'as given'), val(odd)) : null);
  }

  // The generation a run spoke, as recorded: the opening's decision (era_decided: the era, the version, how the probe
  // was answered, a stop and its reason, a generation the engagement file declares that the server did not speak) or,
  // where only initialize opened the run, the era script_finished ends with. Nothing is worked out here.
  function generation(o) {
    const decided = asList(isObj(o) ? o.era_decided : null).filter(isObj);
    const d = decided.length ? decided[decided.length - 1] : null;
    const finished = asList(isObj(o) ? o.script_finished : null).filter(isObj);
    const f = finished.length ? finished[finished.length - 1] : null;
    const era = d ? d.era : (f ? f.era : undefined);
    const version = d ? d.version : (f ? f.protocol_version : undefined);
    if ((era === undefined || era === null) && (version === undefined || version === null) && !d) return undefined;
    const probe = d && isObj(d.probe) ? d.probe : null;
    const declared = d && isObj(d.declared) ? d.declared : null;
    return frag(
      era === undefined || era === null ? 'none settled' : mono(era), version ? [' · ', mono(version)] : null,
      probe ? [h('br'), sub('the probe server/discover was answered as ', code(probe.outcome))] : null,
      d && d.outcome === 'stop' ? [h('br'), 'stopped at the opening · ', code(d.reason), isObj(d.refusal) && d.refusal.code !== undefined && d.refusal.code !== null ? [' · error ', code(d.refusal.code)] : null, sub(' — no listing was sent')] : null,
      declared && d.differs === true ? [h('br'), 'the engagement file declares ', mono(String(declared.era) + (declared.version ? ' ' + declared.version : '')), sub(' — an observation, not a stop')] : null);
  }

  // run_started.auth: whom the run spoke as and where its token came from — never a value. null: no token, no identity;
  // absent (a recording from before) shows nothing.
  function authCell(a) {
    if (a === undefined) return undefined;
    if (a === null) return h('span', null, 'no token was sent, and no identity was chosen');
    if (!isObj(a)) return val(a);
    const who = a.identity ? [' as ', mono(a.identity), a.role ? [' (', mono(a.role), ')'] : null] : null;
    const rest2 = others(a, ['identity', 'role', 'token_used', 'source', 'env_name']);
    if (a.token_used !== true) return frag('no token was sent', who, sub(' — no Authorization header'), rest2);
    return frag('a token was used', who, ' (', a.source === 'env' ? ['env ', mono(a.env_name)] : (a.source === 'file' ? 'a file' : mono(a.source)), ')', rest2);
  }

  // run_finished.http: the counts as given, its tls in words.
  function httpFinished(x, scheme) {
    if (!isObj(x)) return val(x);
    return kv(Object.entries(x).map(([k, v]) => [k, k === 'tls' ? tlsSet(v, scheme) : val(v, 1)]));
  }

  // The scheme run_started.endpoint records, or undefined.
  function schemeOf(rs) { return isObj(rs) && isObj(rs.endpoint) ? rs.endpoint.scheme : undefined; }

  // A failure's recorded detail — under reason tls the TLS library's text, masked when it was
  // recorded — as text, with the verdict's causes for it beside it: the cause its reason names
  // (tls), or, where none does, the cause named after the event.
  function failureView(ev, causes) {
    const all = asList(causes).filter(isObj);
    let mine = all.filter((c) => c.cause === ev.reason);
    if (!mine.length) mine = all.filter((c) => c.cause === ev.type);
    const detail = ev.detail;
    return h('div', { class: 'failure' },
      h('div', null, h('h3', null, 'detail, as recorded'),
        typeof detail === 'string' && detail !== '' ? textBlock(detail)
          : detail === undefined || detail === '' ? h('p', { class: 'none' }, 'none recorded') : val(detail)),
      h('div', null, h('h3', null, 'the cause, from the verdict'),
        mine.length ? causeList(mine) : h('p', { class: 'none' }, 'no cause of the verdict is named after it')));
  }

  // ---- routes --------------------------------------------------------------------------

  function href(path, params) {
    const qs = new URLSearchParams();
    if (params) for (const [k, v] of Object.entries(params)) if (v !== null && v !== undefined && v !== '') qs.set(k, String(v));
    const s = qs.toString();
    return '#/' + path + (s ? '?' + s : '');
  }

  function link(path, params, ...kids) { return h('a', { href: href(path, params) }, ...kids); }

  // ---- the API -------------------------------------------------------------------------

  function localError(text) {
    return { view: 'error', notices: [{ kind: 'page_error', text, where: 'view' }], data: null, status: 0 };
  }

  async function api(path, params) {
    const qs = new URLSearchParams();
    if (params) for (const [k, v] of Object.entries(params)) if (v !== null && v !== undefined) qs.set(k, String(v));
    const s = qs.toString();
    const url = 'api/' + path + (s ? '?' + s : '');
    let res;
    try {
      res = await fetch(url, { headers: { Accept: 'application/json' }, cache: 'no-store', credentials: 'same-origin', redirect: 'error' });
    } catch (e) {
      return localError('The viewer could not be reached (' + String(e && e.message || e) + ').');
    }
    let body = null;
    try { body = await res.json(); } catch (e) { body = null; }
    if (!isObj(body) || !Array.isArray(body.notices)) {
      return localError('The answer to /api/' + path + ' was not an envelope (HTTP ' + res.status + ').');
    }
    body.status = res.status;
    body.notices = body.notices.filter(isObj);
    return body;
  }

  // ---- notices -------------------------------------------------------------------------

  const NOTICE_KINDS = [
    'not_given', 'store_refused', 'recording_changed', 'recording_not_found', 'bundle_not_intact',
    'refused', 'not_a_result', 'comparison_not_complete', 'fleet_state_not_in_store', 'capped',
    'not_in_this_recording', 'not_recorded_by_this_version', 'candidates',
  ];
  const ERROR_KINDS = ['not_found', 'conflict', 'bad_request', 'forbidden', 'method_not_allowed', 'misdirected_request', 'internal_error', 'page_error'];
  const NOTICE_LABEL = {
    not_given: 'Not given',
    store_refused: 'Store refused',
    recording_changed: 'Recording changed',
    recording_not_found: 'Recording not found',
    bundle_not_intact: 'Bundle not intact',
    refused: 'Refused',
    not_a_result: 'Not a result',
    comparison_not_complete: 'Comparison not complete',
    fleet_state_not_in_store: 'Fleet state not in the store',
    capped: 'Capped',
    not_in_this_recording: 'Not in this recording',
    not_recorded_by_this_version: 'Not recorded by this version',
    candidates: 'Candidates for disclosure',
    not_found: 'Not found',
    conflict: 'Not served',
    bad_request: 'Bad request',
    forbidden: 'Forbidden',
    method_not_allowed: 'Method not allowed',
    misdirected_request: 'Misdirected request',
    internal_error: 'Internal error',
    page_error: 'The page could not read an answer',
  };

  function cappedWords(n) {
    const shown = n.shown, total = n.total;
    const hasShown = shown !== null && shown !== undefined;
    if (total === null || total === undefined) {
      return hasShown ? shown + ' shown, capped; the total was not recorded' : 'capped; the total was not recorded';
    }
    return (hasShown ? shown : '?') + ' of ' + total + ' shown, capped';
  }

  function causeList(causes) {
    const list = asList(causes);
    if (list.length === 0) return h('p', { class: 'none' }, 'none recorded');
    return h('ul', { class: 'causes' }, list.map((c) => {
      const o = isObj(c) ? c : { cause: c };
      return h('li', null,
        h('span', { class: 'key wire' }, o.cause === undefined ? '—' : String(o.cause)),
        h('span', { class: 'words wire' }, o.words === undefined || o.words === null ? h('span', { class: 'muted' }, 'no words given') : o.words),
        o.state !== undefined && o.state !== null ? stateChip(o.state) : h('span'));
    }));
  }

  // The body a notice of each kind shows below its text. Every field the kind does not name
  // is shown too, as given, so nothing a view passes is hidden.
  const NOTICE_BODY = {
    not_given(n) {
      return [['option'], h('p', { class: 'notice-text' }, 'Give ', h('span', { class: 'notgiven-option wire' }, n.option === undefined ? '(option not named)' : n.option), ' on the command line; this view reads nothing without it.')];
    },
    store_refused(n) {
      return [['store', 'words'], kv([['store', mono(n.store)]]), h('h3', null, 'The refusal, as raised'), textBlock(n.words === undefined ? '' : n.words), h('p', { class: 'sub' }, 'Nothing of the store is shown.')];
    },
    recording_changed(n) {
      // Either the bytes differ (found_digest), or the file could not be read (unreadable): only
      // the first says the bytes differ.
      const unreadable = n.unreadable !== undefined && n.unreadable !== null;
      return [['recording', 'found', 'filed', 'found_digest', 'unreadable'],
        h('p', { class: 'say' }, unreadable
          ? 'A file was found under --runs where this run\'s recording should be, and it could not be read; nothing of it is shown as this run\'s.'
          : 'The file found under --runs is not the recording this run was filed from; its content is never shown as this run\'s.'),
        kv([['recording, as filed', mono(n.recording)], ['found under --runs', mono(n.found)], ['filed SHA-256 (runs.run)', mono(n.filed)],
          unreadable ? ['could not be read', h('span', { class: 'wire' }, String(n.unreadable))] : ['SHA-256 of the file found', mono(n.found_digest)],
          unreadable && n.found_digest !== undefined && n.found_digest !== null ? ['SHA-256 of the file found', mono(n.found_digest)] : [null, undefined]].filter((p) => p[0] !== null))];
    },
    recording_not_found(n) {
      return [['recording', 'looked_in'], kv([['recording, as filed', mono(n.recording)], ['looked for in', mono(n.looked_in)]]), h('p', { class: 'sub' }, 'Looked for, not found there; shown from the store only.')];
    },
    bundle_not_intact(n) {
      const files = asList(n.files).filter(isObj);
      return [['directory', 'summary', 'files', 'problems'], kv([['bundle', mono(n.directory)], ['found', n.summary === undefined ? undefined : h('span', { class: 'wire' }, String(n.summary))]]),
        h('h3', null, 'Files that are not as the index lists them'),
        files.length ? table([{ label: 'Path' }, { label: 'State' }, { label: 'Note' }], files.map((f) => [mono(f.path), fileState(f.state), f.note === null || f.note === undefined ? dash() : h('span', { class: 'wire' }, String(f.note))]))
          : h('p', { class: 'none' }, 'none listed'),
        isEmpty(n.problems) ? null : [h('h3', null, 'Problems'), h('ul', { class: 'list' }, asList(n.problems).map((x) => h('li', { class: 'wire' }, x)))],
        h('p', { class: 'say' }, 'No file of this bundle is served for download.')];
    },
    refused(n) {
      // CONTRACT 6/views.py: `source` is the file's text (null when it is not readable as the
      // loaders read it), `path` the file.
      const text = typeof n.source === 'string' ? n.source : null;
      return [['source', 'path', 'words'], kv([['file', n.path === undefined ? undefined : mono(n.path)]]),
        h('h3', null, 'The loader\'s words'), textBlock(n.words === undefined ? '' : n.words),
        h('h3', null, 'The file\'s text, beside them'),
        text === null ? h('p', { class: 'none' }, n.source === null ? 'not shown: the file is not readable as the loader reads it' : 'not given') : sourceText(text)];
    },
    not_a_result(n) {
      // On the store's findings: no one state, but the runs that are not results.
      if (Array.isArray(n.runs)) {
        const ofTotal = typeof n.count === 'number' ? [String(n.count), typeof n.total === 'number' ? ' of ' + n.total : '', ' runs of this provenance are not results'] : null;
        return [['state', 'exit_code', 'rules', 'causes', 'runs', 'count', 'total'],
          n.state !== null && n.state !== undefined ? h('div', { class: 'statebig' }, stateChip(n.state, null, true)) : null,
          ofTotal ? h('p', { class: 'say' }, ofTotal) : null,
          h('h3', null, 'Runs that are not results'),
          n.runs.length ? table([{ label: 'Run' }, { label: 'State' }, { label: 'Causes' }], n.runs.map((r) => (isObj(r)
            ? [mono(short(r.run)), stateChip(r.state), causeKeys(r.causes)] : [mono(r), dash(), dash()])))
            : h('p', { class: 'none' }, 'none listed'),
          isEmpty(n.causes) ? null : [h('h3', null, 'Causes — each key with its words'), causeList(n.causes)]];
      }
      return [['state', 'exit_code', 'rules', 'causes'],
        h('div', { class: 'statebig' }, stateChip(n.state, null, true),
          h('span', { class: 'exit' }, 'exit ', n.exit_code === null || n.exit_code === undefined ? '—' : String(n.exit_code)),
          n.rules !== undefined ? h('span', { class: 'sub' }, 'judged under rules ', String(n.rules)) : null),
        h('h3', null, 'Causes — each key with its words'),
        causeList(n.causes)];
    },
    comparison_not_complete(n) {
      return [['before_state', 'after_state'], h('div', { class: 'chips' }, h('span', { class: 'sub' }, 'before'), stateChip(n.before_state), arrow(), h('span', { class: 'sub' }, 'after'), stateChip(n.after_state)),
        h('p', { class: 'sub' }, 'What it calls gone may only be missing. The comparison follows.')];
    },
    fleet_state_not_in_store(n) {
      return [['fleet', 'looked_for', 'found'], kv([['fleet', mono(n.fleet)], ['state', h('span', { class: 'tag t-missing' }, 'not recorded in the store')], ['looked for', mono(n.looked_for)],
        ['found, not the store\'s (its digest differs)', n.found === undefined || n.found === null ? undefined : mono(n.found)]])];
    },
    capped(n) {
      const unreadable = Array.isArray(n.unreadable) ? n.unreadable : null;
      return [['what', 'source', 'cap', 'shown', 'total', 'unreadable'], h('p', { class: 'say' }, cappedWords(n)),
        kv([['what', mono(n.what)], ['source', mono(n.source)], ['cap', n.cap === undefined || n.cap === null ? undefined : scalar(n.cap)]]),
        unreadable ? [h('h3', null, 'Not read'), unreadable.length ? h('ul', { class: 'list' }, unreadable.map((p) => h('li', null, mono(p)))) : h('p', { class: 'none' }, 'none listed')] : null];
    },
    not_in_this_recording(n) {
      return [['event'], h('p', { class: 'say' }, code(n.event === undefined ? '?' : n.event), ' — not in this recording')];
    },
    not_recorded_by_this_version(n) {
      return [['what'], h('p', { class: 'say' }, code(n.what === undefined ? '?' : n.what), ' — not recorded by this version')];
    },
    candidates(n, opts) {
      // A zero on a view that is not a result is not a count that reads as complete.
      const zeroNar = n.count === 0 && opts && opts.nar;
      return [['count'], h('p', { class: 'say' }, zeroNar ? 'none recorded — the run is not a result; what there is are ' : n.count === undefined || n.count === null ? 'count not recorded — ' : String(n.count) + ' — ', 'candidates for disclosure, not results to publish')];
    },
  };

  function noticeEl(n, opts) {
    opts = opts || {};
    const known = NOTICE_KINDS.includes(n.kind) || ERROR_KINDS.includes(n.kind);
    const t = fromTemplate('tpl-notice');
    const node = t.node;
    node.classList.add(known ? 'n-' + n.kind : 'n-unknown');
    if (n.kind === 'not_a_result') node.classList.add(stateClass(n.state));
    if (opts.compact) node.classList.add('compact');
    add(t.slot('label'), [known ? own(NOTICE_LABEL, n.kind) : 'Notice of a kind this page does not know']);
    add(t.slot('kind'), [n.kind === undefined ? '(no kind)' : String(n.kind)]);
    if (n.where !== undefined && n.where !== 'view') {
      const w = t.slot('where');
      add(w, ['at ']);
      if (opts.whereLink) add(w, [h('a', { href: opts.whereLink }, n.where)]); else add(w, [String(n.where)]);
    } else {
      t.slot('where').remove();
    }
    if (n.text !== undefined && n.text !== null) add(t.slot('text'), [String(n.text)]); else t.slot('text').remove();
    const body = t.slot('body');
    let used = ['kind', 'text', 'where'];
    if (opts.compact) {
      if (n.kind === 'capped') add(body, [h('span', { class: 'say' }, cappedWords(n))]);
      if (n.kind === 'not_a_result') {
        add(body, [Array.isArray(n.runs)
          ? h('span', { class: 'say' }, plural(n.runs.length, 'run') + ' not a result')
          : h('div', { class: 'chips' }, stateChip(n.state), h('span', { class: 'mono' }, 'exit ', String(n.exit_code)), causeKeys(n.causes))]);
      }
      if (n.kind === 'candidates') add(body, [h('span', { class: 'say' }, 'candidates for disclosure, not results to publish')]);
      if (n.kind === 'fleet_state_not_in_store') add(body, [h('span', { class: 'say' }, 'state: not recorded in the store')]);
      if (n.kind === 'not_in_this_recording') add(body, [h('span', { class: 'say' }, code(String(n.event)), ' — not in this recording')]);
      if (n.kind === 'not_recorded_by_this_version') add(body, [h('span', { class: 'say' }, code(String(n.what)), ' — not recorded by this version')]);
      if (n.kind === 'bundle_not_intact') add(body, [h('span', { class: 'say' }, 'not intact — no file of it is served')]);
      if (n.kind === 'recording_changed') add(body, [h('span', { class: 'say' }, n.unreadable !== undefined && n.unreadable !== null ? 'the file found could not be read' : 'the file found is not this run\'s recording')]);
      return node;
    }
    const make = own(NOTICE_BODY, n.kind);
    if (make) {
      const [fields, ...parts] = make(n, opts);
      used = used.concat(fields);
      add(body, parts);
    }
    const extra = others(n, used, 'Other fields of this notice');
    if (extra) add(body, [extra]);
    return node;
  }

  function noticeKey(n) { return [n.kind, n.where, n.text].map((x) => String(x)).join('\u0000'); }

  // Every notice of the envelope, first and in its order. Notices about a part of the view
  // are shown compact here and whole in place; a long run of them folds after the first few.
  function noticesTop(env, opts) {
    opts = opts || {};
    const box = h('div', { class: 'notices', role: 'region', 'aria-label': 'Notices' });
    const skip = opts.skip || new Set();
    const list = env.notices.filter((n) => !skip.has(noticeKey(n)));
    let i = 0;
    while (i < list.length) {
      const n = list[i];
      if (n.where === undefined || n.where === 'view') {
        box.appendChild(noticeEl(n, { nar: anyNar(env) }));
        i += 1;
        continue;
      }
      const group = [];
      while (i < list.length && list[i].where !== undefined && list[i].where !== 'view') group.push(list[i++]);
      const els = group.map((g) => noticeEl(g, { compact: true, whereLink: opts.whereLink ? opts.whereLink(g.where) : null }));
      if (els.length <= 6) { els.forEach((e) => box.appendChild(e)); continue; }
      els.slice(0, 3).forEach((e) => box.appendChild(e));
      const more = h('details', null, h('summary', null, plural(els.length - 3, 'more notice') + ' about parts of this view, in order'), h('div', { class: 'notices' }, els.slice(3)));
      box.appendChild(more);
    }
    return list.length ? box : null;
  }

  function noticesAt(env, where) {
    const list = env.notices.filter((n) => n.where === where);
    if (!list.length) return null;
    return h('div', { class: 'notices' }, list.map((n) => noticeEl(n, { nar: anyNar(env) })));
  }

  function noticesWhere(env, test) {
    const list = env.notices.filter((n) => typeof n.where === 'string' && test(n.where));
    if (!list.length) return null;
    return h('div', { class: 'notices' }, list.map((n) => noticeEl(n, {})));
  }

  function has(env, kind, where) {
    return env.notices.some((n) => n.kind === kind && (where === undefined || n.where === where));
  }

  // An empty list, never silent. With not_a_result on the envelope it says the run is not a
  // result; a notice about the list's own place is named.
  function noneRecorded(env, where, opts) {
    opts = opts || {};
    const nar = env && env.notices.find((n) => n.kind === 'not_a_result' && (n.where === 'view' || n.where === where));
    const storeNar = nar && Array.isArray(nar.runs);
    const partNar = !nar && env && env.notices.some((n) => n.kind === 'not_a_result');
    const about = env && where ? env.notices.filter((n) => n.where === where && n.kind !== 'not_a_result') : [];
    let words = 'none recorded';
    if (storeNar) words = 'none recorded — not every run filed is a result';
    else if (nar) words = 'none recorded — the run is not a result';
    else if (partNar && opts.several) words = 'none recorded — not every run here is a result';
    return h('p', { class: 'none' + (nar || (partNar && opts.several) ? ' nar' : '') }, words,
      about.length ? h('span', { class: 'sub' }, ' (see the notice: ', about.map((n, i) => [i ? ', ' : '', code(n.kind)]), ')') : null);
  }

  // The envelope says the run (view-level) is not a result, or a run behind the view is not.
  function viewNar(env) { return !!env && env.notices.some((n) => n.kind === 'not_a_result' && n.where === 'view'); }
  function anyNar(env) { return !!env && env.notices.some((n) => n.kind === 'not_a_result'); }

  // A count for a header: never a bare zero where the view is not a result.
  function countWords(env, n, one, many, tail) {
    if (n === 0 && anyNar(env)) return viewNar(env) && !narOfStore(env) ? 'none recorded — the run is not a result' : 'none recorded — not every run here is a result';
    if (n === 0) return 'none recorded';
    return plural(n, one, many) + (tail || '');
  }
  function narOfStore(env) { return env.notices.some((n) => n.kind === 'not_a_result' && n.where === 'view' && Array.isArray(n.runs)); }

  function refusedWhole(env) { return env.data === null || env.data === undefined; }

  // ---- the header ------------------------------------------------------------------------

  let PACKAGE = null;

  async function loadAbout() {
    const env = await api('about');
    const d = isObj(env.data) ? env.data : null;
    if (!d) return env;
    PACKAGE = typeof d.package === 'string' ? d.package : null;
    if (Array.isArray(d.isolations)) ISOLATIONS = d.isolations.filter((x) => typeof x === 'string');
    if (Array.isArray(d.observed_isolations)) OBSERVED = d.observed_isolations.filter((x) => typeof x === 'string');
    const pk = document.querySelector('[data-slot="package"]');
    pk.replaceChildren(vis(PACKAGE || 'viewer'));
    const ver = document.querySelector('[data-slot="version"]');
    ver.replaceChildren(vis([d.version !== undefined ? 'version ' + d.version : null,
      d.recording_schema !== undefined ? 'recording schema ' + d.recording_schema : null,
      d.store_schema !== undefined ? 'store schema ' + d.store_schema : null,
      d.rules !== undefined ? 'rules ' + d.rules : null].filter(Boolean).join(' · ')));
    if (d.local !== undefined) document.querySelector('[data-slot="local"]').replaceChildren(vis(d.local));
    return env;
  }

  function setTitle(page) { document.title = (PACKAGE ? visText(PACKAGE) + ' — ' : '') + page + ' · local read-only viewer'; }

  // ---- runs ----------------------------------------------------------------------------

  async function pageRuns() {
    setTitle('Runs');
    const env = await api('runs');
    const out = frag(pageHead('Runs', 'Recordings under --runs, each in its state',
      'Every run directory the search found, newest first. A run\'s state is what the verdict reads back from its recording.'));
    add(out, [noticesTop(env)]);
    if (refusedWhole(env)) return out;
    const rows = asList(env.data);
    const body = rows.length ? table(
      [{ label: 'Run', cls: 'w-ref' }, { label: 'Started (UTC)', cls: 'w-time' }, { label: 'Server × scenario', cls: 'w-pair' }, { label: 'Mode · transport · isolation' }, { label: 'Fleet' }, { label: 'State' }, { label: 'Exit', num: true }, { label: 'Causes' }],
      rows.map((r) => [
        frag(link('run', { ref: r.ref }, mono(r.ref)), r.run_id ? [h('br'), sub(mono(r.run_id))] : null),
        cellText(r.wall_clock_utc),
        isEmpty(r.server_name) && isEmpty(r.scenario_name) ? dash() : frag(cellText(r.server_name), h('span', { class: 'muted' }, ' × '), cellText(r.scenario_name)),
        frag(cellText(r.mode), ' · ', cellText(r.transport), ' · ', isolationCell(r.isolation, r.egress_observed)),
        r.fleet ? link('fleet', { id: r.fleet }, mono(r.fleet)) : dash(),
        stateChip(r.state), cellText(r.exit_code), causeKeys(r.causes),
      ])) : noneRecorded(env, 'view');
    add(out, [panel('Runs', rows.length ? plural(rows.length, 'run') + ' listed' + (has(env, 'capped', 'view') ? ' · capped, see the notice' : '') : null, body)]);
    return out;
  }

  // ---- one run -------------------------------------------------------------------------

  const TAB_LABEL = {
    overview: 'Overview', verdict: 'Verdict', messages: 'Messages', findings: 'Findings and observations',
    inventory: 'Inventory', interventions: 'Interventions', 'http': 'HTTP', sandbox: 'Sandbox', stderr: 'stderr',
  };

  function whereTab(ref) {
    return (where) => {
      const m = /^(tab|listing):(.+)$/.exec(where);
      if (!m) return null;
      return href('run', { ref, tab: m[1] === 'tab' ? m[2] : 'inventory' });
    };
  }

  async function pageRun(p) {
    const ref = p.get('ref');
    setTitle('Run');
    const env = await api('run', { ref });
    const d = isObj(env.data) ? env.data : null;
    const tabs = d ? asList(d.tabs).filter((t) => typeof t === 'string') : [];
    const tab = p.get('tab') || 'overview';
    const out = frag();
    const rs = d && isObj(d.overview) ? d.overview.run_started : null;
    const v = d && isObj(d.verdict) ? d.verdict : null;
    // Notices first, before anything of data: the heading names only what was asked for.
    out.appendChild(pageHead('Run', ref === null ? '(no run named)' : ref, null, { mono: true }));
    add(out, [noticesTop(env, { whereLink: whereTab(ref) })]);
    if (!d) return out;
    out.appendChild(runHead(d, rs, v, env));
    const nav = h('nav', { class: 'tabs', 'aria-label': 'Parts of this run' }, tabs.map((t) =>
      h('a', { href: href('run', { ref, tab: t }), 'aria-current': t === tab ? 'page' : null }, own(TAB_LABEL, t) || t)));
    out.appendChild(nav);
    if (!tabs.includes(tab)) {
      out.appendChild(h('p', { class: 'inplace' }, 'This run has no ', code(tab), ' part. Its parts are the tabs above.'));
      return out;
    }
    const part = h('div', { class: 'stack', id: 'tab-' + tab });
    add(part, [noticesAt(env, 'tab:' + tab)]);
    if (tab === 'verdict') add(part, [noticesAt(env, 'verdict')]);
    const content = Object.hasOwn(d, tab) ? d[tab] : undefined;
    try {
      switch (tab) {
        case 'overview': add(part, [tabOverview(env, content, d.egress_observed, v)]); break;
        case 'verdict': add(part, [tabVerdict(env, v)]); break;
        case 'messages': add(part, [await tabMessages(env, ref, p)]); break;
        case 'findings': add(part, [await tabFindings(env, content, ref, p, d.messages)]); break;
        case 'inventory': add(part, [tabInventory(env, content, ref, v)]); break;
        case 'interventions': add(part, [tabInterventions(env, content, ref)]); break;
        case 'http': add(part, [tabHttp(env, content, ref, schemeOf(rs))]); break;
        case 'sandbox': add(part, [tabSandbox(env, content)]); break;
        case 'stderr': add(part, [tabStderr(env, content)]); break;
        default: add(part, [panel(own(TAB_LABEL, tab) || tab, 'shown as given', val(content))]);
      }
    } catch (e) {
      add(part, [noticeEl({ kind: 'page_error', text: 'This part could not be drawn: ' + String(e && e.message || e) + '. It is shown as given below.' }), jsonBlock(content)]);
    }
    out.appendChild(part);
    return out;
  }

  function runHead(d, rs, v, env) {
    const head = h('div', { class: 'runhead' });
    const mode = isObj(rs) ? rs.mode : null;
    const ph = h('div', { class: 'pagehead' }, h('div', { class: 'eyebrow' }, 'State, from the verdict', mode ? [' · ', String(mode), ' mode'] : null));
    if (v) ph.appendChild(h('div', { class: 'headrow' }, stateChip(v.state, 'exit ' + (v.exit_code === null || v.exit_code === undefined ? '—' : v.exit_code), true)));
    head.appendChild(ph);
    if (d) {
      const pairs = [['recording', mono(d.recording)]];
      if (isObj(rs)) {
        pairs.push(['mode', frag(mono(rs.mode), rs.script ? [' · script ', mono(rs.script)] : null)]);
        pairs.push(['transport', mono(rs.transport)]);
        if (rs.endpoint !== undefined && rs.endpoint !== null) pairs.push(['endpoint', mono(rs.endpoint)]);
        if (schemeOf(rs) !== undefined) pairs.push(['scheme', mono(schemeOf(rs))]);
        const fin = isObj(d.overview) && isObj(d.overview.run_finished) ? d.overview.run_finished : null;
        if (fin && isObj(fin.http) && Object.hasOwn(fin.http, 'tls')) pairs.push(['TLS', tlsSet(fin.http.tls, schemeOf(rs))]);
        pairs.push(['trust store', trustStore(rs.trust_store_env)]);
        pairs.push(['generation', generation(d.overview)]);
        pairs.push(['auth', authCell(rs.auth)]);
        pairs.push(['isolation', isolationCell(rs.isolation, d.egress_observed)]);
        pairs.push(['server', mono(rs.server_name)]);
        if (d.server_version !== undefined && d.server_version !== null) pairs.push(['server version', versionCell(d.server_version, d.server_version_kind)]);
        if (rs.scenario_name) pairs.push(['scenario', mono(rs.scenario_name)]);
      }
      head.appendChild(h('div', { class: 'factbox' }, kv(pairs)));
      if (env && has(env, 'refused', 'engagement')) {
        head.appendChild(frag(engagementHeader('run', null, 'Refused: the engagement this run recorded is not one this version reads.'), noticesAt(env, 'engagement')));
      } else if (d.engagement !== undefined) head.appendChild(engagementHeader('run', d.engagement));
    }
    return head;
  }

  // ---- the engagement header (run, fleet, store) -------------------------------------------

  function windowWords(w) {
    if (!isObj(w)) return w === undefined ? undefined : val(w);
    return frag(mono(w.from === undefined ? '—' : w.from), arrow(), mono(w.until === undefined ? '—' : w.until));
  }

  // A run's or a fleet's: the file's id, digest and window as the recording or fleet.json
  // carries them — declared, never checked here. A run adds pacing_enforced, pacing and window_exceeded.
  function engagementHeader(what, e, notKnown) {
    const box = h('section', { class: 'engagement', 'aria-label': 'Engagement' });
    box.appendChild(h('div', { class: 'eyebrow' }, 'Engagement', what === 'fleet' ? ' · from fleet.json' : ' · as recorded'));
    if (notKnown) { box.appendChild(h('p', { class: 'inplace' }, notKnown)); return box; }
    if (e === null || e === undefined) {
      box.appendChild(h('p', { class: 'sub' }, what === 'fleet' ? 'none: this fleet\'s fleet.json names no engagement file' : 'none: this run recorded no engagement file'));
      return box;
    }
    const pairs = [
      ['id (declared)', mono(e.engagement_id_declared)],
      ['digest of the file', mono(e.engagement_digest)],
      ['window (declared)', windowWords(e.window_declared)],
    ];
    if (what === 'run') {
      pairs.push(['pacing_enforced', pacing(e.pacing_enforced, e.pacing)]);
      pairs.push(['window_exceeded', windowExceeded(e.window_exceeded)]);
    }
    box.appendChild(kv(pairs));
    return box;
  }

  function seqLink(ref, seq) {
    if (seq === null || seq === undefined) return dash();
    return link('run', { ref, tab: 'messages', seq }, mono('#' + seq));
  }

  function dirArrow(dir) {
    if (dir === 'client_to_server') return frag(h('span', { 'aria-hidden': 'true' }, '→ '), sub('client to server'));
    if (dir === 'server_to_client') return frag(h('span', { 'aria-hidden': 'true' }, '← '), sub('server to client'));
    return cellText(dir);
  }

  function dirShort(dir) {
    if (dir === 'client_to_server') return h('span', { 'aria-label': 'client to server' }, '→');
    if (dir === 'server_to_client') return h('span', { 'aria-label': 'server to client' }, '←');
    return cellText(dir);
  }

  function seconds(ns) {
    if (typeof ns !== 'number') return scalar(ns);
    return mono((ns / 1e9).toFixed(3) + ' s');
  }

  // Whose exit code is it (cli.RUN_EXIT_STATUS, DRIVE_EXIT_STATUS; audit 3.8).
  const EXIT_OWNER = {
    driver: 'drive: the run\'s state is the exit code; the server\'s own exit is recorded here and said on the terminal, never handed through.',
    proxy: 'run: the server\'s own exit code is handed through — a client started this tool in the server\'s place — unless the server never started or wrote nothing (server_failed, 4).',
  };

  function eventOrNone(env, ev, where) {
    if (ev === null || ev === undefined) return noneRecorded(env, where);
    if (Array.isArray(ev)) {
      if (!ev.length) return noneRecorded(env, where);
      return h('div', { class: 'stack' }, ev.map((e) => val(e)));
    }
    return val(ev);
  }

  // run_started.pacing_enforced with run_started.pacing: true is shown with what the run was held
  // to (runs_per_origin, min_interval_seconds, source), false (a recording of an earlier version)
  // as declared and not enforced, null or absent not at all. Any other value is text, as it stands.
  // Beside any value but true, null and absent too, a run_started.pacing that is there is shown
  // after it, as recorded. Beside true, any key of pacing but the three stands after them, as recorded.
  // One of the three that is not a string, number, boolean or null stands as recorded too, through val().
  const PACING_HELD = ['runs_per_origin', 'min_interval_seconds', 'source'];
  function heldValue(x) { return x === null || ['string', 'number', 'boolean'].includes(typeof x) ? mono(x) : val(x); }
  function pacing(v, held) {
    const beside = held === undefined || held === null ? null : [' ', val(held)];
    if (v === undefined || v === null) return beside ? frag(scalar(v), beside) : undefined;
    if (v === false) return frag(scalar(v), ' ', h('span', { class: 'sub' }, 'pacing declared, not enforced by the version that made it'), beside);
    if (v !== true) return frag(scalar(v), beside);
    if (!isObj(held)) return frag(scalar(v), ' ', held === undefined || held === null ? sub('the values it was held to are not recorded') : val(held));
    const more = rest(held, PACING_HELD);
    return frag(scalar(v), ' ', sub('runs_per_origin ', heldValue(held.runs_per_origin), ' · min_interval_seconds ', heldValue(held.min_interval_seconds), ' · source ', heldValue(held.source)),
      Object.keys(more).length ? [' ', val(more)] : null);
  }

  // The paced events of a run, each as recorded: seconds, why and, where it has one, status. No sum.
  function pacedWaits(events) {
    const list = asEvents(events);
    if (!list.length) return null;
    const rows = list.filter(isObj);
    return panel('Waits', 'paced · as recorded', h('div', { class: 'stack' },
      rows.length ? objTable(rows) : null, list.filter((e) => !isObj(e)).map((e) => val(e))));
  }

  // run_finished.window_exceeded: true when the run finished after its engagement's window closed.
  function windowExceeded(v) {
    if (v === undefined || v === null) return undefined;
    if (v === true) return frag(scalar(v), ' ', tag('t-warn', 'finished after the engagement\'s window closed'));
    return scalar(v);
  }

  function tabOverview(env, o, egress, v) {
    if (!isObj(o)) return noneRecorded(env, 'tab:overview');
    const out = h('div', { class: 'stack' });
    const rs = o.run_started;
    const mm = o.server_name_mismatch;
    for (const m of asEvents(mm)) {
      if (!isObj(m)) continue;
      out.appendChild(h('div', { class: 'banner', role: 'note' }, h('span', { class: 'key' }, 'server_name_mismatch'),
        'The server announces itself as ', code(m.announced), '; the run declared ', code(m.declared),
        m.message_seq !== undefined ? [' (message #', String(m.message_seq), ')'] : null, '. Findings are keyed by the declared name.'));
    }
    for (const f of asEvents(o.server_failed)) {
      if (!isObj(f)) continue;
      out.appendChild(panel(['server_failed · ', code(f.reason)], 'the handshake did not complete · as recorded',
        failureView(f, isObj(v) ? v.causes : null), others(f, ['type', 'reason', 'detail', 'v', 'run_id', 'seq', 't_ns'])));
    }
    const top = h('div', { class: 'cols' });
    if (isObj(rs)) {
      const used = ['argv', 'argv_redaction_count', 'mode', 'script', 'script_digest', 'script_vars', 'server_identity', 'scenario_name', 'server_name', 'reproduction', 'authorization', 'virtual_environment', 'isolation', 'transport', 'endpoint', 'limits', 'wall_clock_utc', 'tool_version', 'schema_version', 'pacing_enforced', 'pacing', 'trust_store_env', 'auth'];
      top.appendChild(panel('run_started', 'as recorded', kv([
        ['mode', mono(rs.mode)],
        ['script', rs.script === undefined ? undefined : frag(mono(rs.script), rs.script_digest ? [h('br'), sub(mono(rs.script_digest))] : null)],
        ['script_vars', rs.script_vars === undefined ? undefined : val(rs.script_vars)],
        ['scenario_name', rs.scenario_name === undefined ? undefined : mono(rs.scenario_name)],
        ['server_name', mono(rs.server_name)],
        ['transport', mono(rs.transport)],
        ['endpoint', rs.endpoint === undefined ? undefined : mono(rs.endpoint === null ? '—' : rs.endpoint)],
        ['scheme', schemeOf(rs) === undefined ? undefined : mono(schemeOf(rs))],
        ['trust_store_env', trustStore(rs.trust_store_env)],
        ['auth', authCell(rs.auth)],
        ['isolation', isolationCell(rs.isolation, egress)],
        ['wall_clock_utc', mono(rs.wall_clock_utc)],
        ['tool_version', mono(rs.tool_version)],
        ['schema_version', scalar(rs.schema_version)],
        ['virtual_environment', rs.virtual_environment === undefined ? undefined : val(rs.virtual_environment)],
        ['server_identity', rs.server_identity === undefined ? undefined : val(rs.server_identity)],
        ['argv', rs.argv === undefined ? undefined : h('ol', { class: 'list mono', start: 0 }, asList(rs.argv).map((a) => h('li', null, mono(a))))],
        ['argv_redaction_count', rs.argv_redaction_count === undefined ? undefined : scalar(rs.argv_redaction_count)],
        ['pacing_enforced', pacing(rs.pacing_enforced, rs.pacing)],
      ]), others(rs, used)));
    } else {
      top.appendChild(panel('run_started', null, noneRecorded(env, 'tab:overview')));
    }
    const side = h('div', { class: 'stack' });
    const decidedEvents = asEvents(o.era_decided).filter(isObj);
    if (decidedEvents.length) side.appendChild(panel('Generation', 'era_decided · as recorded', h('div', { class: 'stack' }, decidedEvents.map((e) => val(e)))));
    const exited = o.server_exited;
    side.appendChild(panel('Server exit', 'server_exited', isEmpty(exited)
      ? noneRecorded(env, 'tab:overview')
      : h('div', { class: 'stack' }, asEvents(exited).map((e) => val(e))), isObj(rs) && own(EXIT_OWNER, rs.mode) ? h('p', { class: 'sub' }, own(EXIT_OWNER, rs.mode)) : null));
    const finishedKeys = ['reason', 'message_count', 'duration_ns', 'dropped_events', 'unwritten_events', 'server_redactions', 'http', 'window_exceeded'];
    // run_finished's fields, nested (views.py) or flat beside the events (CONTRACT 6.1's words).
    const fin = isObj(o.run_finished) ? o.run_finished : o;
    const anyFinished = isObj(o.run_finished) || finishedKeys.some((k) => o[k] !== undefined && o[k] !== null);
    side.appendChild(panel('run_finished — the account', viewNar(env) ? 'as recorded · the run is not a result: what it counts is not all there was' : 'written on the path that cannot drop', anyFinished ? kv([
      ['reason', fin.reason === undefined ? undefined : scalar(fin.reason)],
      ['message_count', fin.message_count === undefined ? undefined : scalar(fin.message_count)],
      ['duration', fin.duration_ns === undefined ? undefined : seconds(fin.duration_ns)],
      ['dropped_events', fin.dropped_events === undefined ? undefined : scalar(fin.dropped_events)],
      ['unwritten_events', fin.unwritten_events === undefined ? undefined : scalar(fin.unwritten_events)],
      ['server_redactions', fin.server_redactions === undefined ? undefined : scalar(fin.server_redactions)],
      ['http', fin.http === undefined ? undefined : httpFinished(fin.http, schemeOf(rs))],
      ['window_exceeded', windowExceeded(fin.window_exceeded)],
    ]) : noneRecorded(env, 'tab:overview'), isObj(o.run_finished) ? others(o.run_finished, finishedKeys) : null));
    top.appendChild(side);
    out.appendChild(top);
    if (isObj(rs)) {
      const trip = h('div', { class: 'cols-3' });
      trip.appendChild(panel('Reproduction triple', 'run_started.reproduction', rs.reproduction === undefined || rs.reproduction === null ? noneRecorded(env, 'tab:overview') : jsonBlock(rs.reproduction)));
      trip.appendChild(panel('authorization', 'a claim as recorded, never verified', rs.authorization === undefined || rs.authorization === null ? noneRecorded(env, 'tab:overview') : val(rs.authorization)));
      trip.appendChild(panel('limits', null, rs.limits === undefined || rs.limits === null ? noneRecorded(env, 'tab:overview') : val(rs.limits)));
      out.appendChild(trip);
    }
    const waits = pacedWaits(o.paced);
    if (waits) out.appendChild(waits);
    const stops = [['run_stopped', o.run_stopped], ['recording_stopped', o.recording_stopped], ['limit_exceeded', o.limit_exceeded]];
    out.appendChild(panel('Stops and limits', 'run_stopped · recording_stopped · limit_exceeded',
      kv(stops.map(([k, x]) => [k, isEmpty(x) ? h('span', { class: 'muted' }, 'none recorded') : h('div', { class: 'stack' }, asEvents(x).map((e) => val(e)))]))));
    const extra = others(o, ['run_started', 'server_failed', 'era_decided', 'script_finished', 'server_exited', 'server_name_mismatch', 'paced', 'run_stopped', 'recording_stopped', 'limit_exceeded', 'run_finished'].concat(finishedKeys), 'Other fields of this part, as given');
    if (extra) out.appendChild(extra);
    return out;
  }

  const EXIT_TABLE = [
    ['complete', '0', 'a result'],
    ['refused', '2', 'nothing started'],
    ['incomplete', '3', 'data is missing'],
    ['server_failed', '4', 'nothing observed'],
    ['sandbox_failed', '5', 'isolation, or the observation, did not hold'],
    ['call_failed', '6', 'a called tool failed: not a result about the content'],
    ['rule wedged', '70', 'a rule wedged the tool'],
    ['output lost', '74', 'the result could not be written to stdout'],
    ['interrupted', '130', 'Ctrl-C with nothing to record it'],
  ];

  function tabVerdict(env, v) {
    if (!isObj(v)) return noneRecorded(env, 'verdict');
    const out = h('div', { class: 'stack' });
    const cls = stateClass(v.state);
    out.appendChild(h('div', { class: 'cols-main' },
      panel('Causes — each key beside its words', 'Verdict.shortfalls, in the verdict\'s order', causeList(v.causes)),
      h('section', { class: 'panel' }, h('div', { class: 'panel-body' },
        h('div', { class: 'eyebrow' }, 'State'),
        h('div', { class: 'statebig' }, h('span', { class: 'chip lg ' + cls }, String(v.state)), h('span', { class: 'exit' }, 'exit ', v.exit_code === null || v.exit_code === undefined ? '—' : String(v.exit_code))),
        kv([['rules', scalar(v.rules)], ['server_exit', v.server_exit === undefined ? undefined : val(v.server_exit)], ['announced_server', v.announced_server === undefined ? undefined : scalar(v.announced_server)]])))));
    out.appendChild(panel('Truncations — recorded caps', 'a recorded cap is complete data, cut where and why it says',
      isEmpty(v.truncations) ? noneRecorded(env, 'verdict') : val(v.truncations)));
    out.appendChild(panel('Statements the scenario asked', 'statement · signal',
      isEmpty(v.statements) ? noneRecorded(env, 'verdict') : val(v.statements)));
    out.appendChild(panel('States and exit codes', 'the exit codes of this version, as the README lists them',
      table([{ label: 'State' }, { label: 'Exit', num: true }, { label: 'Meaning' }], EXIT_TABLE.map(([s, c, m]) => [mono(s), mono(c), m]))));
    const extra = others(v, ['state', 'exit_code', 'rules', 'causes', 'server_exit', 'truncations', 'announced_server', 'statements']);
    if (extra) out.appendChild(extra);
    return out;
  }

  const PAGE = 100;

  async function tabMessages(runEnv, ref, p) {
    const offset = Math.max(0, parseInt(p.get('offset') || '0', 10) || 0);
    const seqParam = p.get('seq');
    const [env, detail] = await Promise.all([
      api('run/messages', { ref, offset, limit: PAGE }),
      seqParam !== null ? api('run/message', { ref, seq: seqParam }) : Promise.resolve(null),
    ]);
    const out = h('div', { class: 'stack' });
    const skip = new Set(runEnv.notices.map(noticeKey));
    const acc = isObj(runEnv.data) && isObj(runEnv.data.messages) ? runEnv.data.messages : null;
    if (acc) {
      const seqs = (l) => isEmpty(l) ? h('span', { class: 'muted' }, 'none recorded') : h('span', { class: 'chips' }, asList(l).map((s) => seqLink(ref, s)));
      out.appendChild(h('div', { class: 'factbox' }, kv([['messages recorded', acc.total === 0 ? h('span', { class: 'none' + (viewNar(runEnv) ? ' nar' : '') }, countWords(runEnv, 0)) : scalar(acc.total)], ['truncated', acc.truncated === undefined ? undefined : seqs(acc.truncated)], ['incomplete', acc.incomplete === undefined ? undefined : seqs(acc.incomplete)]]), others(acc, ['total', 'truncated', 'incomplete'])));
    }
    add(out, [noticesTop(env, { skip })]);
    const d = isObj(env.data) ? env.data : null;
    const listPart = h('div', { class: 'stack' });
    if (d) {
      const total = typeof d.total === 'number' ? d.total : null;
      const off = typeof d.offset === 'number' ? d.offset : offset;
      const items = asList(d.items);
      const pages = total === null ? null : Math.max(1, Math.ceil(total / PAGE));
      const pageNo = Math.floor(off / PAGE) + 1;
      const pager = h('nav', { class: 'pager', 'aria-label': 'Message pages' },
        h('span', null, total === null ? 'page ' + pageNo + ' (the total was not given)' : total === 0 ? countWords(env, 0) : 'page ' + pageNo + ' of ' + pages + ' · messages ' + (items.length ? off + 1 : 0) + '–' + (off + items.length) + ' of ' + total),
        off > 0 ? link('run', { ref, tab: 'messages', offset: 0 }, 'First') : null,
        off > 0 ? link('run', { ref, tab: 'messages', offset: Math.max(0, off - PAGE) }, 'Previous') : null,
        total !== null && off + PAGE < total ? link('run', { ref, tab: 'messages', offset: off + PAGE }, 'Next') : null,
        total !== null && off + PAGE < total ? link('run', { ref, tab: 'messages', offset: (pages - 1) * PAGE }, 'Last') : null);
      const rows = items.map((m) => {
        const marks = [];
        if (m.truncated) marks.push(tag('t-cap', 'truncated'));
        if (m.incomplete) marks.push(tag('t-cap', 'incomplete'));
        if (m.is_error) marks.push(tag('t-bad', 'error'));
        if (typeof m.redaction_count === 'number' && m.redaction_count > 0) marks.push(tag('t-plain', plural(m.redaction_count, 'value') + ' masked'));
        if (m.exchange !== null && m.exchange !== undefined) marks.push(tag('t-plain', 'exchange ', String(m.exchange)));
        if (m.intervened) marks.push(tag('t-info', 'intervention', typeof m.intervened === 'string' ? ' · ' + m.intervened : ''));
        if (m.responded_method) marks.push(tag('t-plain', 'answers ', String(m.responded_method)));
        if (m.quarantined) marks.push(tag('t-bad', 'rule_quarantined'));
        return {
          cls: String(m.seq) === seqParam ? 'selected' : null,
          cells: [link('run', { ref, tab: 'messages', offset: off, seq: m.seq }, mono('#' + m.seq)), dirShort(m.direction), cellText(m.kind), cellText(m.method), cellText(m.id), cellText(m.size_bytes), h('span', { class: 'chips' }, marks)],
        };
      });
      listPart.appendChild(panel('Messages, both directions', '→ client to server · ← server to client', pager,
        rows.length ? table([{ label: '#' }, { label: 'Dir' }, { label: 'Kind' }, { label: 'Method' }, { label: 'Id' }, { label: 'Bytes', num: true }, { label: 'Marks' }], rows, { cls: 'msglist' }) : noneRecorded(env, 'view')));
    }
    if (detail) {
      // The detail first, at full width: a payload is wide, and the list stays below it.
      out.appendChild(messageDetail(detail, ref));
      out.appendChild(listPart);
    } else {
      out.appendChild(listPart);
    }
    return out;
  }

  function messageDetail(env, ref) {
    const pane = h('aside', { class: 'detailpane', 'aria-label': 'Message detail' });
    const d = isObj(env.data) ? env.data : null;
    const m = d ? (isObj(d.message) ? d.message : d) : null;
    pane.appendChild(h('h2', null, m ? ['#', String(m.seq), ' · ', m.direction === 'client_to_server' ? '→ ' : m.direction === 'server_to_client' ? '← ' : '', isObj(m.parse) ? [String(m.parse.kind), m.parse.method ? ' ' + m.parse.method : ''] : 'message'] : 'Message'));
    add(pane, [noticesTop(env)]);
    if (!m) return pane;
    const payload = isObj(m.payload) ? m.payload : null;
    pane.appendChild(kv([
      ['direction', mono(m.direction)], ['transport', m.transport === undefined ? undefined : mono(m.transport)],
      ['size_bytes', scalar(m.size_bytes)], ['truncated', scalar(m.truncated)], ['incomplete', scalar(m.incomplete)],
      ['responded_method', m.responded_method === undefined ? undefined : scalar(m.responded_method)],
      ['exchange', m.exchange === undefined ? undefined : scalar(m.exchange)],
      ['stream', m.stream === undefined ? undefined : scalar(m.stream)],
      ['event_id', m.event_id === undefined ? undefined : scalar(m.event_id)],
      ['parse', m.parse === undefined ? undefined : val(m.parse)],
    ]));
    if (payload) {
      pane.appendChild(h('h3', null, 'Payload, masked as recorded · ', String(payload.encoding)));
      pane.appendChild(payloadBlock(payload));
      pane.appendChild(kv([['redaction_count', scalar(payload.redaction_count)], ['redactions', isEmpty(payload.redactions) ? h('span', { class: 'muted' }, 'none recorded') : h('ul', { class: 'list' }, asList(payload.redactions).map((r) => h('li', null, mono(r))))]]));
    }
    const ivs = pick(d, 'interventions', 'intervention');
    const obs = pick(d, 'observations', 'observation');
    const fnd = pick(d, 'findings', 'finding');
    pane.appendChild(h('h3', null, 'Interventions naming this message'));
    pane.appendChild(isEmpty(ivs) ? noneRecorded(env, 'view') : h('div', { class: 'stack' }, asList(ivs).map((iv) => interventionCard(iv, ref, true))));
    pane.appendChild(h('h3', null, 'Findings naming this message'));
    pane.appendChild(isEmpty(fnd) ? noneRecorded(env, 'view') : findingsTable(asList(fnd), ref));
    pane.appendChild(h('h3', null, 'Observations naming this message'));
    pane.appendChild(isEmpty(obs) ? noneRecorded(env, 'view') : observationsTable(asList(obs), ref));
    const extra = others(m, ['seq', 'direction', 'transport', 'size_bytes', 'truncated', 'incomplete', 'responded_method', 'exchange', 'stream', 'event_id', 'parse', 'payload'], 'Other fields of the event, as recorded');
    if (extra) pane.appendChild(extra);
    if (d && d !== m) {
      const extra2 = others(d, ['message', 'interventions', 'intervention', 'observations', 'observation', 'findings', 'finding']);
      if (extra2) pane.appendChild(extra2);
    }
    return pane;
  }

  function payloadBlock(payload) {
    let data = payload.data;
    if (payload.encoding === 'json' && typeof data === 'string') {
      try { data = JSON.parse(data); } catch (e) { return textBlock(data); }
    }
    if (typeof data === 'string') return textBlock(data);
    return jsonBlock(data);
  }

  function keyDetails(key, title) {
    if (!isObj(key)) return cellText(key);
    return h('details', null, h('summary', null, title || 'key'), kv(Object.entries(key).map(([k, x]) => [k, mono(x === null ? 'null' : jsonText(x))])));
  }

  function normMark(n) { return n === true ? tag('t-info', 'normalized') : n === false ? h('span', { class: 'sub' }, 'raw') : cellText(n); }

  function findingsTable(list, ref) {
    return table([{ label: 'Signal' }, { label: 'Class' }, { label: 'Statement' }, { label: 'Locator' }, { label: 'Path' }, { label: 'Message' }, { label: 'Read' }, { label: 'Key' }],
      list.map((f) => {
        const k = isObj(f.key) ? f.key : {};
        return [mono(k.signal), isObj(f.finding_class) ? frag(mono(f.finding_class.id), ' ', String(f.finding_class.title)) : dash(), mono(k.statement), mono(k.locator), mono(f.path), frag(seqLink(ref, f.message_seq), f.method ? [' ', sub(mono(f.method))] : null), normMark(f.normalized), keyDetails(f.key)];
      }));
  }

  function observationsTable(list, ref) {
    return table([{ label: 'Signal' }, { label: 'Surface' }, { label: 'Path' }, { label: 'Message' }, { label: 'Read' }],
      list.map((o) => [mono(o.signal), mono(o.surface), mono(o.path), frag(seqLink(ref, o.message_seq), o.method ? [' ', sub(mono(o.method))] : null), normMark(o.normalized)]));
  }

  function countMap(m) {
    if (!isObj(m)) return cellText(m);
    const keys = Object.keys(m);
    if (!keys.length) return h('span', { class: 'muted' }, 'none');
    return h('span', { class: 'chips' }, keys.map((k) => tag('t-plain', k, ' ×', isObj(m[k]) ? jsonText(m[k]) : String(m[k]))));
  }

  // Every event of the findings tab, as tables.
  function findingsPanels(env, f, ref) {
    const out = h('div', { class: 'stack' });
    const findings = asList(f.findings);
    const capped = has(env, 'capped', 'tab:findings');
    out.appendChild(panel('Findings', findings.length ? plural(findings.length, 'finding event') + ' recorded' + (capped ? ' · capped, see the notice' : '') + (viewNar(env) ? ' · the run is not a result' : '') : null,
      findings.length ? findingsTable(findings, ref) : noneRecorded(env, 'tab:findings')));
    const obs = asList(f.observations);
    out.appendChild(panel('Observations', obs.length ? obs.length + ' recorded · the built-in walk' + (viewNar(env) ? ' · the run is not a result' : '') : 'the built-in walk',
      obs.length ? observationsTable(obs, ref) : noneRecorded(env, 'tab:findings')));
    const se = asList(f.statements_evaluated);
    out.appendChild(panel('Statements evaluated', 'statement_evaluated',
      se.length ? table([{ label: 'Statement' }, { label: 'Message' }, { label: 'Checked', num: true }, { label: 'Not strings', num: true }, { label: 'Fired' }, { label: 'Reason' }],
        se.map((s) => [mono(s.statement), frag(seqLink(ref, s.message_seq), s.method ? [' ', sub(mono(s.method))] : null), cellText(s.checked), cellText(s.not_strings), countMap(s.fired), cellText(s.reason)])) : noneRecorded(env, 'tab:findings')));
    const fc = asList(f.findings_capped);
    out.appendChild(panel('findings_capped', 'what the per-message cap cut, with the true numbers',
      fc.length ? table([{ label: 'Message' }, { label: 'Cap', num: true }, { label: 'Made', num: true }, { label: 'Recorded', num: true }, { label: 'Cut' }],
        fc.map((c) => [frag(seqLink(ref, c.message_seq), c.method ? [' ', sub(mono(c.method))] : null), cellText(c.cap), cellText(c.made), cellText(c.recorded), isObj(c.cut) ? val(c.cut) : cellText(c.cut)])) : noneRecorded(env, 'tab:findings')));
    out.appendChild(h('div', { class: 'cols' },
      panel('findings_by_statement', 'from run_finished', isEmpty(f.findings_by_statement) ? noneRecorded(env, 'tab:findings') : val(f.findings_by_statement)),
      panel('observations_by_method', 'from run_finished', isEmpty(f.observations_by_method) ? noneRecorded(env, 'tab:findings') : val(f.observations_by_method))));
    const extra = others(f, ['findings', 'observations', 'statements_evaluated', 'findings_capped', 'findings_by_statement', 'observations_by_method']);
    if (extra) out.appendChild(extra);
    return out;
  }

  // ---- the strip: statements against messages (findings tab) --------------------------------

  // How many messages get a column in the strip, and how many findings and messages the pane lists.
  const STRIP_COLUMNS = 12;
  const PANE_FINDINGS = 20;
  const PANE_MESSAGES = 20;
  // How many observations without a finding beside them get a row of the strip, and how many
  // places of the walk one finding of the pane lists.
  const STRIP_WALK_ROWS = 50;
  const PANE_SURFACES = 5;
  // Whether the tables under the strip are drawn open: render() says so where the reader had
  // them open and the address changed in the selected row alone.
  let tablesOpen = false;

  // What an observation of the built-in walk and a finding are paired by: the same message, the
  // same path and the same signal. null for an event that does not name all three as it should.
  function walkKey(seq, path, signal) {
    return typeof seq === 'number' && typeof path === 'string' && typeof signal === 'string' ? jsonOf([seq, path, signal], null) : null;
  }

  // The observations by their key, read once: a run can hold thousands.
  function walkIndex(observations) {
    const index = new Map();
    for (const o of observations) {
      const key = walkKey(o.message_seq, o.path, o.signal);
      if (key === null) continue;
      if (!index.has(key)) index.set(key, []);
      index.get(key).push(o);
    }
    return index;
  }

  function walkPairs(finding, index) {
    const key = walkKey(finding.message_seq, finding.path, isObj(finding.key) ? finding.key.signal : undefined);
    return (key !== null && index.get(key)) || [];
  }

  // No observation recorded is not "the walk looked and saw nothing": the walk does not look for
  // every signal, keeps a limited number per message and can be stopped. So the words say what
  // is recorded and nothing about why.
  function walkWords(seen, of) {
    if (of === 0) return '';
    if (seen === of) return 'observed too';
    if (seen === 0) return 'no observation recorded';
    return seen + ' of ' + of + ' observed';
  }

  // What the statement_evaluated events of one statement on one message count as fired, and
  // whether one of them holds something else than counts where the counts should be.
  function firedCount(events) {
    let count = 0;
    let odd = false;
    for (const e of events) {
      if (!isObj(e.fired)) { odd = true; continue; }
      for (const n of Object.values(e.fired)) {
        if (Number.isSafeInteger(n) && n >= 0) count += n; else odd = true;
      }
    }
    return { count, odd };
  }

  // The rows of the strip: one per statement evaluated, in the order of its first event, then one
  // per statement that only a finding names (a recording cut short). A statement is told apart by
  // its value, never by how it is written on the page.
  function stripRows(evaluated, findings) {
    const rows = [];
    const byId = new Map();
    const rowOf = (statement) => {
      const id = typeof statement === 'string' ? 's' + statement : 'j' + jsonText(statement);
      if (!byId.has(id)) {
        const row = { statement, events: [], findings: [] };
        byId.set(id, row);
        rows.push(row);
      }
      return byId.get(id);
    };
    for (const e of evaluated) rowOf(e.statement).events.push(e);
    for (const x of findings) rowOf(isObj(x.key) ? x.key.statement : undefined).findings.push(x);
    for (const row of rows) row.fired = row.findings.length > 0 || firedCount(row.events).count > 0;
    return rows;
  }

  // Which messages get a column: all of them where the run has at most STRIP_COLUMNS and their
  // list can be read whole, else those an event of the tab names, the first STRIP_COLUMNS in
  // order. `marks` holds the seqs the run view lists as truncated and as incomplete.
  async function stripColumns(ref, messages, events) {
    const total = isObj(messages) && typeof messages.total === 'number' ? messages.total : null;
    const cut = new Set(isObj(messages) ? asList(messages.truncated) : []);
    const unfinished = new Set(isObj(messages) ? asList(messages.incomplete) : []);
    const named = [];
    const bySeq = new Map();
    let unplaced = 0;
    for (const e of events) {
      const seq = e.message_seq;
      if (typeof seq !== 'number') { unplaced += 1; continue; }
      if (!bySeq.has(seq)) {
        bySeq.set(seq, { seq, direction: null, method: null, answers: null });
        named.push(bySeq.get(seq));
      }
      const column = bySeq.get(seq);
      if (column.direction === null && e.direction !== undefined) column.direction = e.direction;
      if (column.method === null && e.method !== undefined) column.method = e.method;
    }
    // An event on a server's message names the method that message answers, not one it asks.
    for (const c of named) {
      if (c.direction === 'server_to_client' && c.method !== null) { c.answers = c.method; c.method = null; }
    }
    named.sort((a, b) => a.seq - b.seq);
    const marked = (columns) => columns.map((c) => merged(c, { truncated: cut.has(c.seq), incomplete: unfinished.has(c.seq) }));
    const tail = unplaced === 0 ? '' : unplaced === 1 ? ' · 1 event names no message by number and has no cell'
      : ' · ' + unplaced + ' events name no message by number and have no cell';
    if (total !== null && total <= STRIP_COLUMNS) {
      const env = await api('run/messages', { ref, offset: 0, limit: STRIP_COLUMNS });
      const items = isObj(env.data) ? asList(env.data.items).filter((m) => isObj(m) && typeof m.seq === 'number') : [];
      const listed = new Set(items.map((m) => m.seq));
      if (items.length === total && listed.size === total && named.every((c) => listed.has(c.seq))) {
        return {
          columns: marked(items.map((m) => ({ seq: m.seq, direction: m.direction === undefined ? null : m.direction, method: m.method === undefined ? null : m.method, answers: m.responded_method === undefined ? null : m.responded_method }))),
          words: 'all ' + plural(items.length, 'message') + ' shown' + tail,
        };
      }
    }
    const columns = named.slice(0, STRIP_COLUMNS);
    let words = total !== null && columns.length <= total ? columns.length + ' of ' + total + ' messages shown' : plural(columns.length, 'message') + ' shown';
    words += ': those an event of this tab names';
    if (named.length > columns.length) words += ' · first ' + columns.length + ' of ' + named.length + ' read messages shown, capped';
    return { columns: marked(columns), words: words + tail };
  }

  // One reading of one statement on one message: the line, and its words for a reader who does
  // not see the line. No record is no more than that: the statement did not apply to the
  // message, or the message was not inspected (a truncated or unfinished one never is), or the
  // record was not written. It is never "nothing found".
  function traceCell(events, findings) {
    const fired = firedCount(events);
    const count = fired.count || findings;
    let kind = 'none';
    let words = 'no record';
    if (count > 0) { kind = 'fired'; words = 'fired'; }
    else if (fired.odd) { kind = 'stopped'; words = 'evaluated; what fired is not recorded as counts'; }
    else if (events.some((e) => e.reason !== null && e.reason !== undefined)) { kind = 'stopped'; words = 'evaluated, with a reason'; }
    else if (events.length) { kind = 'quiet'; words = 'read, nothing fired'; }
    return h('td', { class: 'msg' }, h('span', { class: 'trace ' + kind }, h('span', { class: 'vh' }, words), count > 0 ? h('span', { class: 'n' }, '×' + count) : null));
  }

  // What the run view says of a message that was never inspected: truncated, incomplete or both.
  function cutWords(c) {
    return [c.truncated ? 'truncated' : null, c.incomplete ? 'incomplete' : null].filter(Boolean).join(' and ');
  }

  // `capped` holds the messages a findings_capped event names.
  function stripTable(ref, rows, columns, walkOnly, index, picked, capped) {
    const WAY = { client_to_server: ['→', 'client to server'], server_to_client: ['←', 'server to client'] };
    const head = h('tr', null, h('th', { scope: 'col', class: 'st' }, 'Statement, in the order evaluated'),
      columns.map((c) => {
        const method = c.method !== null ? asText(c.method) : c.answers !== null ? 'answers ' + asText(c.answers) : null;
        // The arrow is for the eye; its words stand with the method for a reader who hears the header.
        const way = typeof c.direction === 'string' ? own(WAY, c.direction) : null;
        const said = [way ? way[1] : null, method].filter((t) => t !== null).join(', ');
        return h('th', { scope: 'col', class: 'msg' }, seqLink(ref, c.seq),
          c.direction === null ? null : [' ', way ? h('span', { 'aria-hidden': 'true' }, way[0]) : cellText(c.direction)],
          said === '' ? null : h('span', { class: 'vh' }, ' ', said),
          c.truncated || c.incomplete ? [' ', h('span', { class: 'tag t-cap' }, '*', h('span', { class: 'vh' }, ' ', cutWords(c)))] : null);
      }),
      h('th', { scope: 'col', class: 'cls' }, 'Class'), h('th', { scope: 'col', class: 'walk' }, 'Built-in walk'));
    const body = h('tbody');
    for (const row of rows) {
      let name;
      if (typeof row.statement === 'string' && row.statement !== '') {
        name = h('a', { class: 'pick', href: href('run', { ref, tab: 'findings', st: row.statement }), 'aria-current': picked === row ? 'true' : null, 'aria-controls': 'strip-pane' }, row.statement);
      } else {
        name = typeof row.statement === 'string' ? mono(jsonString(row.statement)) : cellText(row.statement);
      }
      // Each class once, compared by what the cell shows: the class is only ever text (CONTRACT.md).
      const classes = [];
      for (const x of row.findings) {
        const shown = isObj(x.finding_class) ? frag(mono(x.finding_class.id)) : frag(dash());
        if (!classes.some((c) => c.textContent === shown.textContent)) classes.push(shown);
      }
      const seen = row.findings.filter((x) => walkPairs(x, index).length > 0).length;
      body.appendChild(h('tr', { class: row.fired ? 'fired' : null }, h('th', { scope: 'row', class: 'st' }, name),
        columns.map((c) => traceCell(row.events.filter((e) => e.message_seq === c.seq), row.findings.filter((x) => x.message_seq === c.seq).length)),
        h('td', { class: 'cls' }, classes.map((c, i) => (i ? [', ', c] : c))), h('td', { class: 'walk' }, walkWords(seen, row.findings.length))));
    }
    // An observation without a finding beside it is a row of its own kind. It is not "no statement
    // saw this": a finding can be cut by the cap of its message, or its record not written.
    const alone = walkOnly.length ? h('tbody') : null;
    for (const o of walkOnly) {
      const signal = asText(o.signal);
      const label = [tag('t-obs', 'walk, no finding'), capped.has(o.message_seq) ? [' ', tag('t-cap', 'findings capped here')] : null,
        ' ', h('span', { class: 'wire' }, signal === null ? '—' : signal), ' ', sub('on ', h('span', { class: 'mono' }, '#' + o.message_seq), ' ', mono(o.path))];
      const name = typeof o.seq === 'number'
        ? h('a', { class: 'pick', href: href('run', { ref, tab: 'findings', obs: o.seq }), 'aria-current': picked === o ? 'true' : null, 'aria-controls': 'strip-pane' }, h('span', null, label))
        : h('span', { class: 'mono' }, label);
      alone.appendChild(h('tr', { class: 'walked' }, h('th', { scope: 'row', class: 'st' }, name),
        columns.map((c) => h('td', { class: 'msg' }, c.seq === o.message_seq ? h('span', { class: 'trace seen' }, h('span', { class: 'vh' }, 'observed by the built-in walk')) : null)),
        h('td', { class: 'cls' }), h('td', { class: 'walk' })));
    }
    // The table's least width goes by its count of message columns (m3 to m12 of the stylesheet).
    const wide = columns.length >= 3 ? ' m' + Math.min(columns.length, STRIP_COLUMNS) : '';
    return h('div', { class: 'tablewrap' }, h('table', { class: 'strip' + wide }, h('thead', null, head), body, alone));
  }

  const TRACE_LEGEND = [
    ['none', 'no record: the statement did not apply to the message, the message was not inspected, or the record was not written'],
    ['quiet', 'read, nothing fired'], ['stopped', 'evaluated, with a reason, or what fired is not recorded as counts'], ['fired', 'fired, with the count'],
  ];
  const TRACE_SEEN = ['seen', 'observed by the built-in walk; no finding of the same message, path and signal is recorded'];

  // The detail of what is selected in the strip. `picked` is a row of the strip or a walk-only
  // observation; `missing` says what the address names that this run does not hold.
  function sidePane(ref, picked, missing, f, index) {
    const pane = h('aside', { class: 'sidepane', id: 'strip-pane', 'aria-label': 'Detail of the selected row' });
    if (missing) return add(pane, [h('p', { class: 'inplace' }, missing)]);
    if (!picked) return add(pane, [h('p', { class: 'muted' }, 'Select a statement to see what it read.')]);
    const onMessage = (e) => frag(seqLink(ref, e.message_seq), e.method ? [' ', sub(mono(e.method))] : null);
    const capped = asList(f.findings_capped).filter(isObj);
    if (!Array.isArray(picked.events)) {
      const signal = asText(picked.signal);
      return add(pane, [
        h('div', null, h('div', { class: 'eyebrow' }, 'Observed by the built-in walk, no finding recorded'), h('h2', null, h('span', { class: 'wire' }, signal === null ? '—' : signal))),
        kv([['surface', mono(picked.surface)], ['path', mono(picked.path)], ['message', onMessage(picked)], ['read', normMark(picked.normalized)]]),
        h('p', { class: 'sub' }, 'No finding of the same message, path and signal is recorded. That does not say no statement fired there: a finding can be cut by the cap of its message, and a record can be dropped.'),
        capped.some((c) => c.message_seq === picked.message_seq) ? h('p', { class: 'inplace' }, 'Findings were capped on this message; see the capped notice.') : null,
      ]);
    }
    const named = typeof picked.statement === 'string';
    pane.appendChild(h('div', null, h('div', { class: 'eyebrow' }, 'Selected statement'),
      h('h2', null, named ? h('span', { class: 'wire' }, picked.statement === '' ? jsonString('') : picked.statement) : cellText(picked.statement))));
    const tally = isObj(f.findings_by_statement) && named
      ? [['count for this statement', Object.hasOwn(f.findings_by_statement, picked.statement) ? countMap(f.findings_by_statement[picked.statement]) : dash()]] : [];
    // The messages it fired on or gave a reason for come first: the pane holds a limited number.
    const groups = new Map();
    for (const e of picked.events) {
      if (!groups.has(e.message_seq)) groups.set(e.message_seq, []);
      groups.get(e.message_seq).push(e);
    }
    const said = (events) => firedCount(events).count > 0 || firedCount(events).odd || events.some((e) => e.reason !== null && e.reason !== undefined);
    const all = [...groups.entries()];
    const order = [...all.filter(([, events]) => said(events)), ...all.filter(([, events]) => !said(events))];
    const shown = order.slice(0, PANE_MESSAGES);
    shown.forEach(([seq, events]) => {
      const block = h('div', null, h('h3', null, 'On message ', onMessage(events[0])));
      events.forEach((e) => block.appendChild(kv([
        ['checked', cellText(e.checked)], ['not strings', cellText(e.not_strings)], ['fired', countMap(e.fired)], ['reason', cellText(e.reason)],
      ])));
      const counted = firedCount(events);
      const made = counted.count;
      const held = picked.findings.filter((x) => x.message_seq === seq).length;
      if (counted.odd) {
        block.appendChild(h('p', { class: 'inplace' }, 'What fired is not recorded as counts here; ' + plural(held, 'finding') + ' recorded for this statement on this message.'));
      } else if (held < made) {
        const cappedHere = capped.some((c) => c.message_seq === seq);
        block.appendChild(h('p', { class: 'inplace' }, held + ' of ' + made + ' findings recorded for this statement on this message' + (cappedHere ? '; see the capped notice.' : '.')));
      } else if (held > made) {
        block.appendChild(h('p', { class: 'inplace' }, plural(held, 'finding') + ' recorded for this statement on this message, ' + made + ' counted in statement_evaluated.'));
      }
      pane.appendChild(block);
    });
    if (order.length > shown.length) {
      pane.appendChild(h('p', { class: 'inplace' }, shown.length + ' of ' + order.length + ' messages shown, capped: those it fired on or gave a reason for first. All are in the tables below.'));
    }
    // The count of the whole run is no message's: a block of its own.
    if (tally.length) pane.appendChild(h('div', null, h('h3', null, 'In run_finished'), kv(tally)));
    const list = picked.findings;
    list.slice(0, PANE_FINDINGS).forEach((x, i) => {
      const k = isObj(x.key) ? x.key : {};
      // Each place once, the first PANE_SURFACES of them; the recorded values stand apart from
      // the page's own words.
      const surfaces = new Set();
      for (const o of walkPairs(x, index)) {
        const s = asText(o.surface);
        surfaces.add(s === null ? '—' : s);
        if (surfaces.size > PANE_SURFACES) break;
      }
      const places = [...surfaces].slice(0, PANE_SURFACES);
      const fc = isObj(x.finding_class) ? x.finding_class : null;
      pane.appendChild(h('div', null, h('h3', null, 'Finding ' + (i + 1) + ' of ' + list.length),
        kv([
          ['signal', mono(k.signal)], ['class', fc ? frag(mono(fc.id), ' ', String(fc.title)) : dash()],
          ['locator', mono(k.locator)], ['path', mono(x.path)], ['message', onMessage(x)], ['read', normMark(x.normalized)],
          ['built-in walk', places.length ? frag('observed too, on ', places.map((t, n) => [n ? ', ' : null, mono(t)]), surfaces.size > PANE_SURFACES ? ', and more' : null)
            : 'no observation recorded for this message, path and signal'],
        ]),
        fc ? h('p', { class: 'sub' }, String(fc.description)) : null,
        keyDetails(x.key, 'Key in the store')));
    });
    if (list.length > PANE_FINDINGS) {
      pane.appendChild(h('p', { class: 'inplace' }, PANE_FINDINGS + ' of ' + list.length + ' findings shown, capped. All are in the tables below.'));
    }
    return pane;
  }

  // The findings tab. Where the run evaluated a statement, statements against messages as a
  // table of traces with the detail of one beside it, and under both every event of the tab as
  // the tables, behind a toggle; where it evaluated none, the tables alone.
  async function tabFindings(env, f, ref, p, messages) {
    if (!isObj(f)) return noneRecorded(env, 'tab:findings');
    const tables = findingsPanels(env, f, ref);
    const evaluated = asList(f.statements_evaluated).filter(isObj);
    if (!evaluated.length) return tables;
    const findings = asList(f.findings).filter(isObj);
    const observations = asList(f.observations).filter(isObj);
    const rows = stripRows(evaluated, findings);
    const index = walkIndex(observations);
    const paired = new Set(findings.map((x) => walkKey(x.message_seq, x.path, isObj(x.key) ? x.key.signal : undefined)));
    const walkOnly = observations.filter((o) => !paired.has(walkKey(o.message_seq, o.path, o.signal)) || walkKey(o.message_seq, o.path, o.signal) === null);
    const { columns, words } = await stripColumns(ref, messages, [...evaluated, ...findings, ...observations]);
    // A row of the walk is drawn only where its message has a column, so that it never stands
    // empty, and only so many: all of them are in the tables below.
    const shownSeqs = new Set(columns.map((c) => c.seq));
    const walkRows = walkOnly.filter((o) => shownSeqs.has(o.message_seq)).slice(0, STRIP_WALK_ROWS);
    const st = p.get('st');
    const obs = p.get('obs');
    let picked = null;
    let missing = null;
    if (st !== null) {
      picked = rows.find((r) => r.statement === st) || null;
      if (!picked) missing = 'This run evaluated no statement of that name.';
    } else if (obs !== null) {
      picked = walkOnly.find((o) => typeof o.seq === 'number' && String(o.seq) === obs) || null;
      if (!picked) missing = 'This run holds no observation of that number without a finding beside it.';
    } else {
      picked = rows.find((r) => r.fired) || null;
    }
    const fired = rows.filter((r) => r.fired).length;
    const nar = viewNar(env);
    const note = [plural(rows.length, 'statement'),
      fired === 0 && nar ? 'none recorded as fired — the run is not a result' : fired + ' fired' + (nar ? ' — the run is not a result' : ''),
      walkOnly.length ? walkOnly.length + ' of the walk without a finding' : null, words,
      has(env, 'capped', 'tab:findings') ? 'capped, see the notice' : null].filter(Boolean).join(' · ');
    const legend = walkRows.length ? [...TRACE_LEGEND, TRACE_SEEN] : TRACE_LEGEND;
    const walkCut = walkRows.length < walkOnly.length
      ? h('p', { class: 'inplace' }, walkRows.length + ' of ' + walkOnly.length + ' observations without a finding have a row here: those on a message with a column, '
        + STRIP_WALK_ROWS + ' at most. All are in the tables below.') : null;
    // A column's mark has no room for its word: the words stand under the table, by number.
    const cut = columns.filter((c) => c.truncated || c.incomplete);
    const marks = cut.length ? h('p', { class: 'strip-marks' }, h('span', { class: 'tag t-cap' }, '*'), ' ',
      cut.map((c, i) => [i ? ' · ' : null, h('span', { class: 'mono' }, '#' + c.seq), ' ', cutWords(c)]),
      '. A truncated or incomplete message is not inspected.') : null;
    const capped = new Set(asList(f.findings_capped).filter(isObj).map((c) => c.message_seq));
    const strip = panel('Statements against messages', note, stripTable(ref, rows, columns, walkRows, index, picked, capped), marks, walkCut,
      h('div', { class: 'legend' }, legend.map(([kind, said]) => h('span', { class: 'item' }, h('span', { class: 'trace ' + kind }), said))),
      h('p', { class: 'legend-note' }, 'Built-in walk: whether an observation of the same message, path and signal is recorded beside a finding. None recorded does not say the walk looked there and saw nothing: it does not look at every place a statement can point at or for every signal, keeps a limited number of observations per message, can be stopped, and a record can be dropped.'));
    strip.querySelector('.panel-body').classList.add('flush');
    return frag(
      h('div', { class: columns.length > 5 ? 'split wide' : 'split' }, h('div', { class: 'split-main' }, strip), sidePane(ref, picked, missing, f, index)),
      h('details', { class: 'tables', open: tablesOpen ? true : null }, h('summary', null, 'The same events as tables: findings, observations, statement_evaluated, findings_capped, run_finished'), tables));
  }

  const LISTING_LABEL = { tools: 'Tools', resources: 'Resources', resourceTemplates: 'Templates', prompts: 'Prompts' };
  const LISTING_METHOD = { tools: 'tools/list', resources: 'resources/list', resourceTemplates: 'resources/templates/list', prompts: 'prompts/list' };

  function stepView(s, i, causes) {
    const type = s.type || (s.direction ? 'message' : null);
    let cls = 'step', title = s.step || s.method || (isObj(s.parse) ? s.parse.method : null), status;
    switch (type) {
      case 'message':
        cls += ' ok'; title = s.method || (isObj(s.parse) ? s.parse.method : null) || s.step;
        status = ['sent', s.seq !== undefined ? ' · #' + s.seq : '']; break;
      case 'step_skipped':
        cls += ' skip'; status = ['skipped · ', String(s.reason), s.detail ? ' · ' + s.detail : '']; break;
      case 'step_unanswered':
        cls += ' bad'; status = ['unanswered · ', String(s.reason), s.pages !== undefined ? ' · pages ' + s.pages : ''];
        // A detail (the TLS library's text under tls) is shown whole, as text, not on the status line.
        if (s.detail !== undefined && s.detail !== '') cls += ' wide';
        break;
      case 'step_reissued':
        cls += ' skip'; status = ['asked again · ', String(s.reason), s.page !== undefined ? ' · page ' + s.page : '']; break;
      case 'step_called':
        cls += ' ok'; status = ['called ', String(s.tool), s.check !== undefined ? ' · check ' + jsonText(s.check) : '', typeof s.redaction_count === 'number' && s.redaction_count ? ' · ' + s.redaction_count + ' masked' : '']; break;
      case 'call_failed':
        cls += ' bad'; status = ['call_failed · ', String(s.tool), ' · ', String(s.kind), s.code !== undefined && s.code !== null ? ' · code ' + s.code : '']; break;
      default:
        status = [type ? String(type) : 'step'];
    }
    const used = ['type', 'step', 'method', 'seq', 'reason', 'detail', 'pages', 'tool', 'check', 'kind', 'code', 'redaction_count', 'parse', 'direction', 'page'];
    return h('div', { class: cls }, h('span', { class: 'n' }, String(i + 1), type ? ' · ' + type : ''), h('span', { class: 'm wire' }, title === undefined || title === null ? '—' : String(title)), h('span', { class: 's wire' }, status),
      cls.includes(' wide') ? failureView(s, causes) : null,
      others(s, used, 'as recorded'));
  }

  function classText(fc, sep) {
    return isObj(fc) && fc.id ? sep + String(fc.id) + (fc.title ? ' ' + String(fc.title) : '') : '';
  }

  function itemChips(it) {
    const chips = [];
    for (const o of asList(pick(it, 'observations'))) {
      if (!isObj(o)) continue;
      chips.push(tag('t-obs', String(o.signal), o.normalized ? ' · normalized' : ''));
    }
    for (const f of asList(pick(it, 'findings'))) {
      if (!isObj(f)) continue;
      const k = isObj(f.key) ? f.key : {};
      chips.push(h('span', { class: 'tag t-find' }, 'finding · ', String(k.statement), ' · ', String(k.signal), classText(f.finding_class, ' · '), f.normalized ? ' · normalized' : ''));
    }
    return chips.length ? h('div', { class: 'chips' }, chips) : null;
  }

  function itemCard(name, it) {
    const obj = isObj(it) && isObj(it.item) ? it.item : isObj(it) && isObj(it.value) ? it.value : it;
    if (!isObj(obj)) return h('div', { class: 'card' }, val(obj), itemChips(it));
    const card = h('div', { class: 'card' });
    let title = obj.name, subline = null, fields = null;
    if (name === 'resources') { title = obj.uri !== undefined ? obj.uri : obj.name; subline = [obj.name !== undefined && obj.uri !== undefined ? obj.name : null, obj.mimeType ? ' · ' + obj.mimeType : null]; }
    if (name === 'resourceTemplates') { title = obj.uriTemplate !== undefined ? obj.uriTemplate : obj.name; subline = obj.name !== undefined ? obj.name : null; }
    if (name === 'tools') {
      subline = obj.title !== undefined ? obj.title : (isObj(obj.annotations) && obj.annotations.title !== undefined ? obj.annotations.title : null);
      const props = isObj(obj.inputSchema) && isObj(obj.inputSchema.properties) ? obj.inputSchema.properties : null;
      if (props) fields = ['(', Object.keys(props).map((k, i) => [i ? ', ' : '', k, isObj(props[k]) && props[k].type !== undefined ? ': ' + jsonText(props[k].type) : '']), ')'];
    }
    if (name === 'prompts' && Array.isArray(obj.arguments)) fields = ['(', obj.arguments.map((a, i) => [i ? ', ' : '', isObj(a) ? String(a.name) : jsonText(a)]), ')'];
    card.appendChild(h('div', { class: 'headrow' }, h('span', { class: 'name' }, title === undefined ? '(no name)' : jsonText(title)),
      subline !== null && subline !== undefined ? h('span', { class: 'title wire' }, subline) : null,
      fields ? h('span', { class: 'fields wire' }, fields) : null));
    if (obj.description !== undefined) card.appendChild(h('div', { class: 'desc wire' }, vis(jsonText(obj.description), true)));
    add(card, [itemChips(it)]);
    const fo = asList(pick(it, 'findings')).concat(asList(pick(it, 'observations')));
    if (fo.length) card.appendChild(h('details', null, h('summary', null, 'Where each fired (path; the characters are not recorded)'), table([{ label: 'Event' }, { label: 'Signal' }, { label: 'Path' }, { label: 'Message' }],
      fo.filter(isObj).map((e) => [e.key ? 'finding' : 'observation', mono(e.key ? e.key.signal : e.signal), mono(e.path), cellText(e.message_seq)]))));
    card.appendChild(h('details', null, h('summary', null, 'As recorded (masked)'), jsonBlock(obj)));
    return card;
  }

  function tabInventory(env, inv, ref, v) {
    if (!isObj(inv)) return noneRecorded(env, 'tab:inventory');
    const out = h('div', { class: 'stack' });
    const steps = asList(inv.steps).filter(isObj);
    const sf = inv.script_finished;
    out.appendChild(panel('The script, one turn at a time', 'requests sent, steps skipped, unanswered, called, failed',
      steps.length ? h('div', { class: 'steps' }, steps.map((s, i) => stepView(s, i, isObj(v) ? v.causes : null))) : noneRecorded(env, 'tab:inventory'),
      h('h3', null, 'script_finished'),
      sf === null || sf === undefined ? noneRecorded(env, 'tab:inventory') : kv([
        ['inventory', isObj(sf) ? h('span', { class: 'tag ' + (sf.inventory === 'complete' ? 't-ok' : sf.inventory === 'capped' ? 't-cap' : 't-warn') }, String(sf.inventory)) : val(sf)],
        ...(isObj(sf) ? ['era', 'protocol_version', 'sent', 'skipped', 'unanswered', 'called', 'failed'].map((k) => [k, sf[k] === undefined ? undefined : val(sf[k])]) : []),
      ]), isObj(sf) ? others(sf, ['inventory', 'era', 'protocol_version', 'sent', 'skipped', 'unanswered', 'called', 'failed']) : null));
    const listings = isObj(inv.listings) ? inv.listings : {};
    const names = Object.keys(LISTING_LABEL).filter((n) => Object.hasOwn(listings, n)).concat(Object.keys(listings).filter((n) => !Object.hasOwn(LISTING_LABEL, n)));
    for (const name of names) {
      const l = listings[name];
      const items = isObj(l) ? asList(l.items) : asList(l);
      const method = own(LISTING_METHOD, name);
      const stepNotes = steps.filter((s) => (s.type === 'step_skipped' || s.type === 'step_unanswered') && s.step === method);
      const pages = isObj(l) ? l.pages : undefined;
      const seqs = isObj(l) ? asList(l.seqs) : [];
      const note = [items.length ? plural(items.length, 'item') : null,
        pages !== undefined && pages !== null && Number(pages) > 0 ? (items.length ? ' · ' : '') + plural(Number(pages), 'page') + ' (counted from messages)' : '',
        seqs.length ? ' · answered in ' : ''];
      const p = panel([own(LISTING_LABEL, name) || name, ' ', h('span', { class: 'sub' }, mono(name))], [note, seqs.map((s, i) => [i ? ', ' : '', seqLink(ref, s)])],
        noticesAt(env, 'listing:' + name),
        stepNotes.map((s) => h('p', { class: 'inplace' }, code(s.type), ' ', code(s.step), ' · ', String(s.reason), s.detail ? h('span', { class: 'wire' }, ' · ', String(s.detail)) : '', s.pages !== undefined ? ' · pages ' + s.pages : '')),
        items.length ? h('div', { class: 'cards' }, items.map((it) => itemCard(name, it))) : (stepNotes.length ? null : noneRecorded(env, 'listing:' + name)),
        isObj(l) ? others(l, ['items', 'pages', 'seqs']) : null);
      out.appendChild(p);
    }
    if (!names.length) out.appendChild(panel('Listings', null, noneRecorded(env, 'tab:inventory')));
    const extra = others(inv, ['steps', 'script_finished', 'listings']);
    if (extra) out.appendChild(extra);
    return out;
  }

  // A change's before and after are recorded as payloads ({encoding, data, redactions, …}).
  function valueBlock(v) {
    if (isObj(v) && 'encoding' in v && 'data' in v) {
      return frag(payloadBlock(v), typeof v.redaction_count === 'number' && v.redaction_count ? h('span', { class: 'sub' }, plural(v.redaction_count, 'value') + ' masked') : null);
    }
    return jsonBlock(v);
  }
  function changeRow(c) {
    return [mono(c.path), valueBlock(c.before), valueBlock(c.after)];
  }

  function interventionCard(wrapped, ref, compact) {
    if (!isObj(wrapped)) return val(wrapped);
    // views.py wraps the event: {event, message_seq, invalidated_by}; a bare event is taken too.
    // Copied with merged(), so a recorded "__proto__" stays a key.
    const iv = isObj(wrapped.event) ? merged(wrapped.event, { message_seq: wrapped.message_seq, invalidated_by: wrapped.invalidated_by }) : wrapped;
    const steps = asList(iv.steps).filter(isObj);
    const body = h('div', { class: 'card' });
    body.appendChild(h('div', { class: 'headrow' },
      h('span', { class: 'tag ' + (iv.action === 'drop' ? 't-bad' : 't-info') }, 'intervention · ', String(iv.action)),
      dirShort(iv.direction), sub('message id ', mono(iv.message_id === undefined ? '—' : jsonText(iv.message_id))),
      iv.message_seq !== undefined ? seqLink(ref, iv.message_seq) : (iv.seq !== undefined && !compact ? sub('event #', String(iv.seq)) : null),
      !isEmpty(iv.invalidated_by) ? tag('t-bad', 'invalid — quarantined: ', asList(iv.invalidated_by).join(', ')) : null));
    if (!steps.length) body.appendChild(h('p', { class: 'none' }, 'no steps recorded'));
    steps.forEach((s, i) => {
      body.appendChild(h('div', { class: 'stack' },
        h('div', { class: 'headrow' }, mono(String(i + 1) + ' '), h('strong', { class: 'wire' }, String(s.rule)), tag('t-plain', String(s.action)), s.reason ? sub('reason ', mono(s.reason)) : null),
        asList(s.changes).length ? table([{ label: 'Path' }, { label: 'Before' }, { label: 'After' }], asList(s.changes).filter(isObj).map(changeRow)) : null,
        asList(s.skipped).length ? table([{ label: 'Skipped path' }, { label: 'Reason' }], asList(s.skipped).filter(isObj).map((k) => [mono(k.path), mono(k.reason)])) : null,
        others(s, ['rule', 'action', 'reason', 'changes', 'skipped'])));
    });
    if (iv.original !== undefined || iv.replacement !== undefined) {
      body.appendChild(h('details', null, h('summary', null, 'original and replacement, masked as recorded'),
        h('h3', null, 'original'), valueBlock(iv.original), h('h3', null, 'replacement'), valueBlock(iv.replacement)));
    }
    add(body, [others(iv, ['action', 'direction', 'message_id', 'message_seq', 'seq', 'type', 'v', 'run_id', 't_ns', 'steps', 'original', 'replacement', 'invalidated_by'])]);
    return body;
  }

  function tabInterventions(env, x, ref) {
    const out = h('div', { class: 'stack' });
    const ivs = asList(isObj(x) ? pick(x, 'interventions', 'intervention') : x);
    const qs = asList(isObj(x) ? pick(x, 'rule_quarantined', 'quarantined') : null).map((q) => (isObj(q) && isObj(q.event) ? merged(q.event, { invalidates: q.invalidates }) : q));
    const ivBySeq = new Map(ivs.filter(isObj).map((w) => [isObj(w.event) ? w.event.seq : w.seq, w]));
    out.appendChild(panel('rule_quarantined', 'every intervention of a quarantined rule is invalid, before and after',
      qs.length ? h('div', { class: 'cards' }, qs.map((q) => isObj(q) ? h('div', { class: 'card' },
        h('div', { class: 'headrow' }, h('strong', { class: 'wire' }, String(q.rule)), tag('t-bad', String(q.reason)), dirShort(q.direction), sub('message id ', mono(q.message_id === undefined ? '—' : jsonText(q.message_id)))),
        q.detail !== undefined ? textBlock(q.detail) : null,
        kv([['invalidated_hits', scalar(q.invalidated_hits)]]),
        (() => {
          const inv = pick(q, 'invalidates', 'invalidated', 'interventions');
          if (inv === undefined) return null;
          return frag(h('h3', null, 'The interventions it invalidates'), isEmpty(inv) ? h('p', { class: 'none' }, 'none recorded') : h('ul', { class: 'plain' }, asList(inv).map((i) => {
            if (isObj(i)) return h('li', null, interventionCard(i, ref));
            const w = ivBySeq.get(i);
            const ev = w && isObj(w.event) ? w.event : w;
            return h('li', null, 'intervention event ', mono('#' + i), w && w.message_seq !== undefined && w.message_seq !== null ? [' on message ', seqLink(ref, w.message_seq)] : null,
              isObj(ev) ? [' · ', String(ev.action), ' · rules ', asList(ev.steps).filter(isObj).map((s) => String(s.rule)).join(', ')] : null);
          })));
        })(),
        others(q, ['rule', 'reason', 'detail', 'direction', 'message_id', 'invalidated_hits', 'invalidates', 'invalidated', 'interventions'])) : val(q))) : noneRecorded(env, 'tab:interventions')));
    out.appendChild(panel('Interventions', (ivs.length ? plural(ivs.length, 'event') + ' · ' : '') + 'what the rules did, step by step',
      ivs.length ? h('div', { class: 'cards' }, ivs.map((iv) => interventionCard(iv, ref))) : noneRecorded(env, 'tab:interventions')));
    if (isObj(x) && x.quarantined_rules !== undefined) out.insertBefore(h('div', { class: 'factbox' }, kv([['quarantined rules', isEmpty(x.quarantined_rules) ? h('span', { class: 'muted' }, 'none recorded') : val(x.quarantined_rules)]])), out.firstChild);
    if (isObj(x)) add(out, [others(x, ['interventions', 'intervention', 'rule_quarantined', 'quarantined', 'quarantined_rules'])]);
    return out;
  }

  function headersKv(hs) {
    if (!isObj(hs)) return val(hs);
    return kv(Object.entries(hs).map(([k, v]) => [k, mono(typeof v === 'string' ? v : jsonText(v))]));
  }

  function tabHttp(env, x, ref, scheme) {
    const out = h('div', { class: 'stack' });
    const exchanges = asList(isObj(x) ? pick(x, 'exchanges') : x).filter(isObj);
    const summary = isObj(x) ? pick(x, 'http', 'run_finished') : undefined;
    out.appendChild(panel('run_finished.http', null, summary === undefined || summary === null ? noneRecorded(env, 'tab:http') : httpFinished(summary, scheme)));
    const rows = [];
    for (const e of exchanges) {
      // Each slot holds the events of the exchange (one, normally); more than one is said.
      const first = (v) => (Array.isArray(v) ? (isObj(v[0]) ? v[0] : {}) : isObj(v) ? v : {});
      const many = ['request', 'response', 'end'].filter((k) => Array.isArray(e[k]) && e[k].length > 1);
      const rq = first(pick(e, 'request', 'http_request'));
      const rs = first(pick(e, 'response', 'http_response'));
      const en = first(pick(e, 'end', 'http_end'));
      const msgs = asList(pick(e, 'messages')).map((m) => (isObj(m) ? m : { seq: m }));
      rows.push([
        mono(e.exchange !== undefined ? e.exchange : rq.exchange), cellText(rq.connection), cellText(rq.method), mono(rq.target), exchangeTls(rq.tls), cellText(rq.session),
        frag(cellText(rs.status), rs.reason ? [' ', sub(rs.reason)] : null), cellText(rs.framing), cellText(en.ended),
        msgs.length ? h('span', { class: 'chips' }, msgs.map((m) => link('run', { ref, tab: 'messages', seq: m.seq }, mono('#' + m.seq), m.method || m.kind ? [' ', mono(m.method || m.kind)] : null))) : dash(),
      ]);
      if (many.length) rows.push(rowNote(10, h('p', { class: 'inplace' }, 'more than one event of this exchange in ', many.join(', '), '; all are below, as recorded')));
      rows.push(rowNote(10, h('details', null, h('summary', null, 'heads and byte counts'),
        h('div', { class: 'cols' }, h('div', null, h('h3', null, 'request headers (masked)'), headersKv(rq.headers)), h('div', null, h('h3', null, 'response headers (masked)'), headersKv(rs.headers))),
        kv([['content_type', rs.content_type === undefined ? undefined : scalar(rs.content_type)], ['request_body_bytes', en.request_body_bytes === undefined ? undefined : scalar(en.request_body_bytes)], ['response_body_bytes', en.response_body_bytes === undefined ? undefined : scalar(en.response_body_bytes)], ['head_bytes', en.head_bytes === undefined ? undefined : scalar(en.head_bytes)], ['events', en.events === undefined ? undefined : scalar(en.events)], ['comments', en.comments === undefined ? undefined : scalar(en.comments)]]),
        many.length ? jsonBlock(Object.fromEntries(many.map((k) => [k, e[k]]))) : null,
        others(e, ['exchange', 'request', 'response', 'end', 'http_request', 'http_response', 'http_end', 'messages']))));
    }
    out.appendChild(panel('Exchanges', 'http_request · http_response · http_end, joined by exchange',
      exchanges.length ? table([{ label: '#' }, { label: 'Conn' }, { label: 'HTTP' }, { label: 'Target' }, { label: 'TLS' }, { label: 'Session' }, { label: 'Status' }, { label: 'Framing' }, { label: 'Ended' }, { label: 'MCP messages' }], rows) : noneRecorded(env, 'tab:http')));
    if (isObj(x)) add(out, [others(x, ['exchanges', 'http', 'run_finished'])]);
    return out;
  }

  function tabSandbox(env, x) {
    const out = h('div', { class: 'stack' });
    const o = isObj(x) ? x : {};
    const steps = asList(pick(o, 'sandbox_step', 'sandbox_steps', 'steps')).filter(isObj);
    const failed = pick(o, 'sandbox_failed');
    for (const f of asEvents(failed)) {
      if (!isObj(f)) continue;
      out.appendChild(h('div', { class: 'banner bad', role: 'note' }, h('span', { class: 'key' }, 'sandbox_failed'),
        'condition ', code(f.condition), ' · phase ', code(f.phase), f.detail !== undefined ? [' · ', h('span', { class: 'wire' }, jsonText(f.detail))] : null));
    }
    const list = h('ul', { class: 'checklist' }, steps.map((s) => h('li', null,
      h('span', { class: 'mark' + (s.ok ? '' : ' bad'), 'aria-hidden': 'true' }, s.ok ? '✓' : '✗'),
      h('div', null, h('div', { class: 'what wire' }, String(s.step)), s.detail !== undefined && s.detail !== null ? h('div', { class: 'detail wire' }, typeof s.detail === 'string' ? vis(s.detail, true) : val(s.detail)) : null),
      h('div', null, h('span', { class: s.ok ? 'held' : 'failed' }, s.ok ? 'held' : 'failed'), typeof s.seconds === 'number' ? h('div', { class: 'sub' }, s.seconds.toFixed(2) + ' s') : null))));
    out.appendChild(h('section', { class: 'panel' }, h('header', { class: 'panel-head' }, h('h2', { class: 'panel-title' }, 'sandbox_step — the proof, in order'), h('span', { class: 'panel-note' }, 'as recorded; a gate or target-started step is not one of them')),
      h('div', { class: 'panel-body flush' }, steps.length ? list : h('div', { class: 'panel-body' }, noneRecorded(env, 'tab:sandbox')))));
    const att = asList(pick(o, 'egress_attempt', 'egress_attempts')).filter(isObj);
    const dns = asList(pick(o, 'egress_dns')).filter(isObj);
    out.appendChild(panel('What the server tried to reach', 'the kernel\'s record is authoritative',
      att.length ? table([{ label: 'Protocol' }, { label: 'Family' }, { label: 'Original destination' }, { label: 'Port', num: true }, { label: 'Kind' }, { label: 'Kernel count', num: true }, { label: 'Unit' }],
        att.map((a) => [cellText(a.proto), cellText(a.family), mono(a.destination), cellText(a.port), cellText(a.kind), cellText(a.count), cellText(a.unit)])) : noneRecorded(env, 'tab:sandbox'),
      h('h3', null, 'egress_dns'),
      dns.length ? table([{ label: 'Transport' }, { label: 'Family' }, { label: 'qname' }, { label: 'qtype' }, { label: 'Answered' }, { label: 'Masked', num: true }],
        dns.map((q) => [cellText(q.transport), cellText(q.family), mono(q.qname), cellText(q.qtype), cellText(q.answered), cellText(q.qname_redactions)])) : noneRecorded(env, 'tab:sandbox')));
    const sum = pick(o, 'egress_summary');
    out.appendChild(panel('egress_summary', 'sink held against the kernel by membership',
      sum === undefined || sum === null ? noneRecorded(env, 'tab:sandbox') : val(sum)));
    add(out, [others(o, ['sandbox_step', 'sandbox_steps', 'steps', 'sandbox_failed', 'egress_attempt', 'egress_attempts', 'egress_dns', 'egress_summary'])]);
    return out;
  }

  function tabStderr(env, x) {
    const list = asList(isObj(x) ? pick(x, 'server_stderr', 'events', 'stderr') : x).filter(isObj);
    const out = h('div', { class: 'stack' });
    out.appendChild(panel('server_stderr', 'what the server wrote to its stderr, masked as recorded',
      list.length ? h('div', { class: 'stack' }, list.map((e) => {
        const p = isObj(e.payload) ? e.payload : null;
        return h('div', { class: 'stack' },
          h('div', { class: 'headrow' }, e.seq !== undefined ? mono('#' + e.seq) : null, sub(plural(Number(e.size_bytes) || 0, 'byte')), e.truncated ? tag('t-cap', 'truncated') : null, p && p.redaction_count ? tag('t-plain', p.redaction_count + ' masked') : null),
          p ? payloadBlock(p) : (typeof e.payload === 'string' ? textBlock(e.payload) : val(e.payload)),
          others(e, ['seq', 'size_bytes', 'truncated', 'payload']));
      })) : noneRecorded(env, 'tab:stderr')));
    if (isObj(x)) add(out, [others(x, ['server_stderr', 'events', 'stderr'])]);
    return out;
  }

  // ---- the store -----------------------------------------------------------------------

  const STORE_TABS = [
    ['store/runs', 'Runs', null],
    ['store/triage', 'Triage', null],
    ['store/findings', 'Findings · reference', { provenance: 'reference' }],
    ['store/findings', 'Findings · poison', { provenance: 'poison' }],
    ['store/candidates', 'Real-world candidates', null],
    ['store/diff', 'Diff two runs', null],
  ];

  function storeTabs(path, params) {
    const prov = params && params.get('provenance');
    return h('nav', { class: 'tabs', 'aria-label': 'Store views' }, STORE_TABS.map(([p, label, q]) => {
      const current = p === path && (!q || (q.provenance === (prov || 'reference')));
      return h('a', { href: href(p, q), 'aria-current': current ? 'page' : null }, label);
    }));
  }

  async function storeHead(path, params, lede) {
    const env = await api('store/engagement');
    return frag(pageHead('Finding store', 'Each finding under its key, each run in its state', lede ||
      'Read-only. Where a finding sat in a run is a sighting beside it, never part of its key. A store of another schema is refused whole.'),
    storeEngagement(env), storeTabs(path, params));
  }

  // The store's engagement (Store.engagement): its id, the current digest, delete_after as
  // declared, and every version. Its notices are the store view's own, shown below; only a
  // refusal of the engagement rows themselves is said here.
  function storeEngagement(env) {
    if (refusedWhole(env)) return null;
    const d = isObj(env.data) ? env.data : {};
    const e = d.engagement;
    const box = h('section', { class: 'engagement', 'aria-label': 'The store\'s engagement' });
    box.appendChild(h('div', { class: 'eyebrow' }, 'Engagement · as the store holds it'));
    const refusal = noticesAt(env, 'engagement');
    if (refusal) { box.appendChild(refusal); return box; }
    if (!isObj(e)) {
      box.appendChild(h('p', { class: 'sub' }, 'none: this store holds no engagement'));
    } else {
      const versions = asList(e.versions).filter(isObj);
      box.appendChild(kv([
        ['id (declared)', mono(e.engagement_id_declared)],
        ['current digest', mono(e.engagement_digest)],
        ['versions', String(versions.length)],
        ['delete_after (declared)', e.delete_after_declared === null || e.delete_after_declared === undefined ? h('span', { class: 'muted' }, 'none declared') : mono(e.delete_after_declared)],
      ]));
      if (versions.length) {
        box.appendChild(h('details', null, h('summary', null, 'Every version of the file, oldest first'),
          table([{ label: '#', num: true }, { label: 'Digest' }, { label: 'Supersedes' }, { label: 'Set (UTC)' }, { label: 'Window (declared)' }, { label: 'Removed before filing' }, { label: 'The file, as declared' }],
            versions.map((v) => [cellText(v.version), mono(short(v.digest)), v.supersedes ? mono(short(v.supersedes)) : dash(), cellText(v.set_utc), windowWords(v.window_declared) || dash(), causeKeys(v.removed),
              v.file_declared === null || v.file_declared === undefined ? dash() : val(v.file_declared)]))));
      }
    }
    const bundles = asList(d.bundles).filter(isObj);
    if (bundles.length) {
      box.appendChild(h('details', null, h('summary', null, plural(bundles.length, 'bundle') + ' packed from this store'),
        table([{ label: 'Index digest' }, { label: 'Path, as written' }, { label: 'Packed (UTC)' }, { label: 'Derived from' }],
          bundles.map((b) => [mono(short(b.index_digest)), mono(b.path), cellText(b.packed_utc), b.derived_from ? mono(short(b.derived_from)) : dash()]))));
    }
    return box;
  }

  const RECORDING_STATUS = {
    found: ['t-ok', 'found under --runs'],
    not_found: ['t-warn', 'not found under --runs'],
    changed: ['t-grave', 'changed — not this run\'s bytes'],
  };

  async function pageStoreRuns(p) {
    setTitle('Store · runs');
    const env = await api('store/runs');
    const out = await storeHead('store/runs', p);
    add(out, [noticesTop(env)]);
    if (refusedWhole(env)) return out;
    const rows = asList(env.data).filter(isObj);
    const trs = [];
    for (const r of rows) {
      const changedUnreadable = env.notices.some((n) => n.kind === 'recording_changed' && n.where === 'run:' + r.run && n.unreadable !== undefined && n.unreadable !== null);
      const st = changedUnreadable ? ['t-grave', 'changed — the file could not be read'] : own(RECORDING_STATUS, r.recording_status);
      trs.push({
        cells: [
          mono(short(r.run)),
          frag(mono(r.server), h('span', { class: 'muted' }, ' × '), mono(r.scenario)),
          provTag(r.provenance), isolationCell(r.isolation, r.egress_observed), stateChip(r.state), causeKeys(r.causes),
          frag(cellText(r.problem_count)),
          mono(r.rules),
          frag(st ? tag(st[0], st[1]) : cellText(r.recording_status),
            r.recording_status === 'found' && r.ref ? [h('br'), link('run', { ref: r.ref }, 'open the recording')] : null),
        ],
      });
      const here = noticesAt(env, 'run:' + r.run);
      const detail = h('details', null, h('summary', null, 'run in full'), kv([
        ['run (SHA-256 of the recording)', mono(r.run)], ['server_version', versionCell(r.server_version, r.server_version_kind)], ['announced_server', scalar(r.announced_server)],
        ['launch_digest', mono(r.launch_digest)], ['tool', frag(mono(r.tool_version), ' · ', mono(r.tool_content))], ['scenario_digest', mono(r.scenario_digest)],
        ['images', frag('sandbox ', mono(r.sandbox_image === null ? '—' : r.sandbox_image), ' · target ', mono(r.target_image === null ? '—' : r.target_image))],
        ['complete', scalar(r.complete)], ['problems (first 20)', isEmpty(r.problems) ? h('span', { class: 'muted' }, 'none recorded') : h('ul', { class: 'list' }, asList(r.problems).map((x) => h('li', { class: 'wire' }, x)))],
        ['truncations', isEmpty(r.truncations) ? h('span', { class: 'muted' }, 'none recorded') : val(r.truncations)],
        ['endpoint certificates', certificates(r.endpoint_certificates)],
        ['ref', r.ref === undefined ? undefined : mono(r.ref)],
      ]), others(r, ['run', 'provenance', 'server', 'announced_server', 'server_version', 'server_version_kind', 'egress_observed', 'endpoint_certificates', 'launch_digest', 'tool_version', 'tool_content', 'scenario', 'scenario_digest', 'isolation', 'sandbox_image', 'target_image', 'state', 'complete', 'problem_count', 'problems', 'causes', 'truncations', 'rules', 'recording_status', 'ref']));
      trs.push(rowNote(9, here, detail));
    }
    add(out, [panel('Runs in the store', rows.length ? plural(rows.length, 'run') + ' · oldest first' : null,
      rows.length ? table([{ label: 'Run · sha256 of recording' }, { label: 'Server × scenario', cls: 'w-pair' }, { label: 'Provenance' }, { label: 'Isolation' }, { label: 'State' }, { label: 'Causes' }, { label: 'Problems', num: true }, { label: 'Rules' }, { label: 'Recording' }], trs) : noneRecorded(env, 'view'))]);
    return out;
  }

  // The key's seven fields (store.KEY_FIELDS), and server_version_kind beside it.
  const KEY_FIELDS = ['server', 'server_version', 'tool_version', 'scenario', 'statement', 'locator', 'signal', 'server_version_kind'];

  function keysTable(list) {
    const known = list.every((k) => isObj(k) && Object.keys(k).every((x) => KEY_FIELDS.includes(x)));
    if (!known) return objTable(list.map((k) => (isObj(k) ? k : { value: k })));
    return table([{ label: 'Server' }, { label: 'Server version' }, { label: 'Scenario' }, { label: 'Statement' }, { label: 'Locator · signal' }, { label: 'Tool version' }],
      list.map((k) => [mono(k.server), versionCell(k.server_version, k.server_version_kind, true), mono(k.scenario), mono(k.statement), frag(mono(k.locator), h('br'), h('strong', null, mono(k.signal))), mono(k.tool_version)]));
  }

  async function pageStoreFindings(p) {
    const prov = p.get('provenance') || 'reference';
    setTitle('Store · findings');
    const env = await api('store/findings', { provenance: prov });
    const out = await storeHead('store/findings', p);
    add(out, [noticesTop(env)]);
    if (refusedWhole(env)) return out;
    const list = asList(env.data);
    add(out, [panel(['Findings · ', provTag(prov)], list.length ? plural(list.length, 'key') + ' · each finding once, under its key' + (anyNar(env) ? ' · not every run filed is a result, see the notice' : '') : null,
      list.length ? keysTable(list) : noneRecorded(env, 'view'),
      h('p', { class: 'sub' }, 'How often each was sighted is the store\'s count, in its sightings table; this view lists the keys.'))]);
    return out;
  }

  async function pageStoreCandidates(p) {
    setTitle('Store · real-world candidates');
    const env = await api('store/candidates');
    const out = await storeHead('store/candidates', p);
    add(out, [noticesTop(env)]);
    if (refusedWhole(env)) return out;
    const list = asList(env.data);
    if (!has(env, 'candidates')) {
      add(out, [noticeEl({ kind: 'candidates', text: 'Real-world findings are kept apart from what may be published.' })]);
    }
    add(out, [panel(['Real-world candidates ', provTag('real-world')], 'candidates for disclosure, not results to publish' + (anyNar(env) ? ' · not every run filed is a result, see the notice' : ''),
      list.length ? keysTable(list) : noneRecorded(env, 'view'))]);
    return out;
  }

  async function runOptions(selected) {
    const env = await api('store/runs');
    const rows = asList(env.data).filter(isObj);
    return { env, rows };
  }

  // What a picker's option stands for: the row at its index, '' for the first, empty option.
  function chosen(rows, index, field) {
    const r = index === '' ? null : rows[Number(index)];
    return isObj(r) ? r[field] : '';
  }

  function diffPicker(rows, before, after, path) {
    const mk = (name, current) => {
      const sel = h('select', { name, id: 'pick-' + name });
      sel.appendChild(h('option', { value: '' }, '— choose a run —'));
      rows.forEach((r, i) => {
        const label = [short(r.run), ' · ', jsonText(r.server), ' × ', jsonText(r.scenario), ' · ', jsonText(r.state)].join('');
        // An <option> cannot hold markup, so its label has the unsafe characters as tokens
        // (visText), and its value is the row's index: no value of the data is an attribute.
        sel.appendChild(h('option', { value: String(i), selected: r.run === current ? true : null }, visText(label)));
      });
      return h('label', { for: 'pick-' + name }, name, sel);
    };
    const form = h('form', { class: 'pick' }, mk('before', before), mk('after', after), h('button', { type: 'submit', class: 'btn primary' }, 'Compare'));
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      const b = chosen(rows, form.querySelector('select[name="before"]').value, 'run');
      const a = chosen(rows, form.querySelector('select[name="after"]').value, 'run');
      location.hash = href(path, { before: b, after: a });
    });
    return form;
  }

  // kinds: Diff.server_version_kind, {before, after}, labelled beside the server axis's version.
  function axesTable(axes, kinds) {
    if (!isObj(axes)) return val(axes);
    const rows = [];
    for (const [name, ax] of Object.entries(axes)) {
      if (!isObj(ax)) { rows.push([mono(name), dash(), val(ax), dash()]); continue; }
      const fields = Object.entries(ax).filter(([k]) => k !== 'moved');
      fields.forEach(([field, ba], i) => {
        const b = isObj(ba) ? ba.before : ba, a = isObj(ba) ? ba.after : undefined;
        const same = jsonText(b) === jsonText(a);
        const labelled = name === 'server' && field === 'server_version';
        const kb = labelled ? [' ', versionKind(isObj(kinds) ? kinds.before : undefined)] : null;
        const ka = labelled ? [' ', versionKind(isObj(kinds) ? kinds.after : undefined)] : null;
        rows.push([i === 0 ? mono(name) : '', i === 0 ? h('span', { class: ax.moved ? 'moved' : 'unmoved' }, ax.moved ? 'moved' : 'not moved') : '', mono(field),
          frag(mono(b === null || b === undefined ? '—' : jsonText(b)), kb, arrow(), h('span', { class: same ? 'unmoved' : 'moved' }, mono(a === null || a === undefined ? '—' : jsonText(a))), ka)]);
      });
    }
    return table([{ label: 'Axis' }, { label: 'Moved' }, { label: 'Field' }, { label: 'Before → after' }], rows);
  }

  function identityCells(c) {
    const id = isObj(c.identity) ? c.identity : {};
    return [frag(mono(id.server), h('span', { class: 'muted' }, ' × '), mono(id.scenario)), frag(mono(id.statement), h('br'), mono(id.locator), h('br'), h('strong', null, mono(id.signal)))];
  }

  function hints(c) {
    return h('span', { class: 'chips' }, c.statement_hint ? tag('t-info', String(c.statement_hint)) : null, c.cap_hint ? tag('t-cap', String(c.cap_hint)) : null,
      !c.statement_hint && !c.cap_hint ? dash() : null);
  }

  function sightings(list) {
    const l = asList(list).filter(isObj);
    if (!l.length) return dash();
    return h('ul', { class: 'plain' }, l.map((s) => h('li', null, mono(s.path), ' ', sub('#', String(s.message_seq)), s.normalized ? [' ', tag('t-info', 'normalized')] : null)));
  }

  function comparedTable(env, where, list) {
    const l = asList(list).filter(isObj);
    return frag(noticesAt(env, where), l.length ? table([{ label: 'Server × scenario' }, { label: 'Statement · locator · signal' }, { label: 'Hints' }, { label: 'Sighted before' }, { label: 'Sighted after' }],
      l.map((c) => [...identityCells(c), hints(c), sightings(c.sightings_before), sightings(c.sightings_after)])) : noneRecorded(env, where));
  }

  // Diff.caveats: per set, each caveat as the store gives it — its name and its words in one
  // string, one to a line, in the store's order. None moves an axis or the attribution.
  function caveatLists(c) {
    if (!isObj(c)) return val(c);
    return kv(Object.entries(c).map(([set, flags]) => [set, !Array.isArray(flags) ? val(flags)
      : flags.length ? h('ul', { class: 'list caveats' }, flags.map((f) => h('li', { class: 'wire' }, typeof f === 'string' ? f : jsonText(f))))
        : h('span', { class: 'muted' }, 'none')]));
  }

  function runInfoBox(label, r) {
    if (!isObj(r)) return panel(label, null, val(r));
    return panel(label, null, h('div', { class: 'headrow' }, stateChip(r.state), provTag(r.provenance), mono(short(r.run))),
      kv([['server × scenario', frag(mono(r.server), ' × ', mono(r.scenario))], ['server version', versionCell(r.server_version, r.server_version_kind, true)],
        ['announced server', r.announced_server === undefined ? undefined : scalar(r.announced_server)],
        ['isolation', isolationCell(r.isolation, r.egress_observed)], ['endpoint certificates', certificates(r.endpoint_certificates)], ['rules', scalar(r.rules)], ['causes', causeKeys(r.causes)]]));
  }

  async function pageStoreDiff(p) {
    setTitle('Store · diff');
    const before = p.get('before'), after = p.get('after');
    const out = await storeHead('store/diff', p);
    const { env: runsEnv, rows } = await runOptions();
    if (!before || !after) {
      add(out, [noticesTop(runsEnv)]);
      if (!refusedWhole(runsEnv)) {
        add(out, [panel('Diff two runs', 'Store.diff: new, gone and unchanged between two runs, with what moved',
          rows.length >= 2 ? diffPicker(rows, before, after, 'store/diff') : noneRecorded(runsEnv, 'view'),
          rows.length === 1 ? h('p', { class: 'sub' }, 'One run in the store; a diff needs two.') : null)]);
      }
      return out;
    }
    const env = await api('store/diff', { before, after });
    add(out, [noticesTop(env)]);
    if (rows.length >= 2) add(out, [h('details', null, h('summary', null, 'Choose other runs'), diffPicker(rows, before, after, 'store/diff'))]);
    if (refusedWhole(env)) return out;
    const d = isObj(env.data) ? env.data : {};
    const nc = d.complete === false || has(env, 'comparison_not_complete');
    const cnote = (where) => [has(env, 'capped', where) ? 'capped, see the notice' : null, nc ? 'the comparison is not complete' : null].filter(Boolean).join(' · ') || null;
    const counters = h('div', { class: 'counters' },
      counter('new', countOrNone(asList(d.new).length, nc), cnote('new')),
      counter('gone', countOrNone(asList(d.gone).length, nc), cnote('gone')),
      counter('unchanged', countOrNone(asList(d.unchanged).length, nc), cnote('unchanged')),
      counter('complete', d.complete === true ? 'yes' : d.complete === false ? 'no' : '—', d.complete === false ? 'a run is not a result; the diff exits 3' : null));
    add(out, [h('div', { class: 'cols' }, runInfoBox('Before', d.before), runInfoBox('After', d.after)), counters]);
    add(out, [h('div', { class: 'cols' },
      panel('Rules and entry', null, kv([['rules', d.rules === undefined ? undefined : val(d.rules)], ['same_entry', scalar(d.same_entry)], ['moved_axes', isEmpty(d.moved_axes) ? h('span', { class: 'muted' }, 'none') : val(d.moved_axes)]])),
      panel('Attribution', 'a change is put down to an axis only when exactly one moved', isObj(d.attribution) ? kv([['attributable', scalar(d.attribution.attributable)], ['axis', scalar(d.attribution.axis)], ['note', h('span', { class: 'wire' }, String(d.attribution.note === undefined ? '' : d.attribution.note))]]) : val(d.attribution)))]);
    add(out, [panel('What moved', 'server · tool · scenario · environment', axesTable(d.axes, d.server_version_kind))]);
    add(out, [panel('Caveats', 'soft flags per set: complete data, but not a clean comparison', isEmpty(d.caveats) ? h('p', { class: 'none' }, 'none recorded') : caveatLists(d.caveats))]);
    add(out, [panel('New', 'in the later run, not the earlier', comparedTable(env, 'new', d.new))]);
    add(out, [panel('Gone', 'in the earlier run, not the later', comparedTable(env, 'gone', d.gone))]);
    add(out, [panel('Unchanged', 'in both; where each sat may have moved', comparedTable(env, 'unchanged', d.unchanged))]);
    add(out, [others(d, ['before', 'after', 'complete', 'rules', 'same_entry', 'axes', 'moved_axes', 'attribution', 'caveats', 'new', 'gone', 'unchanged', 'server_version_kind'])]);
    return out;
  }

  // A comparison that is not complete has no count that reads as complete: zero is "none recorded".
  function countOrNone(n, notComplete) { return n === 0 && notComplete ? 'none recorded' : n; }

  function counter(label, value, note) {
    return h('div', { class: 'counter' }, h('span', { class: 'label' }, label), h('span', { class: 'value' }, String(value)), note ? h('span', { class: 'note' }, note) : null);
  }

  // ---- fleets ----------------------------------------------------------------------------

  function fleetState(env, where, fj) {
    if (has(env, 'fleet_state_not_in_store', where) || fj === null) {
      return h('span', { class: 'tag t-missing' }, 'not recorded in the store');
    }
    if (isObj(fj)) return frag(stateChip(fj.state), fj.interrupted ? [' ', tag('t-warn', 'interrupted ', String(fj.interrupted))] : null);
    return dash();
  }

  async function pageFleets() {
    setTitle('Fleets');
    const env = await api('fleets');
    const out = frag(pageHead('Fleet runs', 'Fleets in the store',
      'A fleet\'s state and interruption are read from its fleet.json under --runs; the store keeps neither, and neither is derived here from the results.'));
    add(out, [noticesTop(env)]);
    if (refusedWhole(env)) return out;
    const rows = asList(env.data).filter(isObj);
    const trs = [];
    for (const r of rows) {
      const fj = r.fleet_json;
      trs.push([
        link('fleet', { id: r.fleet }, mono(r.fleet)), cellText(r.started_utc), cellText(r.finished_utc),
        fleetState(env, 'fleet:' + r.fleet, fj), fleetEngagementCell(env, 'fleet:' + r.fleet, r), scalar(r.complete), mono(r.rules), cellText(r.parallel), isolationCell(r.isolation), mono(short(r.digest)),
        cellText(Array.isArray(r.problems) ? r.problems.length : r.problems),
      ]);
      const here = noticesAt(env, 'fleet:' + r.fleet);
      if (here) trs.push(rowNote(11, here));
      if (!isEmpty(r.problems) && Array.isArray(r.problems)) {
        trs.push(rowNote(11, h('details', null, h('summary', null, 'Problems of this fleet'), h('ul', { class: 'list' }, r.problems.map((x) => h('li', { class: 'wire' }, x))))));
      }
    }
    add(out, [panel('Fleets', rows.length ? plural(rows.length, 'fleet') + ' · oldest first' : null,
      rows.length ? table([{ label: 'Fleet' }, { label: 'Started' }, { label: 'Finished' }, { label: 'State (fleet.json)' }, { label: 'Engagement (declared)' }, { label: 'Complete' }, { label: 'Rules' }, { label: 'Parallel', num: true }, { label: 'Isolation' }, { label: 'Digest' }, { label: 'Problems', num: true }], trs) : noneRecorded(env, 'view'))]);
    if (rows.length >= 2) {
      add(out, [panel('Compare two fleets', 'fleet.compare, entry by entry',
        fleetPicker(rows), h('p', null, link('fleets/compare', null, 'Compare the last two'), ' ', h('span', { class: 'sub' }, '(both omitted: the last two, as fleet diff does)')))]);
    }
    return out;
  }

  // A fleet's engagement in the listing: from its fleet.json, or not known without one.
  function fleetEngagementCell(env, where, r) {
    if (has(env, 'fleet_state_not_in_store', where) || r.fleet_json === null) return h('span', { class: 'tag t-missing' }, 'not known: fleet.json not found');
    if (has(env, 'refused', where)) return tag('t-bad', 'refused, see the notice');
    if (isObj(r.engagement)) return frag(mono(r.engagement.engagement_id_declared), h('br'), sub(mono(short(r.engagement.engagement_digest))));
    return h('span', { class: 'muted' }, 'none');
  }

  function fleetPicker(rows, before, after) {
    const mk = (name, current) => {
      const sel = h('select', { name, id: 'fleet-' + name });
      sel.appendChild(h('option', { value: '' }, '— choose a fleet —'));
      rows.forEach((r, i) => sel.appendChild(h('option', { value: String(i), selected: r.fleet === current ? true : null }, visText(r.fleet))));
      return h('label', { for: 'fleet-' + name }, name, sel);
    };
    const form = h('form', { class: 'pick' }, mk('before', before), mk('after', after), h('button', { type: 'submit', class: 'btn primary' }, 'Compare'));
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      location.hash = href('fleets/compare', {
        before: chosen(rows, form.querySelector('select[name="before"]').value, 'fleet'),
        after: chosen(rows, form.querySelector('select[name="after"]').value, 'fleet'),
      });
    });
    return form;
  }

  async function pageFleet(p) {
    const id = p.get('id');
    setTitle('Fleet');
    const env = await api('fleet', { id });
    const out = frag(pageHead('Fleet run', id === null ? '(no fleet named)' : id, null, { mono: true }));
    add(out, [noticesTop(env)]);
    if (refusedWhole(env)) return out;
    const d = isObj(env.data) ? env.data : {};
    const stateNode = has(env, 'fleet_state_not_in_store') || d.state === undefined || d.state === null
      ? h('span', { class: 'tag t-missing' }, 'not recorded in the store')
      : stateChip(d.state, null, true);
    add(out, [h('div', { class: 'cols' },
      panel('State', 'from fleet.json', h('div', { class: 'statebig' }, stateNode),
        kv([['interrupted', has(env, 'fleet_state_not_in_store') ? h('span', { class: 'tag t-missing' }, 'not recorded in the store') : scalar(d.interrupted)], ['complete (store)', scalar(d.complete)], ['rules', scalar(d.rules)], ['digest', mono(d.digest)]])),
      panel('Pins', null, kv([['started_utc', mono(d.started_utc)], ['finished_utc', mono(d.finished_utc)], ['parallel', scalar(d.parallel)], ['isolation', isolationCell(d.isolation)], ['sandbox_image', mono(d.sandbox_image)], ['target_image', mono(d.target_image)], ['manifest_source', mono(d.manifest_source)], ['manifest_digest', mono(d.manifest_digest)], ['tool', frag(mono(d.tool_version), ' · ', mono(d.tool_content))]])))]);
    add(out, [has(env, 'fleet_state_not_in_store')
      ? engagementHeader('fleet', null, 'Not recorded in the store: the engagement is read from fleet.json, which was not found.')
      : has(env, 'refused', 'engagement') ? frag(engagementHeader('fleet', null, 'Refused: the engagement block of fleet.json is not one this version reads.'), noticesAt(env, 'engagement'))
        : engagementHeader('fleet', d.engagement)]);
    add(out, [panel('Fleet problems', 'what the fleet itself said', isEmpty(d.problems) ? h('p', { class: 'none' }, 'none recorded') : h('ul', { class: 'list' }, asList(d.problems).map((x) => h('li', { class: 'wire' }, x))))]);
    const results = asList(d.results).filter(isObj);
    const trs = [];
    for (const r of results) {
      trs.push([mono(r.entry), provTag(r.provenance), mono(r.scenario), stateChip(r.state), cellText(r.exit_code), mono(short(r.run)), causeKeys(r.causes),
        isEmpty(r.problems) ? dash() : h('ul', { class: 'list' }, asList(r.problems).map((x) => h('li', { class: 'wire' }, x)))]);
      const here = noticesAt(env, 'result:' + r.entry + '/' + r.scenario);
      if (here) trs.push(rowNote(8, here));
    }
    add(out, [panel('Results by entry and scenario', 'one run per key', results.length ? table([{ label: 'Entry' }, { label: 'Provenance' }, { label: 'Scenario' }, { label: 'State' }, { label: 'Exit', num: true }, { label: 'Run' }, { label: 'Causes' }, { label: 'Problems' }], trs) : noneRecorded(env, 'view', { several: true }))]);
    const fnd = d.findings;
    const dc = d.disclosure_candidates;
    const findingsPanel = [];
    if (fnd === undefined || (fnd === null && has(env, 'fleet_state_not_in_store'))) {
      findingsPanel.push(h('p', { class: 'inplace' }, 'Publishable findings are in the fleet\'s fleet.json, which was not found: not recorded in the store.'));
    } else if (isObj(fnd)) {
      for (const [prov, list] of Object.entries(fnd)) {
        const l = asList(list).filter(isObj);
        findingsPanel.push(h('h3', null, provTag(prov), ' ', l.length ? plural(l.length, 'finding') + (anyNar(env) ? ' · not every run here is a result' : '') : ''));
        findingsPanel.push(l.length ? table([{ label: 'Entry × scenario' }, { label: 'Statement · locator · signal' }],
          l.map((f) => { const k = isObj(f.key) ? f.key : {}; return [frag(mono(f.entry), ' × ', mono(f.scenario)), frag(mono(k.statement), h('br'), mono(k.locator), h('br'), h('strong', null, mono(k.signal)))]; })) : noneRecorded(env, 'view', { several: true }));
      }
    } else {
      findingsPanel.push(val(fnd));
    }
    add(out, [panel('Publishable findings', 'reference and poison only', findingsPanel)]);
    add(out, [panel(['Real-world ', provTag('real-world')], 'counted here, listed only under Store · real-world candidates',
      dc === undefined || (dc === null && has(env, 'fleet_state_not_in_store')) ? h('p', { class: 'inplace' }, 'The count is in fleet.json, which was not found: not recorded in the store.')
        : isObj(dc) ? frag(h('p', { class: 'say' }, dc['real-world'] === undefined || dc['real-world'] === null ? 'the count was not given' : String(dc['real-world']), ' — candidates for disclosure, not results to publish'), dc.note !== undefined ? h('p', { class: 'sub wire' }, dc.note) : null, others(dc, ['real-world', 'note']))
          : val(dc),
      h('p', null, link('store/candidates', null, 'Real-world candidates in the store')))]);
    if (Array.isArray(d.processed) && d.processed.length) {
      add(out, [h('details', null, h('summary', null, 'The order runs finished in (a fact about this fleet, never part of its result)'), h('ol', { class: 'list' }, d.processed.map((x) => h('li', null, mono(Array.isArray(x) ? x.join(' × ') : jsonText(x))))))]);
    }
    add(out, [others(d, ['fleet', 'started_utc', 'finished_utc', 'manifest_source', 'manifest_digest', 'tool_version', 'tool_content', 'isolation', 'sandbox_image', 'target_image', 'parallel', 'processed', 'digest', 'complete', 'problems', 'rules', 'results', 'state', 'interrupted', 'findings', 'disclosure_candidates', 'engagement'])]);
    return out;
  }

  const CHANGE_TAG = { compared: 't-plain', added: 't-info', removed: 't-warn', not_comparable: 't-bad' };

  async function pageFleetCompare(p) {
    const before = p.get('before'), after = p.get('after');
    setTitle('Fleets · compare');
    const env = await api('fleets/compare', before || after ? { before, after } : null);
    const d = isObj(env.data) ? env.data : null;
    const out = frag(pageHead('Fleet comparison', 'Two fleets, entry by entry', before || after ? null : 'Both omitted: the last two fleets in the store, as fleet diff does.'));
    add(out, [noticesTop(env)]);
    if (!d) return out;
    add(out, [h('div', { class: 'headrow' }, h('span', { class: 'sub' }, 'before'), mono(d.before), arrow(), h('span', { class: 'sub' }, 'after'), mono(d.after))]);
    const entries = asList(d.entries).filter(isObj);
    let nNew = 0, nGone = 0, nUnch = 0, nNc = 0;
    for (const e of entries) {
      nNew += asList(e.new).length; nGone += asList(e.gone).length;
      if (typeof e.unchanged === 'number') nUnch += e.unchanged;
      if (e.change === 'not_comparable') nNc += 1;
    }
    const nc = d.complete === false || has(env, 'comparison_not_complete');
    const ncNote = nc ? 'the comparison is not complete' : null;
    add(out, [h('div', { class: 'counters' }, counter('new', countOrNone(nNew, nc), ncNote), counter('gone', countOrNone(nGone, nc), ncNote), counter('unchanged', countOrNone(nUnch, nc), ncNote), counter('not comparable', nNc ? plural(nNc, 'key') : 'none'),
      counter('complete', d.complete === true ? 'yes' : d.complete === false ? 'no' : '—', d.complete === false ? 'fleet diff exits 3' : null),
      counter('same_result', d.same_result === true ? 'yes' : d.same_result === false ? 'no' : '—', 'digest equality'))]);
    add(out, [h('div', { class: 'cols' }, panel('Rules', 'said apart from the axes', val(d.rules)), panel('Fleet-wide axes', 'manifest · tool · environment', axesTable(d.axes)))]);
    const trs = [];
    for (const e of entries) {
      const where = 'entry:' + e.entry + '/' + e.scenario;
      const states = isObj(e.states) ? frag(stateChip(e.states.before), arrow(), stateChip(e.states.after)) : e.state !== undefined ? stateChip(e.state) : dash();
      trs.push([frag(mono(e.entry), h('span', { class: 'muted' }, ' × '), mono(e.scenario)), h('span', { class: 'tag ' + (own(CHANGE_TAG, e.change) || 't-plain') }, String(e.change)), states,
        isObj(e.causes) ? frag(causeKeys(e.causes.before), arrow(), causeKeys(e.causes.after)) : dash(),
        e.change === 'compared' ? frag(cellText(asList(e.new).length), ' / ', cellText(asList(e.gone).length), ' / ', cellText(e.unchanged), e.complete === false ? [h('br'), h('span', { class: 'sub' }, 'not complete')] : null) : dash(),
        isEmpty(e.moved_axes) ? dash() : h('span', { class: 'moved' }, asList(e.moved_axes).join(', ')),
        isObj(e.attribution) ? frag(e.attribution.axis !== null && e.attribution.axis !== undefined ? [mono(e.attribution.axis), ' '] : null, h('span', { class: 'sub wire' }, String(e.attribution.note === undefined ? '' : e.attribution.note))) : (e.reason !== undefined ? h('span', { class: 'wire' }, e.reason) : dash())]);
      const lists = [];
      const here = noticesAt(env, where);
      if (here) lists.push(here);
      for (const [label, l] of [['new', e.new], ['gone', e.gone]]) {
        const arr = asList(l).filter(isObj);
        if (!arr.length) continue;
        lists.push(h('h3', null, label));
        lists.push(table([{ label: 'Server × scenario' }, { label: 'Statement · locator · signal' }, { label: 'Hints' }], arr.map((c) => [...identityCells(c), hints(c)])));
      }
      if (!isEmpty(e.caveats)) lists.push(h('h3', null, 'caveats'), val(e.caveats));
      if (e.axes !== undefined) lists.push(h('details', null, h('summary', null, 'axes of this key'), axesTable(e.axes)));
      const ex = others(e, ['entry', 'scenario', 'change', 'state', 'states', 'causes', 'complete', 'moved_axes', 'axes', 'attribution', 'caveats', 'new', 'gone', 'unchanged', 'reason']);
      if (ex) lists.push(ex);
      if (lists.length) trs.push(rowNote(7, lists));
    }
    add(out, [panel('Entry by entry', 'what moved, key by key; new / gone / unchanged',
      entries.length ? table([{ label: 'Entry × scenario' }, { label: 'Change' }, { label: 'States' }, { label: 'Causes' }, { label: 'New / gone / unchanged' }, { label: 'Moved axes' }, { label: 'Attribution' }], trs) : noneRecorded(env, 'view', { several: true }))]);
    add(out, [others(d, ['before', 'after', 'complete', 'same_result', 'rules', 'axes', 'entries'])]);
    return out;
  }

  // ---- corpus and scenarios ---------------------------------------------------------------

  function sourceText(text) {
    const pre = h('pre', { class: 'source wire', 'aria-label': 'Source text, with line numbers' });
    const lines = String(text).split('\n');
    if (lines.length && lines[lines.length - 1] === '') lines.pop();
    for (const line of lines) pre.appendChild(h('span', { class: 'ln' }, vis(line), '\n'));
    return pre;
  }

  async function listPage(api_path, title, eyebrow, lede, routeOne) {
    const env = await api(api_path);
    const out = frag(pageHead(eyebrow, title, lede));
    add(out, [noticesTop(env)]);
    if (refusedWhole(env)) return out;
    const rows = asList(env.data).filter(isObj);
    add(out, [panel('Files given on the command line', null, rows.length ? table([{ label: '#', num: true }, { label: 'Path' }, { label: 'Loads' }],
      rows.map((r) => [cellText(r.index), link(routeOne, { i: r.index }, mono(r.path)), r.ok === true ? tag('t-ok', 'loads') : r.ok === false ? tag('t-bad', 'refused') : cellText(r.ok)])) : noneRecorded(env, 'view'))]);
    return out;
  }

  function sourceBeside(env, d) {
    // A refused file's text is in its notice, beside the words; a loaded one's in data.source.
    const text = isObj(d) && typeof d.source === 'string' ? d.source : null;
    return text === null ? null : panel('The file, as read', 'line numbers are the page\'s; the place in a refusal is a key path', sourceText(text));
  }

  // policy.PERMITTED for the provenance, against policy.PROVIDED: both as the view gives them.
  function isoChips(e) {
    const permitted = pick(e, 'isolation_permitted', 'permitted_isolations', 'permitted', 'isolations');
    if (permitted === undefined) return dash();
    const p = asList(permitted).map(String);
    const provided = Array.isArray(e.isolation_provided) ? e.isolation_provided.map(String) : null;
    const all = provided ? [...new Set([...provided, ...p])] : p;
    if (!all.length) return tag('t-bad', 'none');
    return h('span', { class: 'chips' }, all.map((i) => {
      const ok = p.includes(i), here = !provided || provided.includes(i);
      if (ok && here) return tag('t-ok', '✓ ', i);
      if (ok) return tag('t-warn', '✗ ', i, ' · not provided');
      return tag('t-plain', '✗ ', i);
    }));
  }

  async function pageCorpus(p) {
    const i = p.get('i');
    setTitle('Corpus');
    if (i === null) return listPage('corpus', 'Manifests', 'Corpus', 'Each manifest given with --manifest, through the project\'s own loader.', 'corpus');
    const env = await api('corpus', { i });
    const d = isObj(env.data) ? env.data : null;
    const out = frag(pageHead('Corpus', 'Manifest ' + i, 'Through the project\'s own loader (corpus.load); a file it refuses is refused here with the same words.'));
    add(out, [noticesTop(env)]);
    if (!d) {
      add(out, [sourceBeside(env, d)]);
      return out;
    }
    if (pick(d, 'path', 'file') !== undefined) add(out, [h('div', { class: 'factbox' }, kv([['file', mono(pick(d, 'path', 'file'))]]))]);
    const entries = asList(d.entries).filter(isObj);
    add(out, [h('div', { class: 'banner', role: 'note' }, h('strong', null, 'Read whole · ', plural(entries.length, 'entry', 'entries')),
      isObj(d.manifest) && d.manifest.digest !== undefined ? [' · manifest ', mono(d.manifest.digest)] : d.digest !== undefined ? [' · manifest ', mono(d.digest)] : null,
      isObj(d.tool) ? [' · tool ', mono(d.tool.version), ' ', mono(short(d.tool.content))] : null,
      d.format_version !== undefined ? [' · format ', String(d.format_version)] : null)]);
    const used = ['name', 'description', 'provenance', 'identity', 'transport', 'command_written', 'command', 'scenarios', 'launch_digest', 'paths', 'isolation_permitted', 'isolation_provided', 'permitted_isolations', 'permitted', 'isolations', 'refused_here', 'refusal', 'server_version_kind', 'endpoint'];
    const trs = [];
    for (const e of entries) {
      const idn = isObj(e.identity) ? e.identity : null;
      const cmd = pick(e, 'command_written', 'command');
      const refusal = pick(e, 'refused_here', 'refusal');
      trs.push([
        frag(h('strong', null, mono(e.name)), h('br'), provTag(e.provenance)),
        idn ? frag(mono(idn.kind), ' ', versionCell(idn.version, e.server_version_kind, true), idn.files !== undefined ? [h('br'), sub(plural(Number(idn.files) || 0, 'file'))] : null) : cellText(e.identity),
        frag(mono(e.transport), h('br'), typeof e.endpoint === 'string' ? sub('endpoint ', mono(e.endpoint)) : Array.isArray(cmd) ? mono(cmd.join(' ')) : cellText(cmd), e.launch_digest !== undefined ? [h('br'), sub('launch ', mono(short(e.launch_digest)))] : null),
        h('ul', { class: 'plain' }, asList(e.scenarios).map((s) => h('li', null, isObj(s) ? [mono(s.name), ' ', sub(mono(short(s.digest)))] : mono(s)))),
        frag(isoChips(e), refusal ? [h('br'), h('span', { class: 'sub wire' }, refusal)] : null),
      ]);
      const rest1 = others(e, used, 'Other fields of this entry, as given');
      const paths = e.paths !== undefined ? h('details', null, h('summary', null, 'source paths'), val(e.paths)) : null;
      if (rest1 || paths || e.description !== undefined) trs.push(rowNote(5, e.description !== undefined ? h('p', { class: 'sub wire' }, e.description) : null, paths, rest1));
    }
    add(out, [panel('Entries and what they pin', 'server_version is established from the server\'s content or revision, or declared for an endpoint someone else runs — never the version it announces',
      entries.length ? table([{ label: 'Entry' }, { label: 'Identity' }, { label: 'Launch' }, { label: 'Scenarios' }, { label: 'May run under' }], trs) : noneRecorded(env, 'view'))]);
    add(out, [sourceBeside(env, d)]);
    add(out, [others(d, ['entries', 'source', 'digest', 'path', 'file', 'manifest', 'tool', 'format_version'])]);
    return out;
  }

  async function pageScenarios() {
    setTitle('Scenarios');
    return listPage('scenarios', 'Scenario files', 'Scenarios', 'Each scenario given with --scenario, through the project\'s own loader.', 'scenario');
  }

  async function pageScenario(p) {
    const i = p.get('i');
    setTitle('Scenario');
    const env = await api('scenario', { i });
    const d = isObj(env.data) ? env.data : null;
    const out = frag(pageHead('Scenario', 'Scenario ' + i, 'Through the project\'s own loader (scenario.load); a file it refuses is refused here with the same words.'));
    add(out, [noticesTop(env)]);
    if (!d) { add(out, [sourceBeside(env, d)]); return out; }
    add(out, [h('div', { class: 'factbox' }, kv([['name', d.name === undefined ? undefined : mono(d.name)], ['path', d.path === undefined ? undefined : mono(d.path)], ['as named', d.source_name === undefined ? undefined : mono(d.source_name)], ['digest (SHA-256)', mono(d.digest)], ['format version', d.format_version === undefined ? undefined : scalar(d.format_version)]]))]);
    const rules = asList(d.rules).filter(isObj);
    add(out, [panel('Rules, in file order', 'what a rule would do to a message; a rule that did not match leaves nothing',
      rules.length ? table([{ label: 'Rule' }, { label: 'Action' }, { label: 'Direction' }, { label: 'Method' }, { label: 'Path' }, { label: 'Value · text · position' }],
        rules.map((r) => [h('strong', null, mono(r.name)), tag(r.action === 'drop' ? 't-bad' : 't-info', String(r.action)), cellText(r.direction), cellText(r.method), cellText(r.path),
          frag(r.value !== undefined && r.value !== null ? jsonBlock(r.value) : null, r.text ? textBlock(r.text) : null, r.position ? sub('position ', mono(r.position)) : null, others(r, ['name', 'action', 'direction', 'method', 'path', 'value', 'text', 'position']))])) : noneRecorded(env, 'view'))]);
    const sts = asList(d.statements).filter(isObj);
    add(out, [panel('Statements', 'at this path, in what the server sends, check these signals',
      sts.length ? table([{ label: 'Statement' }, { label: 'Method' }, { label: 'Path' }, { label: 'Signals' }],
        sts.map((s) => [h('strong', null, mono(s.name)), cellText(s.method), cellText(s.path), h('span', { class: 'chips' }, asList(s.signals).map((x) => tag('t-plain', String(x))))])) : noneRecorded(env, 'view'))]);
    add(out, [sourceBeside(env, d)]);
    add(out, [others(d, ['name', 'path', 'source_name', 'digest', 'format_version', 'rules', 'statements', 'source'])]);
    return out;
  }

  // ---- signals -------------------------------------------------------------------------

  const REACH_LABEL = { everywhere: 'every surface', metadata: 'tool metadata only', declared: 'declared only' };
  const REACH_TAG = { everywhere: 't-info', metadata: 'pv-poison', declared: 't-plain' };

  // A signal's kind (signals.Signal.kind): what one hit is. Neither is a severity, so both are
  // drawn alike, in the plain tag; no colour of danger.
  const KIND_SENTENCE = 'Evidence: the hit is the recorded fact itself. Heuristic: the hit is a shape that honest content has too, so a heuristic fires on honest content as well. The kind is no severity.';

  function kindTag(kind) {
    if (typeof kind !== 'string') return tag('t-missing', 'kind not given');
    return tag('t-plain', kind);
  }

  async function pageSignals() {
    setTitle('Signals');
    const env = await api('signals');
    const out = frag(pageHead('Inspector', 'What the server sends that a model could read as instruction',
      'Generated from the code at the time of the request. Each signal is a named check with a stable ID; an observation says where something sat and what shape it had — never a severity, never a verdict.'));
    add(out, [noticesTop(env)]);
    if (refusedWhole(env)) return out;
    const d = env.data;
    if (!isObj(d)) { add(out, [panel('Signals', 'as given', val(d))]); return out; }
    let libKey = ['library', 'signals'].find((k) => Array.isArray(d[k]));
    if (!libKey) libKey = Object.keys(d).find((k) => Array.isArray(d[k]) && d[k].length && d[k].every((x) => isObj(x) && 'signal' in x));
    const used = [];
    if (libKey) {
      used.push(libKey);
      const lib = d[libKey].filter(isObj);
      const tbody = [];
      const rowsByReach = [];
      for (const s of lib) {
        const tr = h('tr', { 'data-reach': own(REACH_LABEL, s.reach) ? s.reach : 'other' },
          h('td', null, h('strong', null, mono(s.signal))),
          h('td', null, s.reach !== undefined ? h('span', { class: 'tag ' + (own(REACH_TAG, s.reach) || 't-plain') }, own(REACH_LABEL, s.reach) || String(s.reach)) : dash()),
          h('td', null, kindTag(s.kind)),
          h('td', null, cellText(s.view)),
          h('td', null, others(s, ['signal', 'kind', 'reach', 'view'], 'more') || dash()));
        tbody.push(tr);
        rowsByReach.push(tr);
      }
      const filter = h('div', { class: 'filter', role: 'group', 'aria-label': 'Filter by reach' });
      const opts = [['all', 'All ' + lib.length], ['everywhere', 'Every surface'], ['metadata', 'Tool metadata'], ['declared', 'Declared only']];
      for (const [key, label] of opts) {
        filter.appendChild(h('button', { type: 'button', 'aria-pressed': key === 'all' ? 'true' : 'false', on: { click: (ev) => {
          for (const b of filter.querySelectorAll('button')) setState(b, 'aria-pressed', 'false');
          setState(ev.currentTarget, 'aria-pressed', 'true');
          for (const tr of rowsByReach) tr.hidden = !(key === 'all' || tr.getAttribute('data-reach') === key);
        } } }, label));
      }
      add(out, [panel(['Library ', h('span', { class: 'sub' }, plural(lib.length, 'signal'))], null, filter,
        table([{ label: 'Signal' }, { label: 'Built-in walk' }, { label: 'Kind' }, { label: 'View' }, { label: '' }], tbody),
        h('p', { class: 'sub' }, '"Declared only" signals are ordinary in honest servers; only a scenario statement can ask for them, for one place the operator says matters.'),
        h('p', { class: 'sub' }, KIND_SENTENCE))]);
    }
    if (Array.isArray(d.inspector_only)) {
      used.push('inspector_only');
      const kinds = isObj(d.signal_kinds) ? d.signal_kinds : {};
      add(out, [panel('Set by the inspector alone', 'not in the library: no walk and no statement asks for them',
        d.inspector_only.length ? table([{ label: 'Signal' }, { label: 'Kind' }], d.inspector_only.map((x) => [h('strong', null, mono(x)), kindTag(own(kinds, x))])) : h('p', { class: 'none' }, 'none'))]);
    }
    if (d.kind_meaning !== undefined || d.kinds !== undefined || d.signal_kinds !== undefined) {
      used.push('kind_meaning', 'kinds', 'signal_kinds');
      add(out, [panel('Evidence or heuristic', 'signals.Kind, in the code\'s own words: what one hit is — no severity, no verdict',
        typeof d.kind_meaning === 'string' ? textBlock(d.kind_meaning) : null,
        d.kinds !== undefined ? kv([['kinds', val(d.kinds)]]) : null)]);
    }
    if (d.surfaces !== undefined || d.metadata_surfaces !== undefined) {
      used.push('surfaces', 'metadata_surfaces');
      const meta = asList(d.metadata_surfaces).map(String);
      const surfaces = asList(d.surfaces);
      // [{surface, metadata}] (views.py) or a list of names beside metadata_surfaces.
      add(out, [panel('Surfaces', 'where in a server message the text sat', surfaces.length ? table([{ label: 'Surface' }, { label: 'Tool metadata' }], surfaces.map((s) => {
        const name = isObj(s) ? s.surface : s;
        const isMeta = isObj(s) ? s.metadata === true : meta.includes(String(s));
        return [mono(name), isMeta ? tag('pv-poison', 'metadata') : dash()];
      })) : val(d.surfaces))]);
    }
    if (isObj(d.walk)) {
      used.push('walk');
      add(out, [panel('The built-in walk', 'which surfaces it reads', val(d.walk))]);
    }
    const idKey = ['identity_fields', 'identities', 'locator_identities'].find((k) => d[k] !== undefined);
    if (idKey) {
      used.push(idKey);
      const idf = d[idKey];
      const pairs = isObj(idf) ? Object.entries(idf) : Array.isArray(idf) && idf.every(isObj) ? idf.map((x) => [x.list, x.field]) : null;
      add(out, [panel('Locators — a place that reads the same next run', 'paths.IDENTITY_FIELDS', pairs
        ? table([{ label: 'List' }, { label: 'Identity' }], pairs.map(([k, x]) => [mono(k), mono(jsonText(x))])) : val(idf))]);
    }
    const normKey = ['normalization', 'normalisation'].find((k) => d[k] !== undefined);
    if (normKey) {
      used.push(normKey);
      const norm = d[normKey];
      let body;
      if (Array.isArray(norm)) body = h('ol', { class: 'list' }, norm.map((x) => h('li', null, isObj(x) ? val(x) : h('span', { class: 'wire' }, String(x)))));
      else if (isObj(norm)) {
        body = frag(
          typeof norm.order === 'string' ? [h('h3', null, 'Order, in the code\'s own words (signals._flatten)'), textBlock(norm.order)] : null,
          typeof norm.normalize === 'string' ? [h('h3', null, 'signals.normalize'), textBlock(norm.normalize)] : null,
          norm.stripped !== undefined ? [h('h3', null, 'Stripped characters'), val(norm.stripped)] : null,
          others(norm, ['order', 'normalize', 'stripped']));
      } else body = val(norm);
      add(out, [panel('Normalisation — a second, readable copy', null, body)]);
    }
    const capKey = ['caps', 'limits'].find((k) => d[k] !== undefined);
    if (capKey) { used.push(capKey); add(out, [panel('Caps', 'the bounds the code works within', val(d[capKey]))]); }
    for (const [k, x] of Object.entries(rest(d, used.filter(Boolean)))) add(out, [panel(k, 'as given', val(x))]);
    return out;
  }

  // ---- triage ----------------------------------------------------------------------------

  // Where a row carried into the store came from (Store.triage_imports), or null for a row
  // written in it: a row whose origin is not shown is a row nobody can question.
  function importedFrom(row) {
    const im = isObj(row) && isObj(row.imported) ? row.imported : null;
    if (!im) return null;
    return sub('imported from store ', mono(short(String(im.store_sha256))), ' (schema ', mono(im.store_schema), ') at ', mono(im.at_utc));
  }

  // One role's current row (Store.triage_current), or none: the role has made no decision.
  function triageCell(row) {
    if (!isObj(row)) return h('span', { class: 'muted' }, 'no row');
    const im = importedFrom(row);
    return frag(tag(row.status === 'question' ? 't-warn' : 't-plain', String(row.status)),
      h('br'), sub('by ', h('span', { class: 'wire' }, String(row.author)), ' · ', mono(row.at_utc)), im ? [h('br'), im] : null);
  }

  function triageRows(list) {
    return table([{ label: 'Rows' }, { label: 'Role' }, { label: 'Status' }, { label: 'Author' }, { label: 'At (UTC)' }, { label: 'Supersedes' }, { label: 'Imported' }],
      list.filter(isObj).map((r) => [cellText(r.id), mono(r.role), tag(r.status === 'question' ? 't-warn' : 't-plain', String(r.status)),
        h('span', { class: 'wire' }, String(r.author)), cellText(r.at_utc), r.supersedes === null || r.supersedes === undefined ? dash() : mono(r.supersedes),
        importedFrom(r) || h('span', { class: 'muted' }, 'written here')]));
  }

  // A finding's rows in the order they were made, fetched when its details are opened.
  function historyOnDemand(finding) {
    const box = h('div', { class: 'stack' }, h('p', { class: 'sub' }, 'Loading…'));
    let loaded = false;
    const details = h('details', { on: { toggle: async () => {
      if (!details.open || loaded) return;
      loaded = true;
      const env = await api('store/triage/history', { finding });
      const d = isObj(env.data) ? env.data : null;
      box.replaceChildren(...[noticesTop(env), d ? (asList(d.history).length ? triageRows(asList(d.history)) : h('p', { class: 'none' }, 'no row: no decision has been recorded')) : null].filter(Boolean));
    } } }, h('summary', null, 'every row of this finding'), box);
    return details;
  }

  function triageTable(env, list, where) {
    const rows = asList(list).filter(isObj);
    if (!rows.length) return noneRecorded(env, where);
    const trs = [];
    for (const f of rows) {
      const t = isObj(f.triage) ? f.triage : {};
      trs.push([mono(f.finding), mono(f.finding_key), frag(mono(f.server), h('span', { class: 'muted' }, ' × '), mono(f.scenario)),
        frag(mono(f.statement), h('br'), mono(f.locator), h('br'), h('strong', null, mono(f.signal))), versionCell(f.server_version, f.server_version_kind, true),
        triageCell(t.operator), triageCell(t.customer), link('review', { finding: f.finding }, 'review mode')]);
      trs.push(rowNote(8, historyOnDemand(f.finding)));
    }
    return table([{ label: 'Finding' }, { label: 'Finding key' }, { label: 'Server × scenario' }, { label: 'Statement · locator · signal' }, { label: 'Server version' }, { label: 'Operator' }, { label: 'Customer' }, { label: '' }], trs);
  }

  function questionsTable(list) {
    const rows = asList(list).filter(isObj);
    return table([{ label: 'Finding' }, { label: 'Locator · signal' }, { label: 'Asked in the role of' }, { label: 'Party asked' }, { label: '' }],
      rows.map((q) => {
        const k = isObj(q.key) ? q.key : {}, r = isObj(q.row) ? q.row : {};
        return [mono(q.finding), frag(mono(k.locator), h('br'), h('strong', null, mono(k.signal))), mono(q.role), h('span', { class: 'wire' }, String(r.author)), link('review', { finding: q.finding }, 'review mode')];
      }));
  }

  async function pageTriage(p) {
    setTitle('Store · triage');
    const env = await api('store/triage');
    const out = await storeHead('store/triage', p, 'Each finding with every role\'s current decision beside it — the operator\'s and the customer\'s, neither overriding the other. Read-only: a decision is recorded with store triage set, never here.');
    add(out, [noticesTop(env)]);
    if (refusedWhole(env)) return out;
    const d = isObj(env.data) ? env.data : {};
    const questions = isObj(d.questions) ? d.questions : {};
    const open = [...asList(questions.reference), ...asList(questions.poison)];
    add(out, [panel('Open questions', 'current rows with status question, apart; real-world ones are under the candidates',
      open.length ? questionsTable(open) : h('p', { class: 'none' }, 'none: no current row is a question'))]);
    const findings = isObj(d.findings) ? d.findings : {};
    for (const prov of Object.keys(findings)) {
      add(out, [panel(['Findings · ', provTag(prov)], plural(asList(findings[prov]).length, 'finding') + (has(env, 'not_a_result', 'findings:' + prov) ? ' · not every run filed is a result, see the notice' : ''),
        noticesAt(env, 'findings:' + prov), triageTable(env, findings[prov], 'findings:' + prov))]);
    }
    const rw = asList(questions['real-world']);
    add(out, [panel(['Real-world candidates ', provTag('real-world')], 'candidates for disclosure, not results to publish',
      noticesAt(env, 'candidates'), triageTable(env, d.candidates, 'candidates'),
      rw.length ? [h('h3', null, 'Open questions about candidates'), questionsTable(rw)] : null)]);
    if (isObj(d.statuses)) {
      add(out, [h('details', null, h('summary', null, 'The statuses each role may set (store.TRIAGE_STATUSES)'),
        kv(Object.entries(d.statuses).map(([role, list]) => [role, h('span', { class: 'chips' }, asList(list).map((x) => code(x)))])))]);
    }
    return out;
  }

  // ---- review mode -----------------------------------------------------------------------

  const TEXT_STATUS = {
    recorded: null,
    not_located: 'the path does not lead to a value in the message as recorded',
    not_read: 'not read: the recording is not this run\'s, or not under --runs (see the notice)',
  };

  function placeText(pl) {
    if (pl.text_status === 'recorded') {
      const t = typeof pl.text === 'string' ? textBlock(pl.text) : jsonBlock(pl.text);
      return frag(t, pl.truncated ? tag('t-cap', 'the message was cut at the message limit') : null, pl.incomplete ? tag('t-cap', 'the message is recorded incomplete') : null);
    }
    if (pl.text_status === 'ambiguous') {
      // The path names more than one place in the message as recorded: every one is shown as a
      // candidate, none as the text the signal fired on.
      const cands = asList(pl.candidates);
      return frag(h('p', { class: 'inplace' }, 'ambiguous: the path names ', String(cands.length), pl.candidates_capped ? ' or more' : '', ' places in the message as recorded (a key holds a dot or a bracket); each is a candidate, none is picked'),
        h('ol', { class: 'list' }, cands.map((c) => h('li', null, typeof c === 'string' ? textBlock(c) : jsonBlock(c)))));
    }
    return h('p', { class: 'inplace' }, own(TEXT_STATUS, pl.text_status) || String(pl.text_status));
  }

  function rolePanel(role, row) {
    if (!isObj(row)) return panel(role, 'current row', h('p', { class: 'none' }, 'no row: the ' + role + ' has made no decision'));
    return panel(role, 'current row', h('div', { class: 'headrow' }, tag(row.status === 'question' ? 't-warn' : 't-plain', String(row.status))),
      kv([['author', h('span', { class: 'wire' }, String(row.author))], ['at (UTC)', mono(row.at_utc)], ['row', mono(row.id)], ['engagement digest', row.engagement_digest ? mono(short(row.engagement_digest)) : h('span', { class: 'muted' }, 'none')],
        ['imported from', isObj(row.imported) ? frag(sub('store ', mono(row.imported.store_sha256), ' of schema ', mono(row.imported.store_schema)), h('br'), sub('export ', mono(row.imported.file_sha256), ' · at ', mono(row.imported.at_utc))) : h('span', { class: 'muted' }, 'not imported: written in this store')]]));
  }

  function copyLine(line) {
    const text = isObj(line) && typeof line.text === 'string' ? line.text : '';
    const pre = h('pre', { class: 'copyline wire', tabindex: '0' }, vis(text, true));
    const said = h('span', { class: 'sub', 'aria-live': 'polite' });
    const button = h('button', { type: 'button', class: 'btn', on: { click: async () => {
      try { await navigator.clipboard.writeText(text); said.replaceChildren('copied'); } catch (e) { said.replaceChildren('not copied: select the line and copy it'); }
    } } }, 'Copy the line');
    return frag(pre, h('div', { class: 'headrow' }, button, said),
      h('p', { class: 'sub' }, 'Replace ', code('<STATUS>'), ' with one status and ', code('[NAME]'), ' with who says it, inside the single quotes. Nothing is recorded until the line is run; this page writes nothing.'),
      h('p', { class: 'sub' }, 'Inside single quotes nothing is live for the shell — no $, no backtick, no backslash; an apostrophe in the words is written ', code("'\\''"), '.'),
      kv([['statuses the customer may set', h('span', { class: 'chips' }, asList(line && line.statuses).map((x) => code(x)))], ['store, by its absolute path', mono(line && line.store)]]));
  }

  // Every row of the finding, behind a toggle that is off when the page opens and says which
  // it is: the current rows stand above, as store triage list prints them; the history is what
  // --history adds, there for the customer to ask for, never a second edition.
  function historyToggle(list) {
    const rows = asList(list).filter(isObj);
    if (!rows.length) return panel('History', 'both roles', h('p', { class: 'none' }, 'no row: no decision has been recorded'));
    const box = h('div', { id: 'review-history', hidden: true }, triageRows(rows));
    const state = h('span', { class: 'tag t-plain', 'aria-live': 'polite' }, 'history hidden');
    const button = h('button', { type: 'button', class: 'btn', 'aria-expanded': 'false', 'aria-controls': 'review-history', on: { click: () => {
      const show = box.hidden;
      box.hidden = !show;
      setState(button, 'aria-expanded', show ? 'true' : 'false');
      button.replaceChildren(show ? 'Hide the history' : 'Show the history');
      state.replaceChildren(show ? 'history shown' : 'history hidden');
    } } }, 'Show the history');
    return panel('History', plural(rows.length, 'row') + ' of both roles in the order they were made, the current ones and those a later row superseded',
      h('div', { class: 'headrow' }, state, button), box);
  }

  async function pageReview(p) {
    const finding = p.get('finding');
    setTitle('Review mode');
    const env = await api('store/triage/review', { finding });
    const out = frag(pageHead('Review mode', 'Finding ' + (finding === null ? '(none named)' : finding), 'One finding and nothing else of the store, to walk through with the customer. To leave, use the browser\'s back button.'));
    add(out, [noticesTop(env)]);
    const d = isObj(env.data) ? env.data : null;
    if (!d) return out;
    const k = isObj(d.key) ? d.key : {};
    const fc = isObj(d.finding_class) ? d.finding_class : null;
    add(out, [panel(['The finding ', provTag(d.provenance)], d.provenance === 'real-world' ? 'a candidate for disclosure, not a result to publish' : 'its key, as the store files it',
      kv([['server', mono(k.server)], ['server version', versionCell(k.server_version, k.server_version_kind)], ['scenario', mono(k.scenario)], ['statement', mono(k.statement)],
        ['locator', mono(k.locator)], ['signal', h('strong', null, mono(k.signal))], ['class', fc ? frag(mono(fc.id), ' ', String(fc.title)) : 'none: the signal is unknown to this version'], ['tool version', mono(k.tool_version)]]))]);
    const t = isObj(d.triage) ? d.triage : {};
    add(out, [h('div', { class: 'cols' }, rolePanel('operator', t.operator), rolePanel('customer', t.customer))]);
    add(out, [historyToggle(d.history)]);
    add(out, [panel('The line to copy', 'store triage set, for the customer\'s row', copyLine(d.line))]);
    const sightings = asList(d.sightings).filter(isObj);
    const parts = [noticesAt(env, 'sightings')];
    for (const s of sightings) {
      const st = own(RECORDING_STATUS, s.recording_status);
      parts.push(h('h3', null, 'Run ', mono(short(s.run)), ' ', stateChip(s.state), ' ', st ? tag(st[0], st[1]) : cellText(s.recording_status)));
      parts.push(kv([['server version', versionCell(s.server_version, s.server_version_kind, true)], ['isolation', isolationCell(s.isolation, s.egress_observed)], ['recording, as filed', mono(s.recording)]]));
      parts.push(noticesAt(env, 'sighting:' + s.run));
      const places = asList(s.places).filter(isObj);
      parts.push(places.length ? table([{ label: 'Path' }, { label: 'Message', num: true }, { label: 'The text recorded there' }],
        places.map((pl) => [frag(mono(pl.path), pl.normalized ? [h('br'), tag('t-info', 'normalized')] : null), mono('#' + pl.message_seq), placeText(pl)])) : h('p', { class: 'none' }, 'none shown'));
    }
    add(out, [panel('Where complete runs sighted it', 'only runs that are a result; the text as recorded, masked at write time',
      sightings.length ? parts : [parts[0], noneRecorded(env, 'sightings')])]);
    const named = asList(d.not_results).filter(isObj);
    if (named.length) {
      add(out, [panel('Runs that sighted it and are not a result', 'named, not sightings of a result',
        noticesAt(env, 'not_results'),
        table([{ label: 'Run' }, { label: 'State' }, { label: 'Exit', num: true }, { label: 'Causes' }, { label: 'Places', num: true }],
          named.map((r) => [mono(short(r.run)), stateChip(r.state), cellText(r.exit_code), causeKeys(r.causes), cellText(r.places)])))]);
    }
    return out;
  }

  // ---- evidence: bundles and attestations --------------------------------------------------

  // A download of a file this server checks and serves (api/bundle/file, api/attestation/file):
  // a relative same-origin URL whose parameters are encoded, never a URL from the data.
  function downloadLink(path, params, label) {
    if (path !== 'bundle/file' && path !== 'attestation/file') throw new Error('not a download of this page');
    const a = document.createElement('a');
    a.setAttribute('href', 'api/' + path + '?' + new URLSearchParams(params).toString());
    a.className = 'download';
    add(a, [label]);
    return a;
  }

  const FILE_STATE = { intact: 't-ok', changed: 't-grave', missing: 't-bad', unlisted: 't-warn' };
  function fileState(state) { return tag(own(FILE_STATE, state) || 't-plain', String(state)); }

  function bundleState(state) {
    if (state === 'intact') return tag('t-ok', 'intact');
    if (state === 'not_intact') return tag('t-grave', 'not intact');
    if (state === 'refused') return tag('t-bad', 'refused: its index cannot be read');
    return cellText(state);
  }

  async function pageEvidence() {
    setTitle('Evidence');
    const [benv, aenv] = await Promise.all([api('bundles'), api('attestations')]);
    const out = frag(pageHead('Evidence', 'Bundles and attestations', 'Each bundle given with --bundle, checked against its own index; each attestation given with --attestation, read back. Files are served for download only as they were checked.'));
    add(out, [noticesTop(benv)]);
    if (!refusedWhole(benv)) {
      const rows = asList(benv.data).filter(isObj);
      add(out, [panel('Bundles', null, rows.length ? table([{ label: '#', num: true }, { label: 'Directory' }, { label: 'State' }, { label: 'Engagement (declared)' }, { label: 'Made (UTC)' }, { label: 'Index digest' }],
        rows.map((r) => [cellText(r.index), link('bundle', { i: r.index }, mono(r.path)), frag(bundleState(r.bundle), r.words ? [h('br'), h('span', { class: 'sub wire' }, String(r.words))] : null),
          isObj(r.engagement) ? mono(r.engagement.engagement_id_declared) : dash(), cellText(r.created_utc), r.index_digest ? mono(short(r.index_digest)) : dash()])) : noneRecorded(benv, 'view'))]);
    }
    add(out, [noticesTop(aenv)]);
    if (!refusedWhole(aenv)) {
      const rows = asList(aenv.data).filter(isObj);
      add(out, [panel('Attestations', null, rows.length ? table([{ label: '#', num: true }, { label: 'File' }, { label: 'Reads back' }, { label: 'Engagement' }],
        rows.map((r) => [cellText(r.index), link('attestation', { i: r.index }, mono(r.path)), r.ok === true ? tag('t-ok', 'reads back') : frag(tag('t-bad', 'refused'), r.words ? [h('br'), h('span', { class: 'sub wire' }, String(r.words))] : null),
          r.engagement_id === null || r.engagement_id === undefined ? dash() : mono(r.engagement_id)])) : noneRecorded(aenv, 'view'))]);
    }
    return out;
  }

  async function pageBundle(p) {
    const i = p.get('i');
    setTitle('Bundle');
    const env = await api('bundle', { i });
    const d = isObj(env.data) ? env.data : null;
    const out = frag(pageHead('Evidence bundle', d ? d.path : 'Bundle ' + i, 'Checked against its own index now (evidence.verify). Only the files the index lists are served, only while the whole bundle is intact, and each one hashed again when it is served.', { mono: !!d }));
    add(out, [noticesTop(env)]);
    if (!d) return out;
    const e = isObj(d.engagement) ? d.engagement : {};
    add(out, [h('div', { class: 'cols' },
      panel('The bundle', null, h('div', { class: 'statebig' }, bundleState(d.bundle)), kv([
        ['index digest', mono(d.index_digest)], ['engagement (declared)', mono(e.engagement_id_declared)], ['engagement digest', mono(e.engagement_digest)],
        ['made (UTC)', mono(d.created_utc)], ['derived from', d.derived_from ? mono(d.derived_from) : h('span', { class: 'muted' }, 'none: packed from a store')],
        ['signature', d.signature ? h('span', { class: 'wire' }, String(d.signature)) : h('span', { class: 'muted' }, 'none present')],
        ['triage, as the index counts it', d.triage === null || d.triage === undefined ? h('span', { class: 'muted' }, 'not counted in this index') : val(d.triage)],
      ])),
      customerReadme(d.customer_readme))]);
    const roles = asList(d.roles).filter((r) => typeof r === 'string');
    const byRole = isObj(d.files_by_role) ? d.files_by_role : {};
    for (const role of [...roles, ...Object.keys(byRole).filter((r) => !roles.includes(r))]) {
      const files = asList(byRole[role]).filter(isObj);
      if (!files.length) continue;
      add(out, [panel(['Files · ', code(role)], plural(files.length, 'file'),
        table([{ label: 'Path' }, { label: 'State' }, { label: 'Size', num: true }, { label: 'SHA-256' }, { label: 'Download' }],
          files.map((f) => [mono(f.path), frag(fileState(f.state), f.note ? [h('br'), h('span', { class: 'sub wire' }, String(f.note))] : null), cellText(f.size), mono(short(f.sha256)),
            f.download === true ? downloadLink('bundle/file', { i: d.index, path: f.path }, 'download') : h('span', { class: 'muted' }, 'not served: the bundle is not intact')])))]);
    }
    const unlisted = asList(d.unlisted).filter(isObj);
    if (unlisted.length) {
      add(out, [panel('In the tree, not in the index', 'unlisted: never served', table([{ label: 'Path' }, { label: 'Note' }], unlisted.map((f) => [mono(f.path), f.note ? h('span', { class: 'wire' }, String(f.note)) : dash()])))]);
    }
    if (!isEmpty(d.problems)) add(out, [panel('Problems', 'what kept the check from seeing all of it', h('ul', { class: 'list' }, asList(d.problems).map((x) => h('li', { class: 'wire' }, x))))]);
    return out;
  }

  function customerReadme(r) {
    if (!isObj(r) || r.present === false) return panel('CUSTOMER-README.md', 'beside the index', h('p', { class: 'none' }, 'none beside the index'));
    const check = r.check ? tag('t-ok', String(r.check)) : r.problem ? frag(tag('t-bad', 'does not check'), h('br'), h('span', { class: 'sub wire' }, String(r.problem))) : tag('t-missing', 'not checked');
    return panel('CUSTOMER-README.md', 'beside the index, not covered by it', kv([['check', check]]),
      isObj(r.fields) ? val(r.fields) : h('p', { class: 'none' }, 'its names and numbers do not read back'));
  }

  async function pageAttestation(p) {
    const i = p.get('i');
    setTitle('Attestation');
    const env = await api('attestation', { i });
    const d = isObj(env.data) ? env.data : null;
    const out = frag(pageHead('Attestation', d ? d.path : 'Attestation ' + i, 'Read back through report.parse_attestation: what was done and not done, from recorded facts only. One that does not read back is not served.', { mono: !!d }));
    add(out, [noticesTop(env)]);
    if (!d) return out;
    add(out, [panel('The file', null, kv([['engagement', mono(d.engagement_id)], ['SHA-256', mono(d.sha256)], ['size', cellText(d.size)],
      ['download', d.downloadable === true ? downloadLink('attestation/file', { i: d.index }, 'download') : h('span', { class: 'muted' }, 'not served')]]))]);
    const items = asList(d.items).filter(isObj);
    add(out, [panel('What it says', 'each sentence with its kind', items.length ? h('div', { class: 'stack' }, items.map((it) => it.kind === 'heading'
      ? h('h3', null, h('span', { class: 'wire' }, String(it.text)))
      : h('p', null, code('[' + it.kind + ']'), ' ', h('span', { class: 'wire' }, String(it.text))))) : h('p', { class: 'none' }, 'no item'))]);
    return out;
  }

  // ---- about -----------------------------------------------------------------------------

  async function pageAbout() {
    setTitle('About');
    const env = await api('about');
    const out = frag(pageHead('About', 'A local, read-only viewer', 'It reads the sources given on the command line and nothing else on disk; it writes nothing, runs nothing and loads nothing from outside this machine.'));
    add(out, [noticesTop(env)]);
    if (refusedWhole(env)) return out;
    const d = isObj(env.data) ? env.data : {};
    add(out, [h('div', { class: 'cols' },
      panel('This version', null, kv([['package', mono(d.package)], ['version', mono(d.version)], ['recording schema', scalar(d.recording_schema)], ['store schema', scalar(d.store_schema)], ['rules', scalar(d.rules)], ['serving', mono(d.local)],
        ['isolations', d.isolations === undefined ? undefined : val(d.isolations)],
        ['egress observed under', d.observed_isolations === undefined ? undefined : frag(val(d.observed_isolations), h('br'), h('span', { class: 'sub' }, 'under every other isolation egress is not observed: no egress event in such a run means nothing'))]])),
      panel('Sources', 'each path, or null where it was not given', val(d.sources)))]);
    add(out, [others(d, ['package', 'version', 'recording_schema', 'store_schema', 'rules', 'local', 'sources', 'isolations', 'observed_isolations'])]);
    return out;
  }

  // ---- router ----------------------------------------------------------------------------

  const ROUTES = {
    '': pageRuns, runs: pageRuns, run: pageRun,
    store: pageStoreRuns, 'store/runs': pageStoreRuns, 'store/findings': pageStoreFindings,
    'store/candidates': pageStoreCandidates, 'store/diff': pageStoreDiff,
    fleets: pageFleets, fleet: pageFleet, 'fleets/compare': pageFleetCompare,
    corpus: pageCorpus, scenarios: pageScenarios, scenario: pageScenario,
    signals: pageSignals, about: pageAbout,
    'store/triage': pageTriage, review: pageReview,
    evidence: pageEvidence, bundle: pageBundle, attestation: pageAttestation,
  };
  const NAV_OF = {
    '': 'runs', runs: 'runs', run: 'runs', store: 'store', 'store/runs': 'store', 'store/findings': 'store',
    'store/candidates': 'store', 'store/diff': 'store', fleets: 'fleets', fleet: 'fleets', 'fleets/compare': 'fleets',
    corpus: 'corpus', scenarios: 'scenarios', scenario: 'scenarios', signals: 'signals', about: 'about',
    'store/triage': 'store', evidence: 'evidence', bundle: 'evidence', attestation: 'evidence',
  };

  function parseHash() {
    const raw = location.hash;
    if (raw === '' || raw === '#') return { path: '', params: new URLSearchParams() };
    if (!raw.startsWith('#/')) return null;
    const rest1 = raw.slice(2);
    const q = rest1.indexOf('?');
    return { path: q < 0 ? rest1 : rest1.slice(0, q), params: new URLSearchParams(q < 0 ? '' : rest1.slice(q + 1)) };
  }

  let drawn = 0;

  // What a view selects within itself (a row of the strip). An address that differs from the one
  // shown in these alone is the same place: where it names a row, the focus goes to that row and
  // not to the page's heading, and what the reader had open or scrolled to in the place stays.
  const PICK_PARAMS = ['st', 'obs'];
  let placeShown = null;

  function placeOf(r) {
    const q = new URLSearchParams(r.params);
    for (const name of PICK_PARAMS) q.delete(name);
    q.sort();
    return r.path + '?' + q.toString();
  }

  async function render(moveFocus) {
    const r = parseHash();
    if (!r) return;
    const gen = ++drawn;
    const place = placeOf(r);
    // Review mode shows one finding and nothing else: no navigation to any other entry.
    document.body.classList.toggle('review-mode', r.path === 'review');
    const nav = own(NAV_OF, r.path);
    for (const a of document.querySelectorAll('#nav a')) {
      if (a.getAttribute('data-route') === nav) setState(a, 'aria-current', 'page'); else a.removeAttribute('aria-current');
    }
    const main = document.getElementById('main');
    const samePlace = place === placeShown;
    tablesOpen = samePlace && !!main.querySelector('details.tables[open]');
    setState(main, 'aria-busy', 'true');
    main.removeAttribute('data-ready');
    let node;
    try {
      const fn = own(ROUTES, r.path);
      if (fn) node = await fn(r.params);
      else node = frag(pageHead('Not here', 'This page has no such view', null), h('p', null, 'The views are in the navigation.'));
    } catch (e) {
      node = frag(pageHead('Error', 'This view could not be drawn', null), noticeEl({ kind: 'page_error', text: String(e && e.message || e) }));
    }
    if (gen !== drawn) return;
    const stripWas = samePlace ? main.querySelector('table.strip') : null;
    const left = stripWas ? stripWas.parentElement.scrollLeft : 0;
    main.replaceChildren(node);
    // The strip stays where the reader scrolled it to, also after the focus went to a row of it.
    const stripNow = samePlace ? main.querySelector('table.strip') : null;
    const scrollBack = () => { if (stripNow) stripNow.parentElement.scrollLeft = left; };
    scrollBack();
    setState(main, 'aria-busy', 'false');
    setState(main, 'data-ready', String(gen));
    const picked = samePlace && PICK_PARAMS.some((name) => r.params.has(name)) ? main.querySelector('a.pick[aria-current="true"]') : null;
    placeShown = place;
    if (moveFocus) {
      const target = picked || main.querySelector('h1');
      if (target) target.focus({ preventScroll: false });
      scrollBack();
    }
  }

  function start() {
    document.getElementById('skip').addEventListener('click', () => document.getElementById('main').focus());
    window.addEventListener('hashchange', () => render(true));
    // The first view waits for /api/about: which isolations observe egress is its answer.
    loadAbout().then(() => render(false), () => render(false));
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
})();
