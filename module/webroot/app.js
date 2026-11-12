// SPDX-License-Identifier: GPL-3.0-or-later
// pinning-haters WebUI. Runs inside the KernelSU/APatch manager WebView; all device access goes
// through ksu.exec as root. Keys and accepted values mirror module/jni/config/config.cpp exactly.
'use strict';

const MOD = '/data/adb/modules/pinning_haters';
const DIR = '/data/adb/pinning_haters';
const CONFIG = DIR + '/config.json';
const LOG_DIR = DIR + '/log';
const TIERS = ['max', 'balanced', 'compat'];
// [path, default per config.cpp, title, description]
// surfaces.foreign_runtime (Unity IL2CPP, Mono) is left out: no backend exists yet, so the switch did nothing.
const ADV_TOGGLES = [
  ['surfaces.platform_tls', true, 'Platform TLS', 'Platform trust, Network Security Config pins, TrustKit, custom TrustManagers.'],
  ['surfaces.java_dex', true, 'Java pinning', 'OkHttp CertificatePinner and other checks that run after the handshake.'],
  ['surfaces.bundled_tls', true, 'Bundled TLS libraries', 'OpenSSL or BoringSSL shipped inside the app: curl, gRPC, Flutter.'],
  ['relax_hostname_verification', false, 'Relax hostname verification', 'Not pinning. Leave off unless your proxy certificate has the wrong name.'],
  ['aot.evict_oat', true, 'Evict compiled code', "Delete the app's compiled code before launch so DEX patches take effect. Slower app start."],
  ['aot.stat_hook_fallback', true, 'Compiled-code fallback', 'Hide compiled code in-process where it cannot be deleted.'],
  ['hide.self_remap', true, 'Hide the module mapping', "Remove the module's path from the app's memory map."],
];
const LOG_TOGGLES = [
  ['log.enabled', false, 'Record logs', 'One root-only file per app launch, kept 7 days.'],
  ['log.verbose', false, 'Verbose', 'Include debug lines.'],
];

const $ = (id) => document.getElementById(id);
let cfg = normalize({});
let apps = new Map();        // package -> { label, version }
const expanded = new Set();  // targeted apps whose settings are open; survives re-renders
let logLines = [];

// ---- shell bridge --------------------------------------------------------------------------

let seq = 0;
function exec(cmd) {
  return new Promise((resolve, reject) => {
    if (!window.ksu) return reject(new Error('no shell bridge'));
    const cb = 'ph_cb_' + (seq++);
    window[cb] = (code, stdout, stderr) => {
      delete window[cb];
      if (code === 0) resolve(stdout); else reject(new Error(stderr || stdout || 'exit ' + code));
    };
    ksu.exec(cmd, '{}', cb);
  });
}

function toast(msg, isErr) {
  $('status').textContent = msg;
  $('status').classList.toggle('err', !!isErr);
  if (window.ksu) try { ksu.toast(msg); } catch (_) { /* older managers lack toast */ }
}

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

// ---- config ----------------------------------------------------------------------------------

function isObj(v) { return !!v && typeof v === 'object' && !Array.isArray(v); }

// Only guarantee the containers we edit exist; everything else in the file is preserved verbatim.
function normalize(c) {
  c = isObj(c) ? c : {};
  for (const k of ['packages', 'surfaces', 'aot', 'log', 'hide']) if (!isObj(c[k])) c[k] = {};
  if (!TIERS.includes(c.stealth)) c.stealth = 'max';
  for (const name of Object.keys(c.packages)) {
    if (!isObj(c.packages[name])) c.packages[name] = {};
    if ('stealth' in c.packages[name] && !TIERS.includes(c.packages[name].stealth)) delete c.packages[name].stealth;
  }
  return c;
}

function getPath(p) { const [a, b] = p.split('.'); return b === undefined ? cfg[a] : cfg[a][b]; }
function setPath(p, v) { const [a, b] = p.split('.'); if (b === undefined) cfg[a] = v; else cfg[a][b] = v; }
function markDirty() { $('save').classList.add('dirty'); }

async function loadConfig() {
  let text = null;
  try { text = await exec('cat ' + CONFIG); } catch (_) { /* missing file: defaults */ }
  if (text === null) {
    cfg = normalize({});
  } else {
    try { cfg = normalize(JSON.parse(text)); }
    catch (_) { cfg = normalize({}); toast('config.json is not valid JSON; Save will replace it', true); }
  }
  render();
}

async function saveConfig() {
  cfg.version = 2;
  const json = JSON.stringify(cfg, null, 2) + '\n';
  const b64 = btoa(unescape(encodeURIComponent(json)));  // base64 alphabet is shell-safe inside ''
  const tmp = CONFIG + '.tmp';
  try {
    await exec(`mkdir -p ${DIR} && echo '${b64}' | base64 -d > ${tmp} && chmod 600 ${tmp} && mv ${tmp} ${CONFIG}`);
    $('save').classList.remove('dirty');
    toast(Object.keys(cfg.packages).length
      ? 'Saved. Force-stop and reopen the app to apply; no reboot.'
      : 'Saved. No app targeted: the module is inert.');
  } catch (e) {
    toast('Save failed: ' + e.message, true);
  }
}

// ---- render --------------------------------------------------------------------------------

function render() {
  $('tier').value = cfg.stealth;
  renderTargets();
  renderResults();
  renderToggles($('adv-toggles'), ADV_TOGGLES);
  renderToggles($('log-toggles'), LOG_TOGGLES);
  renderLogState();
}

function renderLogState() { $('log-state').textContent = getPath('log.enabled') === true ? 'on' : 'off'; }

function renderToggles(ul, defs) {
  ul.textContent = '';
  for (const [path, def, title, desc] of defs) {
    const cur = getPath(path);
    const cb = el('input', 'switch');
    cb.type = 'checkbox';
    cb.checked = typeof cur === 'boolean' ? cur : def;
    cb.onchange = () => { setPath(path, cb.checked); markDirty(); renderLogState(); };
    const text = el('span');
    text.append(el('b', '', title), el('small', '', desc));
    const label = el('label', 'toggle');
    label.append(text, cb);
    const li = el('li');
    li.append(label);
    ul.append(li);
  }
}

// ---- apps ------------------------------------------------------------------------------------

// Labels, versions and icons come from a small helper run under app_process as root, because
// managers differ in what their WebView offers. Without it the list falls back to package names.
async function loadApps() {
  const all = $('sys').checked;
  try {
    // cd /: app_process on Android 11 crashes at startup when the shell's directory no longer exists.
    const out = await exec(`cd / && /system/bin/app_process -Djava.class.path=${MOD}/apps.dex /system/bin ph.Apps ${MOD}/webroot/icons${all ? ' all' : ''}`);
    apps = new Map(out.split('\n').filter((l) => l.includes('\t')).map((l) => {
      const [pkg, , version, label] = l.split('\t');
      return [pkg, { label: label || pkg, version }];
    }));
    if (!apps.size) throw new Error('empty app list');
  } catch (_) {
    try {
      const out = await exec('pm list packages' + (all ? '' : ' -3'));
      apps = new Map(out.split('\n').map((l) => l.replace(/^package:/, '').trim()).filter(Boolean).map((p) => [p, { label: p, version: '' }]));
    } catch (e) {
      apps = new Map();
      toast('Cannot list apps: ' + e.message, true);
    }
  }
  renderTargets();
  renderResults();
}

const labelOf = (pkg) => (apps.has(pkg) ? apps.get(pkg).label : pkg);
const byLabel = (a, b) => labelOf(a).localeCompare(labelOf(b));
// Case- and accent-insensitive, so "itau" finds "Itaú".
const fold = (s) => s.normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase();

// Icon + name + version + package; the caller appends its own trailing control.
function appRow(pkg) {
  const app = apps.get(pkg);
  const label = labelOf(pkg);
  const img = el('img', 'icon');
  img.alt = '';
  img.loading = 'lazy';
  img.onerror = () => img.replaceWith(el('span', 'icon letter', (label === pkg ? pkg.split('.').pop() : label).charAt(0).toUpperCase()));
  img.src = 'icons/' + pkg + '.png';
  const meta = el('span', 'meta');
  if (label === pkg) {
    meta.append(el('span', 'mono', pkg));
  } else {
    const title = el('span');
    title.append(el('b', '', label), el('small', '', app.version));
    meta.append(title, el('small', 'mono', pkg));
  }
  return [img, meta];
}

function validRedirect(v) {
  const m = v.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}):(\d{1,5})$/);
  return !!m && m.slice(1, 5).every((o) => +o <= 255) && +m[5] >= 1 && +m[5] <= 65535;
}

function field(caption, control, hint) {
  const f = el('div', 'field');
  f.append(caption, control);
  if (hint) f.append(el('p', 'hint', hint));
  return f;
}

function infoButton(dialog, label) {
  const b = el('button', 'info', 'i');
  b.type = 'button';
  b.dataset.dialog = dialog;
  b.setAttribute('aria-label', label);
  return b;
}

function renderTargets() {
  const names = Object.keys(cfg.packages).sort(byLabel);
  const ul = $('targets');
  ul.textContent = '';
  $('empty').hidden = names.length > 0;
  for (const name of names) {
    const rule = cfg.packages[name];
    const chips = el('span', 'chips');
    const fillChips = () => {
      chips.textContent = '';
      if (rule.stealth) chips.append(el('span', 'chip', rule.stealth));
      if (rule.redirect) chips.append(el('span', 'chip', 'proxy'));
    };
    fillChips();
    const summary = el('summary', 'approw');
    summary.append(...appRow(name), chips);

    const sel = el('select');
    sel.setAttribute('aria-label', 'Stealth tier for ' + name);
    sel.append(new Option('default (' + cfg.stealth + ')', ''));
    for (const t of TIERS) sel.append(new Option(t, t));
    sel.value = rule.stealth || '';
    sel.onchange = () => { if (sel.value) rule.stealth = sel.value; else delete rule.stealth; fillChips(); markDirty(); };
    const tierCap = el('span', 'cap', 'Stealth tier');
    tierCap.append(infoButton('tier-info', 'About stealth tiers'));

    // Optional: send this app's TCP 443 to a proxy listener (apps that ignore the system proxy).
    const rd = el('input');
    rd.type = 'text';
    rd.placeholder = '192.168.1.10:8080';
    rd.autocapitalize = 'off';
    rd.spellcheck = false;
    rd.setAttribute('aria-label', 'Redirect TCP 443 of ' + name + ' to a proxy at ip:port');
    rd.value = rule.redirect || '';
    rd.onchange = () => {
      const v = rd.value.trim();
      if (v && !validRedirect(v)) { rd.value = rule.redirect || ''; return toast('Proxy redirect must be <ipv4>:<port>', true); }
      if (v) rule.redirect = v; else delete rule.redirect;
      fillChips();
      markDirty();
    };

    const redirectCap = el('span', 'cap', 'Proxy redirect');
    redirectCap.append(infoButton('redirect-info', 'About the proxy redirect'));

    const rm = el('button', 'danger', 'Remove');
    rm.type = 'button';
    rm.setAttribute('aria-label', 'Remove ' + name);
    rm.onclick = () => { delete cfg.packages[name]; expanded.delete(name); markDirty(); renderTargets(); renderResults(); };

    const body = el('div', 'body');
    body.append(
      field(tierCap, sel),
      field(redirectCap, rd, 'The proxy must accept TLS directly. Burp: enable "Support invisible proxying" on the listener.'),
      rm);
    const d = el('details', 'app');
    d.open = expanded.has(name);
    d.ontoggle = () => { if (d.open) expanded.add(name); else expanded.delete(name); };
    d.append(summary, body);
    const li = el('li');
    li.append(d);
    ul.append(li);
  }
}

function renderResults() {
  const raw = $('search').value.trim();
  const q = fold(raw);
  const ul = $('results');
  ul.textContent = '';
  $('results-wrap').hidden = !q;
  if (!q) return;
  const add = (pkg, action) => {
    const b = el('button', 'approw');
    b.type = 'button';
    b.disabled = !!cfg.packages[pkg];
    b.append(...appRow(pkg), el('span', 'act', b.disabled ? 'Added' : action));
    b.onclick = () => addPackage(pkg);
    const li = el('li');
    li.append(b);
    ul.append(li);
  };
  const hits = [...apps.keys()].filter((p) => fold(p).includes(q) || fold(labelOf(p)).includes(q)).sort(byLabel);
  for (const p of hits.slice(0, 50)) add(p, 'Add');
  if (hits.length > 50) ul.append(el('li', 'hint', (hits.length - 50) + ' more; keep typing'));
  // A package that is not in the list (not installed yet, or a system app) can still be added by name.
  if (!apps.has(raw) && /^[\w$]+(\.[\w$]+)+$/.test(raw)) add(raw, 'Add by name');
  if (!ul.children.length) ul.append(el('li', 'hint', 'No matches'));
}

function addPackage(name) {
  if (cfg.packages[name]) return;
  cfg.packages[name] = {};
  expanded.add(name);
  $('search').value = '';
  markDirty();
  renderTargets();
  renderResults();
  toast('Added ' + labelOf(name) + '; press Save');
}

// ---- log viewer ------------------------------------------------------------------------------

async function loadLogList() {
  const sel = $('log-file');
  const prev = sel.value;
  sel.textContent = '';
  let files = [];
  try {
    files = (await exec('ls -t ' + LOG_DIR)).split('\n').map((s) => s.trim()).filter((f) => /^[\w.-]+\.log$/.test(f));
  } catch (_) { /* no log dir yet */ }
  // companion.log is appended on every launch so mtime always ranks it first; keep the per-launch logs on top.
  const hasCompanion = files.includes('companion.log');
  files = files.filter((f) => f !== 'companion.log');
  if (hasCompanion) files.push('companion.log');
  for (const f of files) sel.append(new Option(f, f));
  if (!files.length) {
    sel.append(new Option('No logs yet (enable logging, Save, then launch the app)', ''));
    logLines = [];
    renderLog();
    return;
  }
  sel.value = files.includes(prev) ? prev : files[0];
  loadLog();
}

async function loadLog() {
  const f = $('log-file').value;
  if (!f) return;
  try {
    logLines = (await exec('cat ' + LOG_DIR + '/' + f)).split('\n');
    if (logLines[logLines.length - 1] === '') logLines.pop();
  } catch (e) {
    logLines = ['cannot read ' + f + ': ' + e.message];
  }
  renderLog();
}

// Line format (companion.cpp + log.cpp):
//   [ts] [LEVEL] [coverage] surface=<name> present=yes|no reachable=yes|no key=value ...
function lineClass(line) {
  if (!line.includes('[coverage]')) return 'line';
  if (line.includes('reachable=no')) return 'line cov cov-warn';
  if (line.includes('reachable=yes')) return 'line cov cov-ok';
  if (line.includes('present=no')) return 'line cov cov-dim';
  return 'line cov';
}

// One launch at a glance, computed here from the coverage lines rather than logged by the module:
// the target process does no extra work for it. A surface can be reached in one library and not in
// another (a static BoringSSL in two libraries), so both lists can name it.
function summarize(lines) {
  const reached = new Map(), blocked = new Map();
  let warnings = 0;
  for (const line of lines) {
    if (/\[(WARN |ERROR)\]/.test(line)) warnings++;
    const m = line.match(/\[coverage\] surface=(\S+) (.*)$/);
    if (!m || m[2].startsWith('present=no')) continue;
    const [, surface, rest] = m;
    const field = (k) => (rest.match(new RegExp('(?:^| )' + k + '=(\\S+)')) || [])[1];
    if (rest.includes('reachable=yes')) {
      reached.set(surface, (reached.get(surface) || 0) + 1);
    } else if (rest.includes('reachable=no')) {
      const why = [field('reason'), field('required_tier') && 'needs ' + field('required_tier'), field('lib')].filter(Boolean).join(', ');
      const list = blocked.get(surface) || [];
      if (why && !list.includes(why)) list.push(why);
      blocked.set(surface, list);
    }
  }
  return { reached, blocked, warnings };
}

function renderSummary() {
  const box = $('log-summary');
  box.textContent = '';
  if (!logLines.some((l) => l.includes('[coverage]'))) return;
  const { reached, blocked, warnings } = summarize(logLines);
  const row = (label, cls, items) => {
    const p = el('p');
    p.append(el('b', cls, label + ' '), items.length ? items.join(' · ') : 'none');
    box.append(p);
  };
  row('Reached:', 'cov-ok', [...reached.keys()]);
  row('Present, not reached:', 'cov-warn', [...blocked].map(([s, why]) => (why.length ? s + ' (' + why.join('; ') + ')' : s)));
  if (warnings) row('Warnings:', 'cov-warn', [warnings + ' WARN/ERROR line' + (warnings > 1 ? 's' : '') + '; filter on WARN']);
}

function renderLog() {
  renderSummary();
  const q = $('log-filter').value.trim().toLowerCase();
  const view = $('log-view');
  view.textContent = '';
  const frag = document.createDocumentFragment();
  let shown = 0;
  for (const line of logLines) {
    if (q && !line.toLowerCase().includes(q)) continue;
    shown++;
    const d = el('div', lineClass(line));
    if (d.className.includes('cov-warn')) {
      // required_tier=<x> is the value to put in the package's stealth override; make it jump out.
      line.split(/(required_tier=\S+)/).forEach((part, i) => d.append(i % 2 ? el('b', '', part) : part));
    } else {
      d.textContent = line;
    }
    frag.append(d);
  }
  if (!shown) frag.append(el('div', 'hint', logLines.length ? 'No lines match the filter' : 'Empty'));
  view.append(frag);
}

async function copyLog() {
  const text = logLines.join('\n');
  if (!text) return toast('Nothing to copy');
  try {
    await navigator.clipboard.writeText(text);
    toast('Copied');
  } catch (_) {
    // navigator.clipboard needs a secure context; the WebView may not grant one.
    const ta = el('textarea');
    ta.value = text;
    document.body.append(ta);
    ta.select();
    toast(document.execCommand('copy') ? 'Copied' : 'Copy failed', false);
    ta.remove();
  }
}

// ---- wiring ----------------------------------------------------------------------------------

function init() {
  if (!window.ksu) {
    $('nobridge').hidden = false;
    $('save').disabled = true;
  }
  $('tier').onchange = () => {
    const next = $('tier').value;
    $('tier-confirm').hidden = next === cfg.stealth;
    $('tier-next').textContent = next;
  };
  $('tier-ok').onclick = () => { cfg.stealth = $('tier').value; $('tier-confirm').hidden = true; markDirty(); renderTargets(); };
  $('tier-cancel').onclick = () => { $('tier').value = cfg.stealth; $('tier-confirm').hidden = true; };
  $('search').oninput = renderResults;
  $('sys').onchange = loadApps;
  // (i) buttons, including the ones rendered per app, open the dialog they name.
  document.addEventListener('click', (e) => {
    const b = e.target.closest('button[data-dialog]');
    if (b) $(b.dataset.dialog).showModal();
    else if (e.target.tagName === 'DIALOG') e.target.close();  // tap on the backdrop
  });
  $('logs').ontoggle = () => { if ($('logs').open) loadLogList(); };
  $('log-file').onchange = loadLog;
  $('log-refresh').onclick = loadLogList;
  $('log-copy').onclick = copyLog;
  $('log-filter').oninput = renderLog;
  $('save').onclick = saveConfig;
  exec(`sed -n 's/^version=//p' ${MOD}/module.prop`).then((v) => { $('version').textContent = v.trim(); }, () => {});
  loadConfig().then(loadApps);
}

init();
