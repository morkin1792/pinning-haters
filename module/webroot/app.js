// SPDX-License-Identifier: GPL-3.0-or-later
// pinning-haters WebUI. Runs inside the KernelSU/APatch manager WebView; all device access goes
// through ksu.exec as root. Keys and accepted values mirror module/jni/config/config.cpp exactly.
'use strict';

const DIR = '/data/adb/pinning_haters';
const CONFIG = DIR + '/config.json';
const LOG_DIR = DIR + '/log';
const TIERS = ['max', 'balanced', 'compat'];
// [path, default per config.cpp, description]
const ADV_TOGGLES = [
  ['surfaces.platform_tls', true, "Wrap conscrypt's verify callback: platform trust, Network Security Config pins, TrustKit, custom TrustManagers."],
  ['surfaces.java_dex', true, 'Patch DEX bytecode at verification time: OkHttp CertificatePinner and other post-handshake pinning.'],
  ['surfaces.bundled_tls', true, 'TLS libraries the app bundles itself: GOT hooks on OpenSSL/BoringSSL consumers (curl, gRPC) and the Flutter libflutter.so pointer swap.'],
  ['surfaces.foreign_runtime', false, 'Unity IL2CPP and Mono. Nothing installable yet (Phase 2). Flutter pin plugins are Java targets under java_dex.'],
  ['relax_hostname_verification', false, 'Also disable hostname verification. Not pinning; leave off unless your proxy certificate has the wrong name.'],
  ['aot.evict_oat', true, "Delete the package's compiled oat artifacts before launch so DEX patches take effect. Slower app start."],
  ['hide.self_remap', true, "Re-map this module's own pages anonymously after hooking, so the module path is gone from /proc/self/maps. Leaves the host's libzygisk.so alone."],
  ['aot.stat_hook_fallback', true, 'In-process stat hook in an ART library for when eviction cannot happen (read-only paths, DEX loaded mid-run).'],
];
const LOG_TOGGLES = [
  ['log.enabled', false, 'Write one log per app launch to ' + LOG_DIR + ' (root-only, rotated after 7 days / 100 MB).'],
  ['log.verbose', false, 'Include debug-level lines.'],
];

const $ = (id) => document.getElementById(id);
let cfg = normalize({});
let installed = [];
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
    if (window.ksu) toast('No config yet; showing defaults');
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
    toast(Object.keys(cfg.packages).length ? 'Saved' : 'Saved (no packages: module is inert)');
  } catch (e) {
    toast('Save failed: ' + e.message, true);
  }
}

// ---- render --------------------------------------------------------------------------------

function render() {
  renderTier();
  renderPackages();
  renderToggles($('adv-toggles'), ADV_TOGGLES);
  renderToggles($('log-toggles'), LOG_TOGGLES);
}

function renderTier() {
  $('tier-now').textContent = cfg.stealth;
  $('tier').value = cfg.stealth;
  for (const li of document.querySelectorAll('.tiers li')) {
    if (li.dataset.tier === cfg.stealth) li.setAttribute('aria-current', 'true'); else li.removeAttribute('aria-current');
  }
  renderPackages();  // "inherit (max)" labels follow the global tier
}

function renderPackages() {
  const names = Object.keys(cfg.packages).sort();
  const ul = $('pkg-list');
  ul.textContent = '';
  $('pkg-empty').hidden = names.length > 0;
  for (const name of names) {
    const rule = cfg.packages[name];
    const sel = el('select');
    sel.setAttribute('aria-label', 'Stealth tier for ' + name);
    sel.append(new Option('inherit (' + cfg.stealth + ')', ''));
    for (const t of TIERS) sel.append(new Option(t, t));
    sel.value = rule.stealth || '';
    sel.onchange = () => { if (sel.value) rule.stealth = sel.value; else delete rule.stealth; markDirty(); };
    const rm = el('button', 'ghost', 'Remove');
    rm.type = 'button';
    rm.setAttribute('aria-label', 'Remove ' + name);
    rm.onclick = () => { delete cfg.packages[name]; markDirty(); renderPackages(); renderPicker(); };
    const li = el('li', 'item');
    li.append(el('span', 'name mono', name), sel, rm);
    ul.append(li);
  }
}

function addPackage(name) {
  name = name.trim();
  if (!name) return;
  if (!/^[\w$]+(\.[\w$]+)*$/.test(name)) return toast('Not a valid package name: ' + name, true);
  if (cfg.packages[name]) return toast(name + ' is already listed');
  cfg.packages[name] = {};
  markDirty();
  renderPackages();
  renderPicker();
  toast('Added ' + name + '; press Save to apply');
}

function renderToggles(ul, defs) {
  ul.textContent = '';
  for (const [path, def, desc] of defs) {
    const cur = getPath(path);
    const cb = el('input');
    cb.type = 'checkbox';
    cb.checked = typeof cur === 'boolean' ? cur : def;
    cb.onchange = () => { setPath(path, cb.checked); markDirty(); };
    const text = el('span');
    text.append(el('b', '', path), el('small', '', desc));
    const label = el('label', 'toggle');
    label.append(cb, text);
    const li = el('li');
    li.append(label);
    ul.append(li);
  }
}

// ---- package picker --------------------------------------------------------------------------

async function loadInstalled() {
  const ul = $('pick-list');
  ul.textContent = '';
  ul.append(el('li', 'hint', 'Loading...'));
  try {
    const out = await exec('pm list packages' + ($('pick-all').checked ? '' : ' -3'));
    installed = out.split('\n').map((l) => l.replace(/^package:/, '').trim()).filter(Boolean).sort();
  } catch (e) {
    installed = [];
    toast('pm list packages failed: ' + e.message, true);
  }
  renderPicker();
}

function renderPicker() {
  const q = $('pick-filter').value.trim().toLowerCase();
  const ul = $('pick-list');
  ul.textContent = '';
  const shown = installed.filter((p) => !cfg.packages[p] && p.toLowerCase().includes(q));
  for (const p of shown.slice(0, 200)) {
    const b = el('button', 'pick', p);
    b.type = 'button';
    b.onclick = () => addPackage(p);
    const li = el('li');
    li.append(b);
    ul.append(li);
  }
  if (shown.length > 200) ul.append(el('li', 'hint', (shown.length - 200) + ' more; narrow the filter'));
  if (!shown.length && installed.length) ul.append(el('li', 'hint', 'No matches'));
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
  $('tier-ok').onclick = () => { cfg.stealth = $('tier').value; $('tier-confirm').hidden = true; markDirty(); renderTier(); };
  $('tier-cancel').onclick = () => { $('tier').value = cfg.stealth; $('tier-confirm').hidden = true; };
  $('pkg-add').onsubmit = (e) => { e.preventDefault(); addPackage($('pkg-name').value); $('pkg-name').value = ''; };
  $('picker').ontoggle = () => { if ($('picker').open && !installed.length) loadInstalled(); };
  $('pick-all').onchange = loadInstalled;
  $('pick-filter').oninput = renderPicker;
  $('log-file').onchange = loadLog;
  $('log-refresh').onclick = loadLogList;
  $('log-copy').onclick = copyLog;
  $('log-filter').oninput = renderLog;
  $('save').onclick = saveConfig;
  loadConfig().then(loadLogList);
}

init();
