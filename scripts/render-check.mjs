// Render the built explorer in jsdom and fail on any console error / exception.
//
// The page is data-driven and must survive datasets that lack circuits or lack the
// v4 bucket data (a censored cell, or any pre-v4 run), so run this against BOTH a
// v4 run dir and an older one before publishing. It has already caught a hardcoded
// default circuit that crashed every chart on datasets without it.
// Also exercises the cost-basis switch and each chart's own controls, since the
// bug class we care about (a chart reading a bucket that isn't there) only shows
// up when a draw function actually runs.
import fs from 'fs';
// jsdom is a dev-only dependency and deliberately not vendored: install it into a
// scratch dir and point JSDOM_PATH at it.
//   npm install --no-audit --no-fund jsdom
//   JSDOM_PATH=$PWD/node_modules/jsdom/lib/api.js node scripts/render-check.mjs <page.html>
const jsdomPath = process.env.JSDOM_PATH || 'jsdom';
const { JSDOM, VirtualConsole } = await import(jsdomPath);

const file = process.argv[2];
const errors = [];
const vc = new VirtualConsole();
vc.on('jsdomError', e => errors.push('jsdomError: ' + (e.stack || e.message)));
vc.on('error', (...a) => errors.push('console.error: ' + a.join(' ')));

const dom = new JSDOM(fs.readFileSync(file, 'utf8'), {
  runScripts: 'dangerously', pretendToBeVisual: true, virtualConsole: vc,
});
const { window } = dom;
await new Promise(r => window.addEventListener('load', r, { once: true }));

const $ = s => window.document.querySelector(s);
const click = el => { if (!el) return; el.dispatchEvent(new window.MouseEvent('click', { bubbles: true })); };

function step(name, fn) {
  const before = errors.length;
  try { fn(); } catch (e) { errors.push(`${name} threw: ${e.stack || e.message}`); }
  if (errors.length > before) console.log(`  ✗ ${name}`);
  else console.log(`  ✓ ${name}`);
}

step('initial render', () => {});
step('basis -> with setup', () => click($('#basis-mode button[data-v="withsetup"]')));
step('basis -> per proof', () => click($('#basis-mode button[data-v="perproof"]')));
step('matrix non-ZK', () => click($('#mx-zk button[data-v="nonzk"]')));
step('phase bars non-ZK', () => click($('#pb-zk button[data-v="nonzk"]')));
step('sweep family sha256', () => {
  const sel = $('#sweep-family'); sel.value = 'sha256';
  sel.dispatchEvent(new window.Event('change', { bubbles: true }));
});
step('sweep non-ZK', () => click($('#sweep-zk button[data-v="nonzk"]')));
step('explorer tier antipodal', () => click($('#exp-tier button[data-v="antipodal"]')));
step('explorer circuit cycle', () => {
  const sel = $('#exp-circuit');
  for (const o of [...sel.options]) {
    sel.value = o.value;
    sel.dispatchEvent(new window.Event('change', { bubbles: true }));
  }
});
step('dist circuit cycle', () => {
  const sel = $('#dist-circuit');
  for (const o of [...sel.options]) {
    sel.value = o.value;
    sel.dispatchEvent(new window.Event('change', { bubbles: true }));
  }
});
step('K toggle prove only', () => click($('#k-pk button[data-v="excl"]')));
step('basis -> with setup (all charts again)', () => click($('#basis-mode button[data-v="withsetup"]')));

// Sanity: the key panels rendered non-empty content.
const checks = {
  '#mx-table': 'matrix table',
  '#exp-svg': 'explorer bars',
  '#sweep-svg': 'sweep chart',
  '#pb-poseidon': 'poseidon phase bars',
  '#comms-table': 'comms table',
  '#basis-mode': 'basis control',
};
for (const [sel, label] of Object.entries(checks)) {
  const el = $(sel);
  const len = el ? (el.innerHTML || '').length : -1;
  console.log(`  ${len > 40 ? '✓' : '✗'} ${label} rendered (${len} chars)`);
  if (len <= 40) errors.push(`${label} (${sel}) rendered empty`);
}

if (errors.length) {
  console.log(`\n${errors.length} PROBLEM(S):`);
  for (const e of [...new Set(errors)].slice(0, 12)) console.log(' - ' + e.slice(0, 400));
  process.exit(1);
}
console.log('\nrender check: PASS');
