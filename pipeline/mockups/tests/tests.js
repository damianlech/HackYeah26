// UI + logic checks for pipeline-builder.html (Clearance mockup), run in headless Chromium via Playwright.
// Usage: NODE_PATH=$(npm root -g) node tests.js   (optional: PAGE=/path/to/pipeline-builder.html, FONTS_DIR=/dir/with/fonts.css)
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { chromium } = require('playwright');

const PAGE = process.env.PAGE || path.resolve(__dirname, '..', 'pipeline-builder.html');
const EXAMPLE = process.env.EXAMPLE || path.resolve(path.dirname(PAGE), '..', 'pipeline.example.yaml');
const FONTS_DIR = process.env.FONTS_DIR || '';
const FONT_URL = /^https:\/\/fonts\.(googleapis|gstatic)\.com\//;
let fails = 0, passes = 0, fontTrouble = false;
const ok = (cond, msg) => { if (cond) passes++; else fails++; console.log((cond ? 'PASS ' : 'FAIL ') + msg); };

function wrappedUrl() {
  // The artifact host adds the document skeleton; tests wrap a temp copy the same way. The real file stays doctype-free.
  const out = path.join(os.tmpdir(), 'clearance-pipeline-builder-wrapped.html');
  fs.writeFileSync(out, '<!doctype html><html><head><meta charset="utf-8"></head><body>' + fs.readFileSync(PAGE, 'utf8') + '</body></html>');
  return 'file://' + out;
}
async function open(browser, { width = 1440, height = 900, scheme = 'light', reduced = true, hash = '' } = {}) {
  const context = await browser.newContext({ viewport: { width, height }, colorScheme: scheme, reducedMotion: reduced ? 'reduce' : 'no-preference' });
  const page = await context.newPage();
  const errors = [], external = [];
  page.on('console', m => {
    if (m.type() !== 'error' && m.type() !== 'warning') return;
    if (FONT_URL.test((m.location() || {}).url || '')) { fontTrouble = true; return; }   // network trouble reaching Google Fonts is not a page bug
    errors.push(m.type() + ': ' + m.text());
  });
  page.on('pageerror', e => errors.push('pageerror: ' + e.message));
  await page.route('**/*', route => {
    const u = route.request().url();
    if (u.startsWith('file://')) return route.continue();
    if (u.startsWith('https://fonts.googleapis.com/') || u.startsWith('https://fonts.gstatic.com/')) {
      if (!FONTS_DIR) return route.continue();
      if (u.startsWith('https://fonts.googleapis.com/')) return route.fulfill({ status: 200, contentType: 'text/css', body: fs.readFileSync(path.join(FONTS_DIR, 'fonts.css'), 'utf8') });
      const f = path.join(FONTS_DIR, u.replace('https://fonts.gstatic.com/', '').replace(/\//g, '_'));
      return fs.existsSync(f) ? route.fulfill({ status: 200, contentType: 'font/woff2', body: fs.readFileSync(f), headers: { 'access-control-allow-origin': '*' } }) : route.abort();
    }
    external.push(u);
    return route.abort();
  });
  await page.goto(wrappedUrl() + (hash ? '#' + hash : ''), { waitUntil: 'load' });
  await page.evaluate(() => document.fonts && document.fonts.ready).catch(() => {});
  await page.waitForTimeout(150);
  return { context, page, errors, external };
}
const overflow = page => page.evaluate(() => ({ sw: document.documentElement.scrollWidth, iw: window.innerWidth }));
// main clips sideways overflow, so also look for visible elements that stick out of the viewport (scroll containers excepted).
const sticksOut = page => page.evaluate(() => {
  const vw = window.innerWidth, out = [];
  const inScroller = el => { for (let a = el.parentElement; a && a !== document.body; a = a.parentElement) { if (a.tagName === 'MAIN') return false; if (/auto|scroll|hidden/.test(getComputedStyle(a).overflowX)) return true; } return false; };
  for (const el of document.querySelectorAll('body *')) {
    if (el.closest('[hidden]') || (el.closest('svg') && el.tagName.toLowerCase() !== 'svg')) continue;
    const cs = getComputedStyle(el); if (cs.display === 'none' || cs.visibility === 'hidden') continue;
    const r = el.getBoundingClientRect(); if (!r.width || !r.height) continue;
    if ((r.left < -1 || r.right > vw + 1) && !inScroller(el)) out.push((el.id ? '#' + el.id : el.tagName.toLowerCase() + '.' + String(el.getAttribute('class') || '').split(' ')[0]) + ` [${Math.round(r.left)}..${Math.round(r.right)}]`);
  }
  return out.slice(0, 6);
});
function stripYaml(s) {
  const out = [];
  for (let l of s.split('\n')) {
    let inq = false, cut = -1;
    for (let i = 0; i < l.length; i++) {
      const ch = l[i];
      if (ch === '"' && l[i - 1] !== '\\') inq = !inq;
      else if (ch === '#' && !inq && (i === 0 || l[i - 1] === ' ')) { cut = i; break; }
    }
    if (cut >= 0) l = l.slice(0, cut);
    l = l.replace(/\s+$/, '');
    if (l) out.push(l);
  }
  return out;
}

(async () => {
  const browser = await chromium.launch();
  const { page, errors, external } = await open(browser);
  const codes = async () => (await page.getAttribute('#health', 'data-codes')) || '';
  const verdict = () => page.$eval('#res-title', e => e.textContent);
  const vclass = () => page.getAttribute('#sim-result .verdict', 'data-verdict');
  const rows = () => page.$$eval('#sim-result .tr', els => els.map(li => ({ id: li.dataset.id, type: li.dataset.type, d: li.dataset.d, why: li.querySelector('.tr-why').textContent })));
  const tab = async t => { await page.click('#tab-' + t); await page.waitForTimeout(60); };
  const sample = async id => {
    await tab('simulate');
    if (await page.isHidden(`#samples button[data-id="${id}"]`)) await page.click('#samples-more');
    await page.click(`#samples button[data-id="${id}"]`); await page.waitForTimeout(60);
  };
  const card = id => page.locator(`.st[data-id="${id}"]`);
  const selectCard = async id => { await tab('pipeline'); await card(id).locator('.st-name').click(); await page.waitForTimeout(40); };
  const openAdv = async () => { if (!(await page.$eval('#insp-adv', d => d.open))) await page.click('#insp-adv > summary'); };
  const healthAll = async () => {
    await tab('pipeline');
    if ((await page.getAttribute('#health-toggle', 'aria-expanded')) !== 'true') await page.click('#health-toggle');
    if (await page.isVisible('#health-all') && /Show all/.test(await page.textContent('#health-all'))) await page.click('#health-all');
  };
  const fix = async code => { await healthAll(); await page.locator('.lint-item', { has: page.locator(`.li-code:text-is("${code}")`) }).first().locator('[data-act="fix"]').click(); await page.waitForTimeout(40); };
  const openBreak = async () => { if (!(await page.$eval('#adv-break', d => d.open))) await page.click('#adv-break > summary'); };

  // ---------- first frame ----------
  ok(await page.isVisible('#panel-overview'), 'opens on the Overview');
  ok((await page.textContent('#ov-brand')) === 'Clearance' && (await page.textContent('#ov-tag')) === 'No AI request leaves the firm without clearance.', 'brand and tagline shown');
  ok((await page.title()) === 'Gate Pipeline Builder', 'artifact <title> unchanged');
  ok((await page.$$('#panel-overview .pin')).length === 5, 'Overview has 5 pins');

  // ---------- pins: open/close, one at a time, Esc, click outside, pins toggle ----------
  await page.click('.pin[data-pin="o5"]');
  ok(await page.isVisible('#pop') && (await page.textContent('#pop-title')) === 'Four possible answers', 'pin opens its bubble');
  ok((await page.getAttribute('.pin[data-pin="o5"]', 'aria-expanded')) === 'true' && (await page.getAttribute('.pin[data-pin="o5"]', 'aria-controls')) === 'pop', 'pin has aria-expanded / aria-controls');
  ok(/Why it matters/.test(await page.textContent('#pop-why')), 'bubble has a "Why it matters" footer');
  await page.click('.pin[data-pin="o2"]');
  ok((await page.textContent('#pop-title')) === 'L2 · The pipeline' && (await page.$$('.pin[aria-expanded="true"]')).length === 1, 'only one bubble open at a time');
  await page.keyboard.press('Escape');
  ok(await page.isHidden('#pop'), 'Esc closes the bubble');
  ok(await page.evaluate(() => document.activeElement && document.activeElement.dataset.pin === 'o2'), 'focus returns to the pin');
  await page.click('.pin[data-pin="o1"]');
  await page.mouse.click(300, 870);
  ok(await page.isHidden('#pop'), 'clicking outside closes the bubble');
  await page.click('.pin[data-pin="o5"]');
  await page.click('.pin[data-pin="o5"]');
  ok(await page.isHidden('#pop'), 'clicking the open pin again closes it');
  await page.click('#pins-toggle');
  ok((await page.textContent('#pins-label')) === 'Pins: off' && (await page.$$eval('.pin', ps => ps.every(p => p.offsetParent === null))), 'pins toggle hides every pin');
  await page.reload(); await page.waitForTimeout(200);
  ok((await page.getAttribute('#pins-toggle', 'aria-pressed')) === 'false' && (await page.$$eval('.pin', ps => ps.every(p => p.offsetParent === null))), 'pins setting is remembered (localStorage)');
  await page.click('#pins-toggle');
  ok((await page.$$eval('#panel-overview .pin', ps => ps.every(p => p.offsetParent !== null))), 'pins back on');

  // ---------- the 60-second tour ----------
  const PINS = await page.evaluate(() => null);
  const expected = [['o2', 'overview', 'L2 · The pipeline'], ['o4', 'overview', 'What is a gate?'], ['p2', 'pipeline', 'One gate, three jobs'], ['p4', 'pipeline', 'JEV, the AI judge'],
    ['p5', 'pipeline', 'When a gate goes down'], ['s1', 'simulate', 'Pick a scenario'], ['s3', 'simulate', 'See every change'], ['a2', 'audit', 'Tamper-evident']];
  void PINS;
  const runsBefore = +(await page.textContent('#audit-count'));
  await page.click('.ov-cta [data-act="tour"]');
  for (let i = 0; i < expected.length; i++) {
    const [id, t, title] = expected[i];
    await page.waitForTimeout(80);
    const step = await page.textContent('#pop-step'), ttl = await page.textContent('#pop-title');
    const active = await page.$eval('[role="tab"][aria-selected="true"]', e => e.id.slice(4));
    const spot = await page.$eval('#tour-spot', e => { const r = e.getBoundingClientRect(); return r.width > 10 && r.height > 10; });
    ok(step === `Step ${i + 1} of 8` && ttl === title && active === t && spot, `tour step ${i + 1}/8 ${id}: "${ttl}" on ${active}`);
    if (id === 'p5') ok(await page.isVisible('#settings-panel'), 'tour opens the settings panel for the "if unavailable" step');
    if (id === 's1') {
      await page.waitForTimeout(150);
      ok(+(await page.textContent('#audit-count')) === runsBefore + 1 && (await vclass()) === 'modify' && /^Rewritten/.test(await verdict()), 'tour Simulate step runs Goldman: MODIFY verdict');
      const clear = await page.evaluate(() => { const a = document.querySelector('#pop').getBoundingClientRect(), b = document.querySelector('#sim-result .strip-card').getBoundingClientRect(); return a.right <= b.left || b.right <= a.left || a.bottom <= b.top || b.bottom <= a.top; });
      ok(clear, 'tour Simulate step: the bubble leaves the flow strip visible');
    }
    if (i === expected.length - 1) ok(/That's it\. Try a request of your own\./.test(await page.textContent('#pop-end')) && (await page.textContent('#tour-next')) === 'Try a request', 'last step: "That\'s it. Try a request of your own."');
    if (i === 1) {
      await page.keyboard.press('ArrowLeft'); await page.waitForTimeout(60);
      ok((await page.textContent('#pop-step')) === 'Step 1 of 8', 'ArrowLeft goes back');
      await page.keyboard.press('ArrowRight'); await page.waitForTimeout(60);
      ok((await page.textContent('#pop-step')) === 'Step 2 of 8', 'ArrowRight goes forward');
    }
    if (i < expected.length - 1) await page.click('#tour-next');
  }
  await page.click('#tour-next');
  await page.waitForTimeout(80);
  ok(await page.isHidden('#tour-block') && (await page.$eval('[role="tab"][aria-selected="true"]', e => e.id)) === 'tab-simulate' && (await page.evaluate(() => document.activeElement.id)) === 'sim-msg', 'tour ends on Simulate with the composer focused');
  await tab('overview');
  await page.click('#tour-top');
  await page.click('#tour-next');
  await page.keyboard.press('Escape');
  ok(await page.isHidden('#tour-block') && await page.isHidden('#pop'), 'Esc ends the tour');

  // ---------- YAML preview equals pipeline.example.yaml (comments aside) ----------
  const yaml = await page.$eval('#yaml-pre', e => e.textContent);
  if (fs.existsSync(EXAMPLE)) {
    const a = stripYaml(fs.readFileSync(EXAMPLE, 'utf8')), b = stripYaml(yaml);
    ok(JSON.stringify(a) === JSON.stringify(b), `YAML preview matches pipeline.example.yaml line for line (${b.length} content lines)`);
  }
  ok(yaml.split('\n').slice(0, 2).every(l => l.startsWith('# ')), 'YAML has a 2-line header');

  // ---------- simulate: samples ----------
  await tab('simulate');
  const visibleChips = async () => page.$$eval('#samples button[data-id]', bs => bs.filter(b => b.offsetParent).length);
  const shown = await visibleChips();
  await page.click('#samples-more');
  const all = await visibleChips();
  ok(shown === 7 && all === 9 && (await page.getAttribute('#samples-more', 'aria-expanded')) === 'true', `scenarios: ${shown} shown by default, "+2 more" reveals ${all}`);
  await page.click('#samples-more');
  await sample('skills');
  ok((await vclass()) === 'allow', '"skills" passes with whole words only');
  await selectCard('filter_kill');
  ok(await page.isVisible('#insp') && (await page.textContent('#insp-title')) === 'Block the word ‘kill’', 'selecting a gate opens the inspector');
  await page.uncheck('#cfg-whole_word');
  ok((await codes()).includes('E5') && (await codes()).includes('W3'), 'whole_word off: E5 (tests fail) + W3: ' + (await codes()));
  ok(await page.$eval('#save-top', b => b.disabled), 'Save disabled while errors exist');
  await sample('skills');
  ok((await vclass()) === 'deny' && /Block the word ‘kill’/.test(await verdict()), '"skills" denied without whole words: ' + await verdict());
  ok(/inside "skills"/.test((await rows()).find(r => r.id === 'filter_kill').why), 'reason names the containing word');
  await fix('E5');
  ok(!(await codes()).includes('E5'), 'E5 fix enables whole_word again');

  await sample('goldman');
  let rs = await rows();
  ok(rs.find(r => r.id === 'mask_firm').d === 'modify' && rs.find(r => r.id === 'mask_firm_out').d === 'modify', 'Goldman: MODIFY on the way in and on the way back');
  const ioTexts = await page.$$eval('#sim-result .io-text', e => e.map(x => x.textContent));
  ok(/Firm will present the Q3 results/.test(ioTexts[0]) && !/Goldman/.test(ioTexts[0]), 'what left the firm is masked ("Firm")');
  ok(!/Goldman/.test(ioTexts[1]) && /Firm reported/.test(ioTexts[1]), 'the answer is masked on the way back');
  ok(/Goldman Sachs reported/.test(await page.$eval('#sim-result .io:nth-child(2) details pre', e => e.textContent)), 'raw model answer said "Goldman Sachs reported…"');
  ok((await page.textContent('#sim-result .tr-diff del')) === 'Goldman Sachs' && (await page.textContent('#sim-result .tr-diff ins')) === 'Firm', 'word diff: Goldman Sachs struck, Firm inserted');
  ok(/charged \$0\.00\d\d/.test(rs.find(r => r.id === 'budget_settle').why), 'budget_settle charges the real cost');
  ok((await page.$$eval('#sim-result .node', ns => ns.length)) === 10, 'flow strip: 9 gates + the model');
  await page.click('#sim-result .tr[data-id="mask_firm"] .tr-row');
  ok(/X-Gate-Id: mask_firm/.test(await page.textContent('#sim-result .tr[data-id="mask_firm"] .tr-det')), 'expanding a row shows the envelope JSON');

  await sample('budget');
  ok((await vclass()) === 'deny' && /Reserve the budget/.test(await verdict()) && /\$0\.0130/.test(await page.textContent('.v-reason')), 'bob over budget: stopped with the amounts');
  ok((await rows()).filter(r => r.d === 'notreached').length === 6, 'gates after the deny: not reached');
  await sample('opus'); ok(/Allow only approved models/.test(await verdict()), 'opus stopped by the model allowlist');
  await sample('inject'); ok((await vclass()) === 'deny' && /83\.5%/.test(await page.textContent('.v-reason')), 'prompt injection stopped by JEV (83.5%)');
  await sample('defensive'); ok((await vclass()) === 'flag' && /49\.2%/.test(await page.textContent('.v-reason')), 'defensive question flagged (49.2%)');
  await sample('kill'); ok(/Block the word ‘kill’/.test(await verdict()), 'real "kill" stopped');
  await sample('benign'); ok((await vclass()) === 'allow', 'benign question cleared');
  await page.selectOption('#sim-key', 'sk-proxy-mallory'); await page.click('#sim-run');
  ok(/Check who is asking/.test(await verdict()) && /HTTP 401/.test(await page.textContent('.verdict .kicker')), 'unknown key: 401 at the identity check');

  // ---------- break things: naive restart vs correct restart, gate down ----------
  await sample('goldman');
  await openBreak();
  await page.selectOption('#sim-onmodify', 'restart');
  await page.check('#sim-naive');
  await page.click('#sim-run');
  rs = await rows();
  ok(rs.filter(r => r.id === 'budget' && r.d === 'allow').length === 2 && rs.filter(r => r.id === 'jev' && r.d === 'allow').length === 2 && rs.filter(r => r.id === 'auth').length === 2, 'naive restart: budget reserved twice, JEV twice, auth twice');
  ok(/reserved 2×/.test(await page.textContent('#sim-result .note.bad')) && /JEV was called 2×/.test(await page.textContent('#sim-result .note.bad')), 'naive restart: red note');
  await page.uncheck('#sim-naive');
  await page.click('#sim-run');
  rs = await rows();
  ok(['auth', 'model_allowed', 'budget'].every(id => rs.some(r => r.id === id && r.d === 'skip')) && rs.filter(r => r.id === 'jev' && r.d === 'allow').length === 1, 'correct restart: identity/budget skipped, JEV once');
  ok(rs.filter(r => r.id === 'budget_settle' && r.d === 'allow').length === 1, 'budget_settle runs exactly once');
  await tab('pipeline');
  await page.click('#add-gate');
  await page.fill('#pal-filter', 'governance');
  await page.click('.cat[data-type="system_prompt"] [data-act="add"]');
  await page.click('[data-act="catalog-close"]');
  ok((await codes()).includes('W4'), 'restart + governance message: W4');
  await sample('benign');
  ok((await rows()).filter(r => r.type === 'system_prompt').length === 3, 'governance message ran 3× (max_restarts 2)');
  ok(((await page.$eval('#sim-result .io details pre', e => e.textContent)).match(/You are an assistant at the Firm/g) || []).length === 3, 'upstream system message stacked 3×');
  await fix('W4');
  ok((await page.$eval('#set-onmodify', s => s.value)) === 'continue' && (await page.$eval('#sim-onmodify', s => s.value)) === 'continue', 'W4 fix: continue (mirrored in Simulate)');
  await selectCard('governance');
  await card('governance').locator('[data-act="del"]').click();
  ok(!(await card('governance').count()), 'gate removed');
  await sample('benign');
  await openBreak();
  const jevUid = await page.$eval('#sim-down', s => [...s.options].find(o => /AI judge/.test(o.textContent)).value);
  await page.selectOption('#sim-down', jevUid);
  await page.click('#sim-run');
  ok((await vclass()) === 'deny' && (await rows()).find(r => r.id === 'jev').d === 'error' && /2,000 ms/.test(await page.textContent('.v-reason')), 'gate down: error → deny (fail closed)');
  await page.selectOption('#sim-down', '');

  // ---------- disguised slur and the W2 fix ----------
  await sample('slur');
  ok((await vclass()) === 'allow', 'disguised slur passes without normalize');
  await fix('W2');
  const order = await page.$$eval('#list-request .st', e => e.map(x => x.dataset.id));
  ok(order.indexOf('normalize') >= 0 && order.indexOf('normalize') < order.indexOf('filter_slur'), 'W2 fix adds normalize before the filter');
  await sample('slur');
  ok((await vclass()) === 'deny' && (await rows()).find(r => r.id === 'normalize').d === 'modify', 'disguised slur now stopped');
  await sample('goldman');
  ok(/Q3 results/.test((await page.$$eval('#sim-result .io-text', e => e.map(x => x.textContent)))[0]), 'leet folding keeps "Q3"');

  // ---------- save, history, rollback ----------
  await tab('pipeline');
  await page.click('#save-top');
  ok(/^v13 saved · hot-reloaded in 0\.4 s \(simulated\) · \d+ warnings?$/.test(await page.locator('.toast').last().textContent()), 'Save: v13 toast');
  ok(/v13 is live/.test(await page.textContent('#status')) && /version: 13/.test(await page.$eval('#yaml-pre', e => e.textContent)), 'v13 live, YAML says version 13');
  await page.click('#yaml-box > summary');
  await page.locator('#history li', { hasText: 'v12' }).locator('[data-act="rollback"]').click();
  await page.click('[data-act="rb-confirm"]');
  ok(/v14 is live/.test(await page.textContent('#status')) && !(await card('normalize').count()), 'roll back to v12 saved as v14');
  await page.click('#yaml-copy');
  await page.waitForTimeout(80);
  ok(/Copied|Selected/.test(await page.textContent('#yaml-copy span')), 'Copy gives feedback');

  // ---------- health check rules ----------
  await selectCard('model_allowed');
  await card('model_allowed').locator('[data-act="up"]').click();
  ok((await codes()).includes('E1') && (await codes()).includes('E2'), 'identity check not first: E1 + E2');
  await fix('E1');
  ok(!(await codes()).includes('E1') && !(await codes()).includes('E2'), 'E1 fix moves auth back to the top');
  await selectCard('budget_settle');
  await openAdv();
  await page.uncheck('#insp-pinned');
  await card('budget_settle').locator('[data-act="del"]').click();
  ok((await codes()).includes('E3'), 'no settlement: E3');
  await fix('E3');
  ok(!(await codes()).includes('E3'), 'E3 fix adds budget_settle');
  await selectCard('filter_slur');
  await openAdv();
  await page.fill('#insp-id', 'filter_kill');
  ok((await codes()).includes('E4'), 'duplicate name: E4');
  await fix('E4');
  const ids = await page.$$eval('#list-request .st', e => e.map(x => x.dataset.id));
  ok(ids.includes('filter_kill_2') && ids.indexOf('filter_kill_2') < ids.indexOf('filter_kill'), 'E4 fix renames the edited gate');
  await selectCard('jev');
  for (let i = 0; i < 3; i++) await card('jev').locator('[data-act="up"]').click();
  ok((await codes()).includes('W1'), 'AI judge before cheap gates: W1');
  await fix('W1');
  ok(!(await codes()).includes('W1'), 'W1 fix moves it last');
  await selectCard('mask_firm_out');
  await card('mask_firm_out').locator('[data-act="del"]').click();
  ok((await codes()).includes('W5'), 'no mask on the way back: W5');
  await fix('W5');
  ok(!(await codes()).includes('W5'), 'W5 fix adds the response mask');
  await selectCard('jev');
  await openAdv();
  await page.selectOption('#insp-onerror', 'allow');
  ok((await codes()).includes('W6'), 'fails open: W6');
  await page.selectOption('#insp-onerror', '');
  await selectCard('mask_firm');
  await page.fill('#cfg-pattern', 'Goldman (Sachs');
  ok((await codes()).includes('E6') && /✗/.test(await page.textContent('#cfg-pattern-out')), 'invalid regex: E6 + inline message');
  await page.fill('#cfg-pattern', '(a+)+$');
  ok(/nested quantifier/.test(await page.textContent('#cfg-pattern-out')), 'ReDoS-shaped pattern refused');
  await page.fill('#cfg-pattern', 'Goldman Sachs');
  ok(await page.isVisible('[data-wrap="replacement"]'), '"Replace with" shown for mask');
  await page.selectOption('#cfg-decision', 'deny');
  ok(await page.isHidden('[data-wrap="replacement"]'), '"Replace with" hidden for block');
  await page.selectOption('#cfg-decision', 'mask');
  await selectCard('filter_kill');
  await page.click('#contract > summary');
  const contract = await page.textContent('#contract-body');
  ok(['X-Trace-Id', 'X-Gate-Id: filter_kill', 'X-Pipeline-Version', 'Authorization: Bearer ‹internal token›', '"phase": "request"', '"identity"', '"trail"', '"restart": 0', '"decision"', '"findings"', '"output"'].every(s => contract.includes(s)), 'gate contract preview: envelope, headers, reply');
  await page.click('[data-act="insp-close"]');
  ok(await page.isHidden('#insp'), 'closing the inspector gives the rail back');
  await page.click('#add-gate');
  await page.fill('#pal-filter', '');
  const before = await page.locator('#list-request .st').count();
  await page.locator('.cat[data-type="pii_mask"]').dragTo(page.locator('#list-request .st').nth(2));
  ok((await page.locator('#list-request .st').count()) === before + 1, 'drag from the catalogue adds a gate');
  await page.keyboard.press('Escape');

  // ---------- audit ----------
  await tab('audit');
  await page.waitForTimeout(300);
  const nrec = +(await page.textContent('#audit-count'));
  const shownRows = await page.locator('#audit-body tr').count();
  ok(nrec > 10 && shownRows === 10 && await page.isVisible('#audit-more'), `audit: latest 10 of ${nrec} records shown, "Show all" for the rest`);
  await page.click('#audit-more');
  const nrows = await page.locator('#audit-body tr').count();
  ok(nrows === nrec && nrows >= 20 && (await page.locator('#audit-body .sample-tag').count()) === 6, `audit: all ${nrows} rows after "Show all", 6 marked sample`);
  await page.waitForFunction(() => /Chain intact|Broken/.test(document.querySelector('#chain-badge').textContent), null, { timeout: 4000 }).catch(() => {});
  ok(/Chain intact/.test(await page.textContent('#chain-badge')), 'chain badge: intact (' + (await page.textContent('#chain-badge')) + ')');
  await page.locator('#audit-body tr').last().click();
  ok(await page.isVisible('#audit-drawer') && (await page.locator('#audit-drawer .wf .bar').count()) >= 7 && /"hash": "[0-9a-f]{64}"/.test(await page.textContent('#rec-pre')), 'record drawer: waterfall + JSON with hash');
  await page.click('[data-act="audit-close"]');
  await page.click('#audit-more');
  ok((await page.locator('#audit-body tr').count()) === 10, '"Show the latest 10" collapses the table again');
  await page.click('#audit-adv > summary');
  await page.click('#tamper-btn');
  ok(/A record changed/.test(await page.textContent('#chain-badge')), 'tampering marks the chain unverified');
  await page.click('#chain-verify');
  await page.waitForTimeout(200);
  ok(/Broken at record 2/.test(await page.textContent('#chain-badge')) && (await page.locator('#audit-body tr.broken').count()) === 1, 'Verify shows where the chain breaks (the old record is brought into view)');
  await page.click('#tamper-undo');
  await page.click('#chain-verify');
  await page.waitForTimeout(200);
  ok(/Chain intact/.test(await page.textContent('#chain-badge')), 'restored record: chain intact again');
  await page.click('#exp-jsonl');
  const recs = (await page.textContent('#export-pre')).split('\n').map(l => JSON.parse(l));
  ok(recs.length === nrows && recs.every((r, i) => (i === 0 ? r.prev_hash === '0'.repeat(64) : r.prev_hash === recs[i - 1].hash)), 'JSONL export: one record per line, prev_hash links');
  const r1 = Object.assign({}, recs[1]); delete r1.prev_hash; delete r1.hash;
  ok(crypto.createHash('sha256').update(recs[1].prev_hash + '\n' + JSON.stringify(r1)).digest('hex') === recs[1].hash, 'hash = sha256(prev_hash + "\\n" + record), checked in Node');
  await page.click('#exp-csv');
  ok(/^ts,trace,user/.test(await page.textContent('#export-pre')), 'CSV export preview');

  // ---------- deep links ----------
  for (const [h, panel] of [['pipeline', 'pipeline'], ['builder', 'pipeline'], ['simulate', 'simulate'], ['audit', 'audit'], ['overview', 'overview']]) {
    await page.evaluate(x => { location.hash = x; }, h);
    await page.waitForTimeout(60);
    ok(await page.isVisible('#panel-' + panel), `#${h} opens ${panel}`);
  }
  ok(!errors.length && !external.length, 'no console errors, no requests outside Google Fonts' + (errors.length || external.length ? ' ' + JSON.stringify({ errors, external }) : ''));
  await page.context().close();

  // ---------- layout sweep: 1440 and 400, light and dark ----------
  for (const width of [1440, 400]) {
    for (const scheme of ['light', 'dark']) {
      const s = await open(browser, { width, scheme, reduced: false });
      let worst = 0;
      const stuck = [];
      for (const t of ['overview', 'pipeline', 'simulate', 'audit']) {
        await s.page.click('#tab-' + t); await s.page.waitForTimeout(250);
        const o = await overflow(s.page);
        worst = Math.max(worst, o.sw - o.iw);
        stuck.push(...(await sticksOut(s.page)).map(x => t + ': ' + x));
      }
      await s.page.click('#tab-pipeline'); await s.page.click('#settings-btn'); await s.page.waitForTimeout(100);
      stuck.push(...(await sticksOut(s.page)).map(x => 'settings: ' + x));
      await s.page.click('[data-act="settings-close"]');
      if (width === 400) {
        await s.page.click('#tab-overview');
        await s.page.click('.pin[data-pin="o5"]');
        ok(await s.page.$eval('#pop', p => p.classList.contains('sheet') && Math.abs(p.getBoundingClientRect().bottom - window.innerHeight) < 2), 'phone: the bubble is a bottom sheet');
      }
      ok(worst <= 0 && !s.errors.length, `${width}px ${scheme}: no horizontal scroll on any tab, no console errors`);
      ok(!stuck.length, `${width}px ${scheme}: nothing sticks out of the viewport sideways (tabs and settings panel)` + (stuck.length ? ' ' + JSON.stringify(stuck) : ''));
      await s.context.close();
    }
  }
  await browser.close();
  if (fontTrouble) console.log('\nnote: Google Fonts could not be loaded (fallback fonts used); set FONTS_DIR to serve local copies');
  console.log(`\n${passes} passed, ${fails} failed`);
  console.log(fails ? 'FAILED' : 'ALL PASSED');
  process.exit(fails ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
