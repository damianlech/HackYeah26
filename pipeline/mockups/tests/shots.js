// Screenshots of pipeline-builder.html (Clearance mockup) at 1440x900, light theme, via Playwright + headless Chromium.
// Usage: NODE_PATH=$(npm root -g) node shots.js   (optional: PAGE=..., OUT_DIR=..., FONTS_DIR=/dir/with/fonts.css)
// Writes overview.png (at rest), overview-pin.png (pin o2 open), pipeline-builder.png (rail + pin p2 open), pipeline-trace.png (Goldman sample run),
// audit-record.png (Audit tab after Verify, the Goldman record open).
const fs = require('fs');
const os = require('os');
const path = require('path');
const { chromium } = require('playwright');

const PAGE = process.env.PAGE || path.resolve(__dirname, '..', 'pipeline-builder.html');
const OUT_DIR = process.env.OUT_DIR || path.resolve(__dirname, '..');
const FONTS_DIR = process.env.FONTS_DIR || '';

function wrappedUrl() {
  // The artifact host adds the document skeleton; wrap a temp copy the same way. The real file stays doctype-free.
  const out = path.join(os.tmpdir(), 'clearance-pipeline-builder-shots.html');
  fs.writeFileSync(out, '<!doctype html><html><head><meta charset="utf-8"></head><body>' + fs.readFileSync(PAGE, 'utf8') + '</body></html>');
  return 'file://' + out;
}

(async () => {
  const browser = await chromium.launch();
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1, colorScheme: 'light', reducedMotion: 'no-preference' });
  const page = await context.newPage();
  const errors = [];
  let fontTrouble = false;
  page.on('console', m => {
    if (m.type() !== 'error') return;
    if (/^https:\/\/fonts\.(googleapis|gstatic)\.com\//.test((m.location() || {}).url || '')) { fontTrouble = true; return; }
    errors.push(m.text());
  });
  page.on('pageerror', e => errors.push(e.message));
  await page.route('**/*', route => {
    const u = route.request().url();
    if (u.startsWith('file://')) return route.continue();
    if (FONTS_DIR && u.startsWith('https://fonts.googleapis.com/')) return route.fulfill({ status: 200, contentType: 'text/css', body: fs.readFileSync(path.join(FONTS_DIR, 'fonts.css'), 'utf8') });
    if (FONTS_DIR && u.startsWith('https://fonts.gstatic.com/')) {
      const f = path.join(FONTS_DIR, u.replace('https://fonts.gstatic.com/', '').replace(/\//g, '_'));
      return fs.existsSync(f) ? route.fulfill({ status: 200, contentType: 'font/woff2', body: fs.readFileSync(f), headers: { 'access-control-allow-origin': '*' } }) : route.abort();
    }
    if (u.startsWith('https://fonts.googleapis.com/') || u.startsWith('https://fonts.gstatic.com/')) return route.continue();
    return route.abort();
  });
  await page.goto(wrappedUrl() + '#overview', { waitUntil: 'load' });
  await page.evaluate(() => document.fonts && document.fonts.ready).catch(() => {});
  const park = () => page.mouse.move(30, 880);                 // a quiet spot: no hover styles in the shots
  const shot = name => page.screenshot({ path: path.join(OUT_DIR, name) }).then(() => console.log('wrote', path.join(OUT_DIR, name)));

  // 1a. Overview at rest: hero + the full L1 → L2 → L3 flow, no bubble open (first image in the docs).
  await park();
  await page.waitForTimeout(3800);
  await shot('overview.png');
  // 1b. Overview with pin o2 ("L2 · The pipeline") open. Clicking the pin replays the flow dot; let it finish.
  await page.click('.pin[data-pin="o2"]');
  await park();
  await page.waitForTimeout(3800);
  await shot('overview-pin.png');
  await page.keyboard.press('Escape');

  // 2. Pipeline rail with pin p2 ("One gate, three jobs") open.
  await page.click('#tab-pipeline');
  await page.waitForTimeout(300);
  await page.click('.pin[data-pin="p2"]');
  await park();
  await page.waitForTimeout(400);
  await shot('pipeline-builder.png');
  await page.keyboard.press('Escape');

  // 3. Simulate after the "Mentions Goldman Sachs" sample: flow strip, verdict, word diff.
  await page.click('#tab-simulate');
  await page.click('#samples button[data-id="goldman"]');
  await park();
  await page.waitForFunction(() => !document.querySelector('#sim-result .token:not([hidden])') && !document.querySelector('#sim-result .wait'), null, { timeout: 15000 });
  await page.waitForTimeout(600);
  await shot('pipeline-trace.png');

  // 4. Audit after Verify, with the newest record (the Goldman run) open: every gate on one time scale, fingerprint, JSON.
  await page.click('#tab-audit');
  await page.waitForTimeout(300);
  await page.click('#chain-verify');
  await page.click('#audit-body [data-act="audit-row"]');
  await park();
  await page.waitForTimeout(6000);                             // let the "Verified" toast fade out
  await shot('audit-record.png');

  if (fontTrouble) console.warn('warning: Google Fonts could not be loaded, so the shots use fallback fonts; set FONTS_DIR to serve local copies');
  if (errors.length) { console.error('console errors:', errors); process.exitCode = 1; }
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
