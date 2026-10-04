// Renders architecture.html to architecture.png (1800x1190 at 2x) with Playwright + Chromium.
// Usage from the repo root: NODE_PATH=$(npm root -g) node 2-architecture/render.js
// Optional FONTS_DIR=/dir/with/fonts.css serves local font copies when Google Fonts can't be reached.
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1800, height: 1200 }, deviceScaleFactor: 2 });
  const fonts = process.env.FONTS_DIR;
  if (fonts) {
    await page.route('https://fonts.googleapis.com/**', r => r.fulfill({ contentType: 'text/css', body: fs.readFileSync(path.join(fonts, 'fonts.css'), 'utf8') }));
    await page.route('https://fonts.gstatic.com/**', r => {
      const f = path.join(fonts, r.request().url().replace('https://fonts.gstatic.com/', '').replace(/\//g, '_'));
      return fs.existsSync(f) ? r.fulfill({ contentType: 'font/woff2', body: fs.readFileSync(f), headers: { 'access-control-allow-origin': '*' } }) : r.abort();
    });
  }
  await page.goto('file://' + path.resolve(__dirname, 'architecture.html'));
  await page.waitForSelector('body[data-ready="1"]');
  await page.locator('#canvas').screenshot({ path: path.resolve(__dirname, 'architecture.png') });
  await browser.close();
  console.log('wrote', path.resolve(__dirname, 'architecture.png'));
})().catch(e => { console.error(e); process.exit(1); });
