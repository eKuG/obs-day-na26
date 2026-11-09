#!/usr/bin/env node
// Scripted screenshots of the demo rig with the locally installed Chrome (headless).
// usage: node shots.js <scene.json>      scene = [{goto|wait|click|type|press|shot}, ...]
// Keeps a profile dir under tools/.chrome-profile between scenes.
const puppeteer = require("puppeteer-core");
const fs = require("fs");
const path = require("path");

const CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const PROFILE = path.join(__dirname, ".chrome-profile");
const OUT = path.join(__dirname, "..", "evidence");

async function main() {
  const scene = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
  const browser = await puppeteer.launch({
    executablePath: CHROME, headless: "new", userDataDir: PROFILE,
    args: ["--no-first-run", "--no-default-browser-check", "--hide-scrollbars", "--force-device-scale-factor=2"],
    defaultViewport: { width: 1600, height: 1000, deviceScaleFactor: 2 },
  });
  const page = (await browser.pages())[0] || (await browser.newPage());
  page.setDefaultTimeout(20000);
  const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);
  try {
    for (const step of scene) {
      if (step.goto) { log("goto", step.goto); await page.goto(step.goto, { waitUntil: "networkidle2", timeout: 45000 }).catch(e => log("goto timeout (continuing):", e.message)); }
      if (step.wait) { await new Promise(r => setTimeout(r, step.wait)); }
      if (step.waitFor) { await page.waitForSelector(step.waitFor, { timeout: step.timeout || 20000 }).catch(e => log("waitFor miss:", step.waitFor)); }
      if (step.click) {   // click the first element whose visible text contains step.click (case-insensitive), optional tag filter
        const ok = await page.evaluate(({ text, tag }) => {
          const els = Array.from(document.querySelectorAll(tag || "button, a, [role=button], div, span, li"));
          const el = els.find(e => e.children.length < 6 && (e.innerText || "").trim().toLowerCase().includes(text.toLowerCase()) && e.getClientRects().length);
          if (!el) return false; el.scrollIntoView({ block: "center" }); el.click(); return true;
        }, { text: step.click, tag: step.tag });
        log("click", JSON.stringify(step.click), ok ? "ok" : "NOT FOUND");
        await new Promise(r => setTimeout(r, step.after || 800));
      }
      if (step.clickAt) { await page.mouse.click(step.clickAt[0], step.clickAt[1]); await new Promise(r => setTimeout(r, step.after || 800)); log("clickAt", step.clickAt); }
      if (step.clickSel) { await page.click(step.clickSel).catch(e => log("clickSel miss:", step.clickSel)); await new Promise(r => setTimeout(r, step.after || 800)); }
      if (step.type) { await page.type(step.type.sel, step.type.text, { delay: 20 }); }
      if (step.press) { await page.keyboard.press(step.press); await new Promise(r => setTimeout(r, 500)); }
      if (step.select) { await page.select(step.select.sel, step.select.value).catch(e => log("select miss", step.select.sel)); }
      if (step.eval) { const r = await page.evaluate(step.eval); log("eval ->", JSON.stringify(r).slice(0, 200)); }
      if (step.exec) {  // run a shell command mid-scene (e.g. the live patch) and keep going
        const { execSync } = require("child_process");
        try { const out = execSync(step.exec, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }); log("exec ok:", (out || "").trim().slice(0, 120)); }
        catch (e) { log("exec failed:", (e.stderr || e.message || "").toString().slice(0, 200)); }
        await new Promise(r => setTimeout(r, step.after || 300));
      }
      if (step.shot) {
        const file = path.join(OUT, step.shot);
        const clip = step.clip; // [x,y,w,h] in CSS px
        await page.screenshot({ path: file, fullPage: !!step.full, ...(clip ? { clip: { x: clip[0], y: clip[1], width: clip[2], height: clip[3] } } : {}) });
        log("shot", step.shot);
      }
    }
  } finally { await browser.close(); }
}
main().catch(e => { console.error(e); process.exit(1); });
