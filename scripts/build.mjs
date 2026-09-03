// Builds dist/boot.svg and dist/contributions.svg for the profile README.
//
// boot.svg           a systemd-style boot log (same idea as eddiemoss.co.za) with live numbers
// contributions.svg  the last year of contributions drawn in the site's green
//
// Text is rendered with Cascadia Mono outlined to paths (assets/fonts, OFL licensed), so both
// images look the same on every OS. Glyphs are stored once in <defs> and placed with <use>.
//
// Env: GH_TOKEN (required), GH_LOGIN (default edwynmoss), HAS_PAT=1 when GH_TOKEN can see
// private repos. Without a PAT the merged-PR line is left out rather than shown wrong.

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import opentype from "opentype.js";

const login = process.env.GH_LOGIN || "edwynmoss";
const token = process.env.GH_TOKEN;
const hasPat = process.env.HAS_PAT === "1";
if (!token) throw new Error("GH_TOKEN is required");

const font = opentype.loadSync("assets/fonts/CascadiaMono.ttf");
const logo = readFileSync("assets/logo.png").toString("base64");

// ---------- data ----------
const query = `
query($login: String!, $prs: String!) {
  user(login: $login) {
    contributionsCollection {
      contributionCalendar { totalContributions weeks { contributionDays { date contributionCount weekday } } }
    }
  }
  merged: search(type: ISSUE, query: $prs) { issueCount }
}`;
const res = await fetch("https://api.github.com/graphql", {
  method: "POST",
  headers: { authorization: `bearer ${token}`, "content-type": "application/json", "user-agent": "profile-build" },
  body: JSON.stringify({ query, variables: { login, prs: `is:pr is:merged author:${login}` } }),
});
const json = await res.json();
if (json.errors) throw new Error(JSON.stringify(json.errors, null, 2));
const cal = json.data.user.contributionsCollection.contributionCalendar;
const mergedPrs = json.data.merged.issueCount;
const fmt = (n) => n.toLocaleString("en-US");

// ---------- palette (site dark theme) ----------
const C = {
  bg: "#050907", panel: "#0b120e", text: "#e8f0eb", muted: "#9fb0a6", dim: "#5b6b62",
  green: "#24db67", greenBright: "#6ff09a", amber: "#f5a524",
};

// ---------- glyphs ----------
const glyphs = new Map();
function glyphId(ch) {
  if (!glyphs.has(ch)) glyphs.set(ch, { id: `g${glyphs.size}`, d: font.charToGlyph(ch).getPath(0, 0, 1).toPathData(4) });
  return glyphs.get(ch).id;
}
const advance = (size) => (font.charToGlyph("M").advanceWidth / font.unitsPerEm) * size;
function text(str, x, y, size, fill) {
  const adv = advance(size);
  let out = "", cx = x;
  for (const ch of str) {
    if (ch !== " ") out += `<use href="#${glyphId(ch)}" transform="translate(${cx.toFixed(2)} ${y}) scale(${size})" fill="${fill}"/>`;
    cx += adv;
  }
  return { svg: out, width: cx - x };
}
const defs = () => `<defs>${[...glyphs.values()].map((g) => `<path id="${g.id}" d="${g.d}"/>`).join("")}</defs>`;
const frame = (W, H) => `<clipPath id="f"><rect width="${W}" height="${H}" rx="8"/></clipPath>`;

mkdirSync("dist", { recursive: true });

// ---------- boot.svg ----------
{
  const lines = [
    { kind: "bios", text: "EM BIOS v2.14 — Portfolio Systems", delay: 0 },
    { kind: "bios", text: "Copyright (C) 2026, Edwyn Moss", delay: 60 },
    { kind: "gap", delay: 120 },
    { kind: "bios", text: "Booting from GitHub ...", delay: 380 },
    { kind: "kernel", ts: "0.000000", text: `Setting hostname to '${login}'`, delay: 220 },
    { kind: "kernel", ts: "0.412551", text: "Timezone: Africa/Johannesburg (SAST, UTC+2)", delay: 130 },
    { kind: "ok", text: "Mounted /home/edwyn (Cape Town)", delay: 160 },
    { kind: "ok", text: "Started millennial-projects.service", delay: 120 },
    { kind: "ok", text: `Reached target ${fmt(cal.totalContributions)} contributions in the last 12 months`, delay: 140 },
    ...(hasPat ? [{ kind: "ok", text: `Merged ${fmt(mergedPrs)} pull requests`, delay: 90 }] : []),
    { kind: "ok", text: "Loaded 21 certifications", delay: 110 },
    { kind: "ok", text: "Started writeups.service (tryhackme, portswigger, offsec)", delay: 120 },
    { kind: "warn", text: "public-repos.service: most work runs in private orgs, skipping", delay: 260 },
    { kind: "ok", text: "Started OpenBSD Secure Shell server", delay: 110 },
    { kind: "ok", text: "Reached target Graphical Interface", delay: 160 },
    { kind: "gap", delay: 300 },
    { kind: "prompt", text: "edwyn@github:~$ ", delay: 0 },
  ];
  const size = 13, lh = 20, padX = 36, padY = 34, W = 900, H = padY * 2 + lines.length * lh - 6, adv = advance(size);
  let body = "", t = 0;
  lines.forEach((l, i) => {
    t += l.delay;
    const y = padY + size + i * lh;
    let row = "";
    if (l.kind === "bios") row += text(l.text, padX, y, size, C.muted).svg;
    if (l.kind === "kernel") row += text(`[${l.ts.padStart(11)}]`, padX, y, size, C.dim).svg + text(l.text, padX + adv * 14, y, size, C.text).svg;
    if (l.kind === "ok" || l.kind === "warn") {
      row += text("[", padX, y, size, C.dim).svg;
      row += text(l.kind === "ok" ? "  OK  " : " WARN ", padX + adv, y, size, l.kind === "ok" ? C.green : C.amber).svg;
      row += text("]", padX + adv * 7, y, size, C.dim).svg;
      row += text(l.text, padX + adv * 9, y, size, C.text).svg;
    }
    if (l.kind === "prompt") {
      const p = text(l.text, padX, y, size, C.green);
      row += p.svg + `<rect class="cursor" x="${(padX + p.width).toFixed(1)}" y="${y - size + 1}" width="${adv.toFixed(1)}" height="${size + 3}" fill="${C.text}"/>`;
    }
    if (row) body += `<g class="l" style="animation-delay:${t}ms">${row}</g>`;
  });
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-label="Boot log: Edwyn Moss, engineer in Cape Town">
${defs()}
<style>.l{opacity:0;animation:show 1ms linear forwards}@keyframes show{to{opacity:1}}.cursor{animation:blink 1.1s steps(1) infinite}@keyframes blink{50%{opacity:0}}</style>
${frame(W, H)}
<g clip-path="url(#f)"><rect width="${W}" height="${H}" fill="${C.bg}"/><image href="data:image/png;base64,${logo}" x="${W - 80}" y="30" width="44" height="53" opacity="0.92"/>${body}</g>
</svg>
`;
  writeFileSync("dist/boot.svg", svg);
  console.log(`boot.svg ${W}x${H} ${(svg.length / 1024).toFixed(0)} KB, ${t} ms sequence, merged-PR line ${hasPat ? "on" : "off"}`);
}

// ---------- contributions.svg ----------
{
  glyphs.clear();
  const days = cal.weeks.flatMap((w) => w.contributionDays);
  const counts = days.map((d) => d.contributionCount);
  const max = Math.max(...counts);
  const active = counts.filter((c) => c > 0).length;
  let longest = 0, run = 0, current = 0;
  for (const c of counts) { run = c > 0 ? run + 1 : 0; longest = Math.max(longest, run); }
  for (let i = counts.length - 1; i >= 0 && counts[i] > 0; i--) current++;
  const day = (d) => new Date(d + "T00:00:00Z");
  const busiestDate = day(days[counts.indexOf(max)].date).toLocaleDateString("en-GB", { day: "numeric", month: "short", timeZone: "UTC" });

  const nz = counts.filter((c) => c > 0).sort((a, b) => a - b);
  const q = (p) => nz[Math.min(nz.length - 1, Math.floor(nz.length * p))];
  const th = [q(0.25), q(0.5), q(0.75)];
  const scale = [C.panel, "#123f24", "#187a3f", C.green, C.greenBright];
  const color = (c) => (c === 0 ? scale[0] : c <= th[0] ? scale[1] : c <= th[1] ? scale[2] : c <= th[2] ? scale[3] : scale[4]);

  const cell = 12, gap = 3, step = cell + gap, left = 44, top = 30, size = 11, W = 900;
  const gridW = cal.weeks.length * step - gap;
  const x0 = left + Math.floor((W - left - 28 - gridW) / 2);
  let body = "", lastMonth = -1;
  cal.weeks.forEach((w, i) => {
    const m = day(w.contributionDays[0].date).getUTCMonth();
    if (m !== lastMonth && i < cal.weeks.length - 1) {
      body += text(day(w.contributionDays[0].date).toLocaleDateString("en-GB", { month: "short", timeZone: "UTC" }), x0 + i * step, top - 10, size, C.dim).svg;
      lastMonth = m;
    }
  });
  for (const [row, label] of [[1, "Mon"], [3, "Wed"], [5, "Fri"]]) body += text(label, left - 30, top + row * step + cell - 2, size, C.dim).svg;
  cal.weeks.forEach((w, i) => {
    let col = "";
    for (const d of w.contributionDays) col += `<rect x="${x0 + i * step}" y="${top + d.weekday * step}" width="${cell}" height="${cell}" rx="2.5" fill="${color(d.contributionCount)}"><title>${d.date}: ${d.contributionCount}</title></rect>`;
    body += `<g class="w" style="animation-delay:${i * 18}ms">${col}</g>`;
  });
  const bottom = top + 7 * step;
  body += text(`longest streak ${longest} days   ·   current streak ${current} days   ·   busiest day ${fmt(max)} on ${busiestDate}   ·   active ${active} of ${days.length} days`, x0, bottom + 26, size, C.muted).svg;
  const lx = x0 + gridW - 5 * 14 - 32;
  body += text("less", lx - 30, top - 10, size, C.dim).svg;
  scale.forEach((f, i) => { body += `<rect x="${lx + i * 14}" y="${top - 19}" width="10" height="10" rx="2" fill="${f}"/>`; });
  body += text("more", lx + 5 * 14 + 4, top - 10, size, C.dim).svg;
  const H = bottom + 48;
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-label="${fmt(cal.totalContributions)} contributions in the last year">
${defs()}
<style>.w{opacity:0;animation:show .45s ease-out forwards}@keyframes show{to{opacity:1}}</style>
${frame(W, H)}
<g clip-path="url(#f)"><rect width="${W}" height="${H}" fill="${C.bg}"/>${body}</g>
</svg>
`;
  writeFileSync("dist/contributions.svg", svg);
  console.log(`contributions.svg ${W}x${H} ${(svg.length / 1024).toFixed(0)} KB; longest ${longest}, current ${current}, busiest ${max} (${busiestDate}), active ${active}/${days.length}`);
}
