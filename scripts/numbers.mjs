// Builds dist/numbers.svg — a self-hosted "by the numbers" strip for the profile README.
// Runs in GitHub Actions (see .github/workflows/numbers.yml) and commits to the `output` branch.
// With a PAT in METRICS_TOKEN the counts include private repos and orgs; with GITHUB_TOKEN they are public-only.

import { mkdirSync, writeFileSync } from "node:fs";

const login = process.env.GH_LOGIN || "edwynmoss";
const token = process.env.GH_TOKEN;
if (!token) throw new Error("GH_TOKEN is required");

const query = `
query($login: String!, $prs: String!) {
  user(login: $login) {
    contributionsCollection {
      contributionCalendar { totalContributions }
      totalCommitContributions
      restrictedContributionsCount
    }
    organizations(first: 100) { totalCount nodes { repositories(first: 1) { totalCount } } }
    repositories(first: 1, ownerAffiliations: [OWNER]) { totalCount }
    followers { totalCount }
  }
  merged: search(type: ISSUE, query: $prs) { issueCount }
}`;

const res = await fetch("https://api.github.com/graphql", {
  method: "POST",
  headers: { authorization: `bearer ${token}`, "content-type": "application/json", "user-agent": "numbers.mjs" },
  body: JSON.stringify({ query, variables: { login, prs: `is:pr is:merged author:${login}` } }),
});
const json = await res.json();
if (json.errors) throw new Error(JSON.stringify(json.errors, null, 2));

const u = json.data.user;
const numbers = {
  contributions12mo: u.contributionsCollection.contributionCalendar.totalContributions,
  commits12mo: u.contributionsCollection.totalCommitContributions + u.contributionsCollection.restrictedContributionsCount,
  repositories: u.repositories.totalCount + u.organizations.nodes.reduce((n, o) => n + o.repositories.totalCount, 0),
  organizations: u.organizations.totalCount,
  mergedPrs: json.data.merged.issueCount,
  followers: u.followers.totalCount,
  updated: new Date().toISOString().slice(0, 10),
};

const fmt = (n) => (n >= 10000 ? `${(n / 1000).toFixed(1).replace(/\.0$/, "")}k` : n.toLocaleString("en-US"));

const tiles = [
  { label: "CONTRIBUTIONS · 12 MO", value: fmt(numbers.contributions12mo) },
  { label: "MERGED PULL REQUESTS", value: fmt(numbers.mergedPrs) },
  { label: "REPOSITORIES", value: fmt(numbers.repositories) },
  { label: "ORGANISATIONS", value: fmt(numbers.organizations) },
];

const W = 900, H = 132, pad = 18, gap = 14;
const tileW = (W - pad * 2 - gap * (tiles.length - 1)) / tiles.length;

const tileSvg = tiles.map((t, i) => {
  const x = pad + i * (tileW + gap);
  const delay = (0.15 + i * 0.18).toFixed(2);
  return `
  <g transform="translate(${x} ${pad})">
    <rect width="${tileW}" height="${H - pad * 2}" rx="12" fill="#0F2A30" stroke="#1F6F78" stroke-opacity="0.6"/>
    <rect x="0" y="0" width="4" height="${H - pad * 2}" rx="2" fill="#F4B860" opacity="0.9"/>
    <g class="rise" style="animation-delay:${delay}s">
      <text class="v" x="20" y="56">${t.value}</text>
      <text class="l" x="20" y="80">${t.label}</text>
    </g>
  </g>`;
}).join("");

const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-label="GitHub numbers for ${login}">
  <defs>
    <style>
      .v { font: 800 38px "Segoe UI", "Helvetica Neue", Helvetica, Arial, sans-serif; fill: #F4B860; }
      .l { font: 600 11px Consolas, "SFMono-Regular", Menlo, "Courier New", monospace; fill: #3CB4B8; letter-spacing: 1.4px; }
      .u { font: 500 10px Consolas, "SFMono-Regular", Menlo, "Courier New", monospace; fill: #E7DCCB; opacity: .55; }
      .rise { opacity: 0; animation: rise .9s cubic-bezier(.2,.8,.2,1) forwards; }
      @keyframes rise { from { opacity: 0; transform: translateY(10px);} to { opacity: 1; transform: translateY(0);} }
    </style>
    <clipPath id="f"><rect width="${W}" height="${H}" rx="18"/></clipPath>
  </defs>
  <g clip-path="url(#f)">
    <rect width="${W}" height="${H}" fill="#0B1B1F"/>
    ${tileSvg}
    <text class="u" x="${W - pad}" y="${H - 6}" text-anchor="end">updated ${numbers.updated} · includes private work</text>
  </g>
</svg>
`;

mkdirSync("dist", { recursive: true });
writeFileSync("dist/numbers.svg", svg);
writeFileSync("dist/numbers.json", JSON.stringify(numbers, null, 2));
console.log(numbers);
