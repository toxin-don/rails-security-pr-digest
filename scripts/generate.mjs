import fs from "node:fs";
import path from "node:path";
import yaml from "js-yaml";

const OWNER = "rails";
const REPO = "rails";
const ROOT = process.cwd();
const RULES_PATH = path.join(ROOT, "rules", "security_rules.yml");

function readRules() {
  const raw = fs.readFileSync(RULES_PATH, "utf8");
  const rules = yaml.load(raw) ?? {};
  rules.window ??= { type: "hours", value: 24 };
  rules.decision ??= { threshold: 8 };
  rules.strongSignals ??= { patterns: [] };
  rules.scoring ??= { labelWeights: {}, textKeywordWeights: {}, pathWeights: {} };
  rules.securityGuideMapping ??= [];
  return rules;
}

function isoHoursAgo(h) {
  return new Date(Date.now() - h * 3600 * 1000).toISOString();
}

function ymdFromIso(iso) {
  return iso.slice(0, 10);
}

function compileWeightedRegexMap(obj) {
  return Object.entries(obj ?? {}).map(([pattern, weight]) => ({
    re: new RegExp(pattern),
    pattern,
    weight: Number(weight) || 0,
  }));
}

async function ghFetch(url, token) {
  const res = await fetch(url, {
    headers: {
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "rails-security-pr-digest",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`GitHub API ${res.status} ${res.statusText}\n${url}\n${body}`);
  }
  return res.json();
}

// Search API で候補PR番号を拾う（速い）→ pulls API で merged_at を厳密チェック
async function searchMergedPRNumbersSinceDate(dateYYYYMMDD, token) {
  const q = encodeURIComponent(`repo:${OWNER}/${REPO} is:pr is:merged merged:>=${dateYYYYMMDD}`);
  const url = `https://api.github.com/search/issues?q=${q}&per_page=100&page=1`;
  const data = await ghFetch(url, token);
  const items = Array.isArray(data.items) ? data.items : [];
  return items.map((i) => i.number).filter(Boolean);
}

async function getPR(number, token) {
  return ghFetch(`https://api.github.com/repos/${OWNER}/${REPO}/pulls/${number}`, token);
}

async function getIssueLabels(number, token) {
  const issue = await ghFetch(`https://api.github.com/repos/${OWNER}/${REPO}/issues/${number}`, token);
  return (issue.labels ?? []).map((l) => l?.name).filter(Boolean);
}

async function getPRFiles(number, token) {
  const perPage = 100;
  const maxPages = 3; // 大型PRは切る（判定用途なら十分）
  const files = [];
  for (let page = 1; page <= maxPages; page++) {
    const url = `https://api.github.com/repos/${OWNER}/${REPO}/pulls/${number}/files?per_page=${perPage}&page=${page}`;
    const items = await ghFetch(url, token);
    if (!Array.isArray(items) || items.length === 0) break;
    for (const it of items) if (it?.filename) files.push(it.filename);
    if (items.length < perPage) break;
  }
  return files;
}

function scoreOne({ title, body, labels, files }, rules) {
  const text = `${title ?? ""}\n\n${body ?? ""}`;

  // strong signal
  let strongHit = "";
  for (const p of rules.strongSignals.patterns ?? []) {
    const re = new RegExp(p);
    if (re.test(text)) {
      strongHit = p;
      break;
    }
  }

  const hits = [];
  let score = 0;

  // labels
  const lw = rules.scoring.labelWeights ?? {};
  for (const l of labels) {
    const w = Number(lw[l] ?? 0);
    if (w) {
      score += w;
      hits.push({ type: "label", what: l, w });
    }
  }

  // text keywords
  for (const r of compileWeightedRegexMap(rules.scoring.textKeywordWeights)) {
    if (r.re.test(text)) {
      score += r.weight;
      hits.push({ type: "text", what: r.pattern, w: r.weight });
    }
  }

  // path keywords
  for (const r of compileWeightedRegexMap(rules.scoring.pathWeights)) {
    for (const f of files) {
      if (r.re.test(f)) {
        score += r.weight;
        hits.push({ type: "path", what: r.pattern, file: f, w: r.weight });
      }
    }
  }

  // security guide mapping tags
  const tags = [];
  for (const m of rules.securityGuideMapping ?? []) {
    const tag = m.tag;
    const bonus = Number(m.scoreBonus ?? 0);
    const kwRes = (m.keywords ?? []).map((k) => new RegExp(k));
    const pRes = (m.paths ?? []).map((p) => new RegExp(p));
    const kwHit = kwRes.some((re) => re.test(text));
    const pHit = files.some((f) => pRes.some((re) => re.test(f)));
    if (kwHit || pHit) {
      tags.push(tag);
      if (bonus) {
        score += bonus;
        hits.push({ type: "guide", what: tag, w: bonus });
      }
    }
  }

  const threshold = Number(rules.decision.threshold ?? 8);
  const adopt = Boolean(strongHit) || score >= threshold;

  return { adopt, score, strongHit, tags, hits };
}

function mdEscape(s) {
  return String(s ?? "").replace(/\|/g, "\\|");
}

function buildMarkdown({ generatedAt, sinceIso, items }) {
  const lines = [];
  lines.push(`# rails-security-pr-digest`);
  lines.push(``);
  lines.push(`Generated at: **${generatedAt}**`);
  lines.push(`Window start: **${sinceIso}**`);
  lines.push(`Target: **${OWNER}/${REPO}**`);
  lines.push(``);
  lines.push(`## Latest security-related merged PRs`);
  lines.push(``);

  if (items.length === 0) {
    lines.push(`No matching PRs in this window.`);
    lines.push(``);
    return lines.join("\n");
  }

  for (const it of items) {
    const tagStr = it.tags.length ? it.tags.map((t) => `\`${t}\``).join(" ") : "";
    lines.push(`### #${it.number} — ${mdEscape(it.title)}`);
    lines.push(`- URL: ${it.url}`);
    lines.push(`- Merged: ${it.merged_at}`);
    lines.push(`- Score: **${it.score}**${tagStr ? ` (${tagStr})` : ""}`);
    if (it.strongHit) lines.push(`- Strong signal: \`${it.strongHit}\``);
    if (it.labels.length) lines.push(`- Labels: ${it.labels.map((l) => `\`${mdEscape(l)}\``).join(" ")}`);

    if (it.files.length) {
      const shown = it.files.slice(0, 20);
      lines.push(`- Files (${it.files.length}):`);
      for (const f of shown) lines.push(`  - \`${mdEscape(f)}\``);
      if (it.files.length > shown.length) lines.push(`  - …`);
    }

    const top = it.hits.slice(0, 8);
    if (top.length) {
      lines.push(`- Why picked (top hits):`);
      for (const h of top) {
        if (h.type === "label") lines.push(`  - label: \`${mdEscape(h.what)}\` (+${h.w})`);
        if (h.type === "text") lines.push(`  - text: \`${mdEscape(h.what)}\` (+${h.w})`);
        if (h.type === "path") lines.push(`  - path: \`${mdEscape(h.what)}\` on \`${mdEscape(h.file)}\` (+${h.w})`);
        if (h.type === "guide") lines.push(`  - guide: \`${mdEscape(h.what)}\` (+${h.w})`);
      }
      if (it.hits.length > top.length) lines.push(`  - …`);
    }

    lines.push(``);
  }

  return lines.join("\n");
}

async function main() {
  const token = process.env.GITHUB_TOKEN || "";
  const rules = readRules();

  const hours = Number(rules.window?.value ?? 24);
  const sinceIso = isoHoursAgo(hours);
  const since = new Date(sinceIso);

  // Search API は日付粒度なので余裕を持たせる（24hなら +24h バッファ）
  const sinceBuffered = new Date(Date.now() - (hours + 24) * 3600 * 1000).toISOString();
  const dateForSearch = ymdFromIso(sinceBuffered);

  const numbers = await searchMergedPRNumbersSinceDate(dateForSearch, token);

  const picked = [];

  for (const n of numbers) {
    const pr = await getPR(n, token);
    if (!pr?.merged_at) continue;

    const mergedAt = new Date(pr.merged_at);
    if (mergedAt < since) continue; // 厳密に window で切る

    const labels = await getIssueLabels(n, token);
    const files = await getPRFiles(n, token);

    const { adopt, score, strongHit, tags, hits } = scoreOne(
      { title: pr.title, body: pr.body, labels, files },
      rules
    );
    if (!adopt) continue;

    picked.push({
      number: n,
      title: pr.title,
      url: pr.html_url,
      merged_at: pr.merged_at,
      labels,
      files,
      score,
      strongHit,
      tags,
      hits,
    });
  }

  picked.sort((a, b) => new Date(b.merged_at) - new Date(a.merged_at));

  const generatedAt = new Date().toISOString();
  const md = buildMarkdown({ generatedAt, sinceIso, items: picked });

  fs.writeFileSync(path.join(ROOT, "docs", "index.md"), md, "utf8");
  console.log(`Generated docs/index.md with ${picked.length} PRs`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
