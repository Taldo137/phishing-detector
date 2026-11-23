"use strict";

// Email content is attacker-controlled: every value goes on the page with textContent,
// never as HTML, and URLs are shown as plain text, never as links.

const $ = (id) => document.getElementById(id);
let currentScanId = null;

function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = String(text);
  if (className) node.className = className;
  return node;
}

async function api(path, options = {}) {
  const response = await fetch("/api" + path, options);
  const servedBy = response.headers.get("X-Served-By");
  if (servedBy) $("served-by").textContent = `Served by ${servedBy}`;
  const body = await response.json().catch(() => null);
  if (!response.ok) throw new Error((body && body.detail) || `Request failed (HTTP ${response.status})`);
  return body;
}

function formatTime(iso) {
  return new Date(iso).toLocaleString("en-GB", { dateStyle: "medium", timeStyle: "short" });
}

async function onScan(event) {
  event.preventDefault();
  $("error").hidden = true;
  const file = $("file-input").files[0];
  const text = $("email-text").value;
  if (Boolean(file) === Boolean(text.trim())) {
    $("error").textContent = "Choose a file or paste an email (not both).";
    $("error").hidden = false;
    return;
  }
  const form = new FormData();
  if (file) form.append("file", file);
  else form.append("text", text);

  $("scan-button").disabled = true;
  try {
    const r = await api("/scan", { method: "POST", body: form });
    let meta = `Scan #${r.scan_id}`;
    if (r.previous_scan_id) meta += ` · previously scanned as #${r.previous_scan_id}`;
    if (r.cache === "hit") meta += " · cached result";
    showResult({ id: r.scan_id, risk_level: r.risk_level, verdict: r.verdict, score: r.score,
                 sender: r.summary.from, subject: r.summary.subject, findings: r.findings, user_label: null }, meta);
    loadHistory();
  } catch (error) {
    $("error").textContent = error.message;
    $("error").hidden = false;
  } finally {
    $("scan-button").disabled = false;
  }
}

function showResult(scan, meta) {
  currentScanId = scan.id;
  $("risk-badge").className = `badge risk-${scan.risk_level}`;
  $("risk-badge").textContent = `${scan.risk_level} RISK`;
  $("verdict").textContent = scan.verdict;
  $("score").textContent = scan.score;
  $("result-meta").textContent = meta;
  $("result-from").textContent = scan.sender || "(unknown)";
  $("result-subject").textContent = scan.subject || "(none)";

  // Trust signals (negative points) are shown in green, e.g. "-15".
  $("findings-body").replaceChildren(...scan.findings.map((f) => {
    const trust = f.points < 0;
    const row = el("tr");
    const severity = el("td");
    severity.append(el("span", trust ? "trust signal" : f.severity, `pill sev-${f.severity}`));
    row.append(severity, el("td", f.category), el("td", f.title), el("td", f.evidence, "evidence"),
               el("td", trust ? f.points : `+${f.points}`, trust ? "num trust" : "num"));
    return row;
  }));
  $("findings-table").hidden = scan.findings.length === 0;
  $("no-findings").hidden = scan.findings.length > 0;
  showLabel(scan.user_label);
  $("result-card").hidden = false;
}

function showLabel(label) {
  $("label-status").textContent = label ? `Your label: ${label}` : "Is this verdict right? Your feedback is saved.";
}

async function setLabel(label) {
  try {
    const scan = await api(`/history/${currentScanId}/label`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ label }),
    });
    showLabel(scan.user_label);
    loadHistory();
  } catch (error) {
    $("label-status").textContent = `Could not save the label: ${error.message}`;
  }
}

async function loadHistory() {
  const scans = await api("/history?limit=20").catch(() => []);
  $("history-body").replaceChildren(...scans.map((s) => {
    const level = el("td");
    level.append(el("span", s.risk_level, `pill risk-${s.risk_level}`));
    const row = el("tr");
    row.append(el("td", formatTime(s.created_at)), el("td", s.sender || "(unknown)"), el("td", s.subject || "(none)"),
               el("td", s.score, "num"), level, el("td", s.user_label || "-"));
    row.addEventListener("click", async () => {
      const scan = await api(`/history/${s.id}`);
      showResult(scan, `Scan #${scan.id} · ${formatTime(scan.created_at)}`);
      $("result-card").scrollIntoView({ behavior: "smooth" });
    });
    return row;
  }));
}

document.addEventListener("DOMContentLoaded", () => {
  $("scan-form").addEventListener("submit", onScan);
  $("label-phishing").addEventListener("click", () => setLabel("phishing"));
  $("label-safe").addEventListener("click", () => setLabel("safe"));
  loadHistory();
});
