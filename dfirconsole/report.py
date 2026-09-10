"""Triage report — a self-contained document, ready to print to PDF.

The stance: this is not a reprinted dashboard, it is a case file. Fixed
structure (findings -> conclusion -> chain of custody -> exhibits), sober
typography, colour reserved for severity. No external resource: the file must
still be readable in ten years on an offline machine.
"""

from __future__ import annotations

import html
from datetime import datetime

LEVEL_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium",
               "low": "Low", "informational": "Info"}
STATUS_LABEL = {"done": "Sealed", "failed": "Failed", "skipped": "Skipped",
                "pending": "Not run", "running": "Interrupted"}

CSS = """
:root {
  --ink:      #0C1116;
  --panel:    #141D25;
  --panel-2:  #18232C;
  --line:     #24323C;
  --line-soft:#1C2831;
  --text:     #DCE5EA;
  --muted:    #93A6B2;
  --faint:    #6C7F8B;
  --brass:    #D6A345;
  --brass-dim:#A2802F;
  --crit:     #E5484D;
  --high:     #F0793B;
  --med:      #D6A345;
  --low:      #4A9FD4;
  --ok:       #37B37E;
}

@page { size: A4; margin: 14mm 12mm 16mm; }
* { box-sizing: border-box; }
body {
  font: 10.5pt/1.55 "IBM Plex Sans", "Segoe UI", system-ui, sans-serif;
  color: var(--text); background: var(--ink);
  margin: 0 auto; max-width: 195mm; padding: 14mm 10mm;
}
h1, h2, h3, .num, .eyebrow, th, dt { font-family: "Archivo", "Arial Narrow", system-ui, sans-serif; }
.mono, td.v, .seal { font-family: "IBM Plex Mono", Consolas, monospace; }

/* --- header --- */
.head { border-top: 3px solid var(--brass); padding-top: 12px; margin-bottom: 24px; }
.head__row { display: flex; justify-content: space-between; align-items: flex-start; gap: 20px; }
.head h1 { font-size: 22pt; font-weight: 800; letter-spacing: -.01em; margin: 0; text-transform: uppercase; }
.head__kind { font-size: 8pt; font-weight: 700; letter-spacing: .22em; text-transform: uppercase; color: var(--brass-dim); margin: 0 0 4px; }
.head__stamp {
  border: 1.5px solid var(--brass-dim); color: var(--brass); padding: 6px 12px; text-align: center;
  font-family: "Archivo", sans-serif; font-size: 8pt; font-weight: 800;
  letter-spacing: .14em; text-transform: uppercase; white-space: nowrap;
}
.meta { display: grid; grid-template-columns: repeat(4, 1fr); margin-top: 16px;
        border-top: 1px solid var(--line); border-bottom: 1px solid var(--line); }
.meta div { padding: 9px 12px 9px 0; border-right: 1px solid var(--line-soft); }
.meta div:last-child { border-right: none; }
.meta dt { font-size: 7.5pt; font-weight: 700; letter-spacing: .14em;
           text-transform: uppercase; color: var(--faint); margin: 0 0 3px; }
.meta dd { margin: 0; font-size: 9.5pt; font-family: "IBM Plex Mono", monospace;
           color: var(--muted); overflow-wrap: anywhere; line-height: 1.35; }

/* --- conclusion --- */
.verdict { display: grid; grid-template-columns: 96px 1fr; gap: 22px; align-items: start;
           border-left: 4px solid var(--faint); padding: 16px 18px; margin: 26px 0 10px;
           background: var(--panel); }
.verdict.sev-critical { border-left-color: var(--crit); }
.verdict.sev-high { border-left-color: var(--high); }
.verdict.sev-medium { border-left-color: var(--med); }
.verdict.sev-clean { border-left-color: var(--ok); }
.num { font-size: 42pt; font-weight: 800; line-height: .9; letter-spacing: -.03em; }
.num small { display: block; font-size: 8pt; font-weight: 700; letter-spacing: .14em;
             text-transform: uppercase; color: var(--faint); margin-top: 6px; }
.verdict h2 { font-size: 16pt; font-weight: 800; margin: 0 0 7px; line-height: 1.2; }
.verdict p { margin: 0; }
.breakdown { margin-top: 10px; font-size: 8pt; }
.breakdown td { border-bottom: 1px solid var(--line-soft); padding: 4px 8px 4px 0; }
.breakdown td:first-child { color: var(--text); font-family: "Archivo", sans-serif;
                            font-weight: 700; letter-spacing: .06em; text-transform: uppercase;
                            font-size: 7.5pt; }
.conf { font-size: 8pt; letter-spacing: .1em; text-transform: uppercase; color: var(--muted);
        font-family: "Archivo", sans-serif; font-weight: 700; }

.tallies { display: flex; margin: 12px 0 28px; border: 1px solid var(--line); }
.tallies div { flex: 1; padding: 9px 11px; border-right: 1px solid var(--line-soft); background: var(--panel); }
.tallies div:last-child { border-right: none; }
.tallies b { display: block; font-family: "IBM Plex Mono", monospace; font-size: 16pt;
             font-weight: 600; line-height: 1.1; }
.tallies span { font-family: "Archivo", sans-serif; font-size: 7pt; font-weight: 700;
                letter-spacing: .13em; text-transform: uppercase; color: var(--faint); }
.t-critical b { color: var(--crit); } .t-high b { color: var(--high); }
.t-medium b { color: var(--med); } .t-low b { color: var(--low); } .t-informational b { color: var(--faint); }

/* --- sections --- */
section { margin-bottom: 28px; }
h2.sec { font-size: 10pt; font-weight: 800; letter-spacing: .16em; text-transform: uppercase;
         margin: 0 0 11px; padding-bottom: 6px; border-bottom: 1.5px solid var(--brass-dim);
         display: flex; align-items: baseline; gap: 11px; page-break-after: avoid; }
h2.sec i { font-style: normal; font-family: "IBM Plex Mono", monospace; font-size: 8.5pt;
           color: var(--brass); font-weight: 600; }
p { margin: 0 0 9px; color: var(--muted); }
ol, ul { margin: 0 0 9px; padding-left: 20px; color: var(--muted); }
li { margin-bottom: 5px; }
li strong { color: var(--text); }
.lead { font-size: 11.5pt; color: var(--text); }
.note { border-left: 3px solid var(--brass-dim); background: rgba(214,163,69,.08);
        padding: 9px 13px; font-size: 9.5pt; color: var(--med); margin-bottom: 16px; }

/* --- tables --- */
table { width: 100%; border-collapse: collapse; font-size: 8.5pt; table-layout: fixed; }
th { font-size: 7pt; font-weight: 700; letter-spacing: .12em; text-transform: uppercase;
     text-align: left; color: var(--faint); padding: 7px 8px;
     border-bottom: 1.5px solid var(--line); background: var(--panel-2); }
td { padding: 7px 8px; border-bottom: 1px solid var(--line-soft); vertical-align: top;
     color: var(--muted); overflow-wrap: anywhere; }
tbody tr { page-break-inside: avoid; }
td.v { font-size: 8pt; color: var(--faint); }
.lv { font-family: "Archivo", sans-serif; font-size: 7pt; font-weight: 800;
      letter-spacing: .09em; text-transform: uppercase; padding: 2px 5px; white-space: nowrap; }
.lv-critical { background: rgba(229,72,77,.18); color: var(--crit); }
.lv-high { background: rgba(240,121,59,.16); color: var(--high); }
.lv-medium { background: rgba(214,163,69,.16); color: var(--med); }
.lv-low { background: rgba(74,159,212,.16); color: var(--low); }
.tac { font-size: 7pt; color: var(--faint); border: 1px solid var(--line);
       padding: 0 4px; margin-right: 3px; white-space: nowrap; }
.vd { font-family: "Archivo", sans-serif; font-weight: 800; font-size: 7.5pt;
      letter-spacing: .06em; text-transform: uppercase; }
.vd-malicious { color: var(--crit); } .vd-suspicious { color: var(--high); }
.vd-clean { color: var(--ok); } .vd-unknown, .vd-unchecked { color: var(--faint); }
.seal { font-size: 7.5pt; color: var(--brass-dim); letter-spacing: .06em; }
.none { color: var(--faint); font-style: italic; }
h3.sub { font-family: "Archivo", sans-serif; font-size: 8.5pt; font-weight: 800;
         letter-spacing: .14em; text-transform: uppercase; color: var(--brass-dim);
         margin: 18px 0 6px; page-break-after: avoid; }

/* --- footer --- */
.foot { margin-top: 32px; padding-top: 11px; border-top: 1px solid var(--line);
        font-size: 8pt; color: var(--faint); display: flex; justify-content: space-between; gap: 16px; }

/* Printing: dark backgrounds only come out if the browser is set to print
   background graphics. */
@media print {
  body { padding: 0; }
  * { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
}
"""


def _esc(value) -> str:
    return html.escape(str(value if value is not None else ""))


def _bullets(values, tag: str = "ul") -> str:
    if not values:
        return '<p class="none">Nothing to report.</p>'
    if isinstance(values, str):
        values = [values]
    items = "".join(f"<li>{_esc(v)}</li>" for v in values)
    return f"<{tag}>{items}</{tag}>"


def _section(number: str, title: str, body: str) -> str:
    return f'<section><h2 class="sec"><i>{number}</i>{_esc(title)}</h2>{body}</section>'


def _severity(score: int) -> str:
    return "critical" if score >= 75 else "high" if score >= 45 else "medium" if score >= 20 else "clean"


def _steps_table(steps: list[dict]) -> str:
    if not steps:
        return '<p class="none">No step recorded.</p>'
    rows = []
    for step in steps:
        seal = (f'<span class="seal" title="{_esc(step.get("seal_basis"))}">'
                f'{_esc(step.get("seal"))}</span><br>'
                f'<span class="v">{_esc(step.get("seal_basis"))}</span>'
                if step.get("seal") else "—")
        duration = f'{step["duration"]} s' if step.get("duration") is not None else "—"
        rows.append(
            f"<tr><td>{_esc(step.get('label'))}</td>"
            f"<td>{_esc(STATUS_LABEL.get(step.get('status'), step.get('status')))}</td>"
            f"<td>{duration}</td><td>{seal}</td>"
            f"<td class='v'>{_esc(step.get('message'))}</td></tr>"
        )
    return (
        "<table><colgroup><col style='width:27%'><col style='width:12%'>"
        "<col style='width:10%'><col style='width:22%'><col></colgroup>"
        "<thead><tr><th>Step</th><th>State</th><th>Duration</th><th>Seal</th>"
        f"<th>Result</th></tr></thead><tbody>{''.join(rows)}</tbody></table>"
    )


def _ioc_table(iocs: list[dict]) -> str:
    if not iocs:
        return '<p class="none">No indicator extracted.</p>'
    rows = []
    for ioc in iocs[:120]:
        data = ioc.get("enrichment") or {}
        vt = data.get("virustotal") or {}
        abuse = data.get("abuseipdb") or {}
        reputation = []
        if vt and not vt.get("error") and vt.get("found") is not False:
            total = sum(vt.get(k, 0) or 0 for k in ("malicious", "harmless", "undetected", "suspicious"))
            reputation.append(f"VirusTotal {vt.get('malicious', 0)}/{total or '?'}")
            if vt.get("label"):
                reputation.append(_esc(vt["label"]))
        if abuse and not abuse.get("error"):
            reputation.append(f"AbuseIPDB {abuse.get('score', 0)}% ({abuse.get('reports', 0)} reports)")
            if abuse.get("isp"):
                reputation.append(f"{abuse.get('country') or '??'} · {_esc(abuse['isp'])}")
        verdict = ioc.get("threat") or "unchecked"
        css = "vd-" + verdict.replace(" ", "")
        rows.append(
            f"<tr><td>{_esc(ioc.get('type'))}</td><td class='v'>{_esc(ioc.get('value'))}</td>"
            f"<td>{ioc.get('count', 0)}</td>"
            f"<td><span class='vd {css}'>{_esc(verdict)}</span></td>"
            f"<td class='v'>{' · '.join(reputation) or '—'}</td></tr>"
        )
    return (
        "<table><colgroup><col style='width:9%'><col style='width:32%'>"
        "<col style='width:7%'><col style='width:14%'><col></colgroup>"
        "<thead><tr><th>Type</th><th>Value</th><th>Hits</th><th>Verdict</th>"
        f"<th>Reputation</th></tr></thead><tbody>{''.join(rows)}</tbody></table>"
    )


def _findings_table(findings: list[dict], limit: int = 120) -> str:
    if not findings:
        return '<p class="none">No alert retained.</p>'
    rows = []
    for finding in findings[:limit]:
        tactics = "".join(f"<span class='tac'>{_esc(t)}</span>" for t in finding.get("tactics") or [])
        level = finding.get("level", "")
        rows.append(
            f"<tr><td class='v'>{_esc((finding.get('timestamp') or '')[:19].replace('T', ' '))}</td>"
            f"<td><span class='lv lv-{_esc(level)}'>{_esc(LEVEL_LABEL.get(level, level))}</span></td>"
            f"<td>{_esc(finding.get('rule'))}<br>{tactics}</td>"
            f"<td class='v'>{_esc(finding.get('event_id'))}</td>"
            f"<td class='v'>{_esc((finding.get('details') or '')[:280])}</td></tr>"
        )
    more = ""
    if len(findings) > limit:
        more = (f"<p class='none'>{len(findings) - limit} further alert(s) in the "
                "JSON export.</p>")
    return (
        "<table><colgroup><col style='width:14%'><col style='width:9%'>"
        "<col style='width:26%'><col style='width:7%'><col></colgroup>"
        "<thead><tr><th>Timestamp</th><th>Level</th><th>Rule</th><th>ID</th>"
        f"<th>Detail</th></tr></thead><tbody>{''.join(rows)}</tbody></table>{more}"
    )


def _yara_lines(alerts: list) -> list[str]:
    """Detections are objects since streaming parsing was introduced."""
    lines = []
    for alert in alerts[:40]:
        if isinstance(alert, dict):
            parts = [alert.get("message") or alert.get("rule") or "detection"]
            if alert.get("file"):
                parts.append(alert["file"])
            if alert.get("score") is not None:
                parts.append(f"score {alert['score']}")
            lines.append(" — ".join(parts)[:300])
        else:
            lines.append(str(alert)[:300])
    return lines


def _system_html(system: dict | None) -> str:
    if not system:
        return '<p class="none">System capture not performed.</p>'

    host = system.get("host", {})
    rows = "".join(
        f"<tr><td>{_esc(label)}</td><td class='v'>{_esc(host.get(key, '—'))}</td></tr>"
        for key, label in (
            ("hostname", "Machine name"), ("os_name", "Operating system"),
            ("os_version", "Version"), ("domain", "Domain"),
            ("logon_server", "Domain controller"), ("model", "Hardware"),
            ("install_date", "Installed on"), ("boot_time", "Booted on"),
            ("hotfix_count", "Hotfixes installed"),
        ) if host.get(key)
    )
    identity = (f"<table><colgroup><col style='width:30%'><col></colgroup><tbody>{rows}"
                "</tbody></table>") if rows else ""

    users = system.get("users", [])
    user_rows = "".join(
        f"<tr><td>{_esc(u['name'])}</td>"
        f"<td>{'yes' if u.get('admin') else 'no'}</td>"
        f"<td>{'enabled' if u.get('enabled') else ('disabled' if u.get('enabled') is False else '—')}</td>"
        f"<td class='v'>{_esc((u.get('last_logon') or '—')[:19].replace('T', ' '))}</td>"
        f"<td class='v'>{_esc(', '.join(u.get('flags') or []))}</td></tr>"
        for u in users
    )
    users_table = (
        "<table><colgroup><col style='width:20%'><col style='width:8%'>"
        "<col style='width:10%'><col style='width:20%'><col></colgroup>"
        "<thead><tr><th>Account</th><th>Admin</th><th>State</th><th>Last logon</th>"
        f"<th>Observations</th></tr></thead><tbody>{user_rows}</tbody></table>"
    ) if users else '<p class="none">No account captured.</p>'

    flagged = [c for c in system.get("connections", []) if c["risk"] != "normal"]
    conn_rows = "".join(
        f"<tr><td>{_esc(c['proto'])}</td>"
        f"<td class='v'>{_esc(c['local_ip'])}:{c['local_port']}</td>"
        f"<td class='v'>{_esc(c['remote_ip'])}{':' + str(c['remote_port']) if c['remote_port'] else ''}</td>"
        f"<td>{_esc(c['state'])}</td>"
        f"<td class='v'>{_esc(c['process'] or ('PID ' + str(c['pid'])))}</td>"
        f"<td class='v'>{_esc(' ; '.join(c['flags']))}</td></tr>"
        for c in flagged[:60]
    )
    conn_table = (
        "<table><colgroup><col style='width:7%'><col style='width:19%'>"
        "<col style='width:19%'><col style='width:12%'><col style='width:16%'><col>"
        "</colgroup><thead><tr><th>Proto</th><th>Local</th><th>Remote</th>"
        f"<th>State</th><th>Process</th><th>Observations</th></tr></thead>"
        f"<tbody>{conn_rows}</tbody></table>"
    ) if flagged else '<p class="none">No socket flagged.</p>'

    roots = system.get("root_entries", [])
    root_rows = "".join(
        f"<tr><td class='v'>{_esc(e['path'])}</td><td>{_esc(e['kind'])}</td>"
        f"<td class='v'>{_esc((e.get('created') or '—')[:19].replace('T', ' '))}</td>"
        f"<td class='v'>{_esc(' ; '.join(e['flags']))}</td></tr>"
        for e in roots[:40]
    )
    root_table = (
        "<table><colgroup><col style='width:28%'><col style='width:10%'>"
        "<col style='width:20%'><col></colgroup><thead><tr><th>Path</th>"
        f"<th>Type</th><th>Created</th><th>Observations</th></tr></thead>"
        f"<tbody>{root_rows}</tbody></table>"
    ) if roots else '<p class="none">Nothing unusual at the root.</p>'

    network = system.get("network", {})
    resume = (f"<p>{network.get('listening', 0)} listening port(s), "
              f"{network.get('established', 0)} established connection(s), "
              f"{network.get('flagged', 0)} flagged socket(s).</p>")

    coverage = system.get("coverage") or {}
    cov_html = ""
    if coverage:
        gaps = (f"<p class='note'>Blind spots: {_esc(' · '.join(coverage['gaps']))}</p>"
                if coverage.get("gaps") else "")
        chan_rows = "".join(
            f"<tr><td>{_esc(c['verdict'])}</td><td>{_esc(c['label'])}</td>"
            f"<td>{_esc(c['importance'])}</td>"
            f"<td class='v'>{c['records'] or '—'}</td>"
            f"<td class='v'>{_esc(c['comment'])}</td></tr>"
            for c in coverage.get("channels", [])
        )
        audit_rows = "".join(
            f"<tr><td>{_esc(a['state'])}</td><td>{_esc(a['label'])}</td>"
            f"<td>{_esc(a['importance'])}</td></tr>"
            for a in coverage.get("audit", [])
        )
        cov_html = (
            f"<p><strong>Coverage {coverage.get('score', 0)}/100</strong> — "
            f"{_esc(coverage.get('verdict', ''))}. Read this next to the risk "
            "score: it says how much of the activity the machine was able to "
            "record.</p>" + gaps
            + "<h3 class='sub'>Event channels</h3>"
            "<table><colgroup><col style='width:12%'><col style='width:26%'>"
            "<col style='width:12%'><col style='width:12%'><col></colgroup>"
            "<thead><tr><th>State</th><th>Channel</th><th>Importance</th>"
            f"<th>Events</th><th>Observations</th></tr></thead><tbody>{chan_rows}</tbody></table>"
            "<h3 class='sub'>Local audit policy</h3>"
            "<table><colgroup><col style='width:22%'><col><col style='width:14%'>"
            "</colgroup><thead><tr><th>State</th><th>Subcategory</th>"
            f"<th>Importance</th></tr></thead><tbody>{audit_rows}</tbody></table>"
        )

    return (identity
            + ("<h3 class='sub'>Logging &amp; audit</h3>" + cov_html if cov_html else "")
            + "<h3 class='sub'>Local accounts</h3>" + users_table
            + "<h3 class='sub'>Network</h3>" + resume + conn_table
            + "<h3 class='sub'>Disk root</h3>" + root_table)


def render(settings, case) -> str:
    report = case.report or {}
    ai = case.ai or {}
    levels = report.get("levels", {})
    score = report.get("risk_score", 0)
    severity = _severity(score)

    host = (report.get("computers") or [["—"]])[0][0]
    window = "—"
    if report.get("first_seen"):
        # Compact format: the date is repeated only when the window spans days.
        first, last = report["first_seen"], report.get("last_seen") or ""
        start = f"{first[8:10]}/{first[5:7]} {first[11:16]}"
        end = (last[11:16] if first[:10] == last[:10]
               else f"{last[8:10]}/{last[5:7]} {last[11:16]}")
        window = f"{start} → {end}"

    # The score is never published without its components: a reader must be
    # able to challenge a single axis rather than the number as a whole.
    breakdown = report.get("score_breakdown") or {}
    breakdown_html = ""
    if breakdown.get("components"):
        rows = "".join(
            f"<tr><td>{_esc(c['name'])}</td>"
            f"<td class='v'>{c['value']} / {c['max']}</td>"
            f"<td class='v'>{_esc(c['detail'])}</td></tr>"
            for c in breakdown["components"]
        )
        breakdown_html = (
            "<table class='breakdown'><colgroup><col style='width:22%'>"
            "<col style='width:14%'><col></colgroup><tbody>" + rows + "</tbody></table>"
        )

    tallies = "".join(
        f"<div class='t-{level}'><b>{levels.get(level, 0)}</b>"
        f"<span>{LEVEL_LABEL[level]}</span></div>"
        for level in ("critical", "high", "medium", "low", "informational")
    )

    key_findings = ai.get("key_findings") or []
    if isinstance(key_findings, list) and key_findings and isinstance(key_findings[0], dict):
        key_html = "<ul>" + "".join(
            f"<li><strong>{_esc(k.get('title'))}</strong>"
            f"{' — ' + _esc(k.get('why')) if k.get('why') else ''}</li>"
            for k in key_findings
        ) + "</ul>"
    else:
        key_html = _bullets(key_findings)

    blocklist = ai.get("iocs_to_block") or []
    if blocklist and isinstance(blocklist[0], dict):
        block_html = "<ul>" + "".join(
            f"<li><strong>{_esc(b.get('value'))}</strong> ({_esc(b.get('type'))})"
            f"{' — ' + _esc(b.get('reason')) if b.get('reason') else ''}</li>"
            for b in blocklist
        ) + "</ul>"
    else:
        block_html = _bullets(blocklist)

    note = f'<p class="note">{_esc(ai["note"])}</p>' if ai.get("note") else ""
    thor_alerts = (case.thor or {}).get("alerts") or []
    scanner_name = "THOR Lite" if case.thor else "not run"

    return f"""<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<title>Kage · Triage report — {_esc(settings.case_name)}</title>
<style>{CSS}</style></head><body>

<header class="head">
  <div class="head__row">
    <div>
      <p class="head__kind">Kage DFIR Toolkit · triage report — Windows host</p>
      <h1>{_esc(settings.case_name)}</h1>
    </div>
    <div class="head__stamp">Restricted<br>distribution</div>
  </div>
  <dl class="meta">
    <div><dt>Analyst</dt><dd>{_esc(settings.analyst or "not specified")}</dd></div>
    <div><dt>Host examined</dt><dd>{_esc(host)}</dd></div>
    <div><dt>Window observed</dt><dd>{_esc(window)}</dd></div>
    <div><dt>Issued on</dt><dd>{datetime.now().strftime("%Y-%m-%d %H:%M")}</dd></div>
  </dl>
</header>

<div class="verdict sev-{severity}">
  <div class="num">{score}<small>out of 100</small></div>
  <div>
    <h2>{_esc(ai.get("verdict") or report.get("verdict") or "Undetermined")}</h2>
    <p class="conf">Confidence {_esc(ai.get("confidence", "not assessed"))} ·
    {report.get("total", 0)} events analysed</p>
    {breakdown_html}
  </div>
</div>
<div class="tallies">{tallies}</div>

{note}

{_section("01", "Summary", f'<p class="lead">{_esc(ai.get("summary")) or "No summary produced."}</p>')}
{_section("02", "Probable sequence", _bullets(ai.get("attack_story"), "ol"))}
{_section("03", "Key findings", key_html)}
{_section("04", "Immediate containment", _bullets(ai.get("containment"), "ol"))}
{_section("05", "Indicators to block", block_html)}
{_section("06", "Next steps", _bullets(ai.get("next_steps"), "ol"))}
{_section("07", "Evidence gaps", _bullets(ai.get("evidence_gaps")))}
{_section("08", "Caveats and false positives",
          f'<p>{_esc(ai.get("false_positive_risk")) or "Not assessed."}</p>')}
{_section("09", "Chain of custody",
          _steps_table([case.steps[s].public() for s in case.order]))}
{_section("10", "Extracted indicators", _ioc_table(report.get("iocs", [])))}
{_section("11", "Timeline alerts", _findings_table(report.get("findings", [])))}
{_section("12", f"YARA scan ({scanner_name})", _bullets(_yara_lines(thor_alerts)))}
{_section("13", "System context", _system_html(case.system))}

<footer class="foot">
  <span>{_esc(settings.case_name)} · {_esc(settings.workspace)}</span>
  <span>Kage DFIR Toolkit — CyLR · Hayabusa · THOR Lite</span>
</footer>
</body></html>"""
