"""Automatic write-up of the triage by a language model.

The model receives a compact summary — never the raw timeline, which would
blow up context and cost — and returns strict JSON that is validated before
display. On a malformed answer we fall back to a deterministic local report,
so the analyst always ends up with something.
"""

from __future__ import annotations

import json
import re

import httpx

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"

# Each provider has its own endpoint. Picking "groq" and landing on
# api.openai.com would be confusing at best, and a key leaked to the wrong
# service at worst. Nothing is guessed; the mapping is explicit.
PROVIDERS: dict[str, dict] = {
    "anthropic": {
        "label": "Anthropic (Claude)",
        "dialect": "anthropic",
        "base_url": "",
        "default_model": "claude-sonnet-4-6",
        "needs_key": True,
    },
    "openai": {
        "label": "OpenAI",
        "dialect": "openai",
        "base_url": "https://api.openai.com/v1",
        "default_model": "gpt-4o",
        "needs_key": True,
    },
    "groq": {
        "label": "Groq",
        "dialect": "openai",
        "base_url": "https://api.groq.com/openai/v1",
        "default_model": "llama-3.3-70b-versatile",
        "needs_key": True,
        # Free tier: 12 000 tokens per minute, request included.
        "max_chars": 24_000,
    },
    "mistral": {
        "label": "Mistral",
        "dialect": "openai",
        "base_url": "https://api.mistral.ai/v1",
        "default_model": "mistral-large-latest",
        "needs_key": True,
        "max_chars": 60_000,
    },
    "openrouter": {
        "label": "OpenRouter",
        "dialect": "openai",
        "base_url": "https://openrouter.ai/api/v1",
        "default_model": "anthropic/claude-sonnet-4",
        "needs_key": True,
    },
    "ollama": {
        "label": "Ollama (local)",
        "dialect": "openai",
        "base_url": "http://localhost:11434/v1",
        "default_model": "llama3.1",
        "needs_key": False,
        # Local models usually run with a small context window.
        "max_chars": 20_000,
    },
    "custom": {
        "label": "Other OpenAI-compatible service",
        "dialect": "openai",
        "base_url": "",
        "default_model": "",
        "needs_key": False,
    },
    "none": {
        "label": "None — local summary",
        "dialect": "local",
        "base_url": "",
        "default_model": "",
        "needs_key": False,
    },
}


def provider_catalog() -> list[dict]:
    """Catalogue for the interface, no secrets exposed."""
    return [
        {"id": key, "label": spec["label"], "base_url": spec["base_url"],
         "default_model": spec["default_model"], "needs_key": spec["needs_key"]}
        for key, spec in PROVIDERS.items()
    ]

SYSTEM_PROMPT = """You are a senior DFIR analyst writing the triage section of
an incident report that will be read by a CISO and, possibly, by counsel. You receive the summary of a \
Hayabusa/THOR triage on a Windows host, plus VirusTotal and AbuseIPDB \
enrichment for the extracted indicators.

Reply ONLY with a valid JSON object, no surrounding text, no Markdown fences, \
with exactly these keys:
{
  "verdict": "one-sentence conclusion, calibrated to the evidence",
  "confidence": "low|medium|high",
  "confidence_rationale": "why that confidence: which sources agree or are missing",
  "summary": "3 to 6 sentences aimed at a CISO, quantified",
  "attack_story": ["probable chronological steps of the attack"],
  "key_findings": [{"title": "...", "why": "...", "severity": "critical|high|medium|low"}],
  "iocs_to_block": [{"value": "...", "type": "...", "reason": "..."}],
  "containment": ["immediate containment actions, in priority order"],
  "next_steps": ["further investigation, each with the artefact to examine"],
  "evidence_gaps": ["what was not observable, and what it prevents concluding"],
  "false_positive_risk": "what could explain these alerts benignly"
}

Standards to hold to:
  * Distinguish OBSERVED (present in the data) from ASSESSED (your inference).
    Prefix assessed statements with "Assessed:" and state the basis.
  * Use calibrated language: "confirmed", "likely", "possible", "insufficient
    evidence". Never write "confirmed" for something a single source suggests.
  * Quantify. "12 credential-access alerts between 09:14 and 09:31" beats
    "several suspicious events".
  * Name the limits. If logging coverage is partial, say which tactics could
    not have been observed at all, and temper the conclusion accordingly.
  * Consider the benign explanation explicitly. Administration tooling,
    security scanners, pentest labs and backup agents trigger the same rules
    as an intruder.
  * Never invent an indicator, hostname, account or timestamp absent from the
    data you were given.
  * Reference ATT&CK technique IDs where the mapping is unambiguous.
  * Write in English, in plain declarative sentences."""


# Rough characters-per-token ratio for budgeting. Deliberately pessimistic:
# overshooting a rate limit costs a full round trip.
CHARS_PER_TOKEN = 3.2


def _payload(report: dict, thor: dict | None, context: dict,
             max_findings: int = 40, max_iocs: int = 30,
             detail_chars: int = 220) -> str:
    findings = report.get("findings", [])[:max_findings]
    iocs = report.get("iocs", [])[:max_iocs]

    compact_findings = [
        {
            "ts": f.get("timestamp"),
            "level": f.get("level"),
            "rule": f.get("rule"),
            "eid": f.get("event_id"),
            "tactics": f.get("tactics"),
            "details": (f.get("details") or "")[:detail_chars],
        }
        for f in findings
    ]
    compact_iocs = [
        {
            "type": i.get("type"),
            "value": i.get("value"),
            "hits": i.get("count"),
            "level": i.get("max_level"),
            "verdict": i.get("threat"),
            "vt": (i.get("enrichment") or {}).get("virustotal"),
            "abuse": (i.get("enrichment") or {}).get("abuseipdb"),
        }
        for i in iocs
    ]

    return json.dumps(
        {
            "case": context,
            "risk_score": report.get("risk_score"),
            "score_breakdown": report.get("score_breakdown"),
            "automatic_verdict": report.get("verdict"),
            "logging_coverage": context.get("coverage"),
            "events_excluded_as_own_tooling": report.get("self_noise"),
            "volumes_by_level": report.get("levels"),
            "time_window": [report.get("first_seen"), report.get("last_seen")],
            "most_frequent_rules": report.get("top_rules", [])[: max(4, max_findings // 4)],
            "observed_tactics": report.get("tactics", []),
            "alerts": compact_findings,
            "indicators": compact_iocs,
            "yara_thor": [
                {"message": a.get("message"), "file": a.get("file"),
                 "score": a.get("score")} if isinstance(a, dict) else str(a)[:160]
                for a in (thor or {}).get("alerts", [])[: max(4, max_findings // 4)]
            ],
        },
        ensure_ascii=False,
    )


def _extract_json(text: str) -> dict | None:
    text = text.strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if fenced:
        text = fenced.group(1)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None


def local_report(report: dict, thor: dict | None = None,
                 system: dict | None = None) -> dict:
    """Deterministic fallback, no network call.

    Written to the same standard as the model output: quantified, calibrated,
    and explicit about what could not be observed.
    """
    levels = report.get("levels", {})
    iocs = report.get("iocs", [])
    flagged = [i for i in iocs if i.get("threat") in ("malicious", "suspicious")]
    tactics = [name for name, _ in report.get("tactics", [])]
    breakdown = report.get("score_breakdown") or {}
    confidence = breakdown.get("confidence", "low")
    coverage = ((system or {}).get("coverage") or {})
    yara_alerts = (thor or {}).get("alerts") or []

    window = ""
    if report.get("first_seen"):
        window = (f" between {report['first_seen'][:16].replace('T', ' ')} and "
                  f"{(report.get('last_seen') or '')[:16].replace('T', ' ')}")

    # -- key findings, taken from the actual alerts rather than rule frequency
    key: list[dict] = []
    seen: set[str] = set()
    for finding in report.get("findings", []):
        rule = finding.get("rule", "")
        if rule in seen or finding.get("level") not in ("critical", "high"):
            continue
        seen.add(rule)
        why = ", ".join(finding.get("tactics") or []) or "no tactic inferred"
        key.append({
            "title": rule,
            "why": f"Observed at {(finding.get('timestamp') or '')[:19].replace('T', ' ')} — {why}",
            "severity": finding["level"],
        })
        if len(key) >= 10:
            break

    summary = (
        f"Hayabusa correlated {report.get('total', 0)} events{window}, of which "
        f"{levels.get('critical', 0)} are critical and {levels.get('high', 0)} high. "
        f"Risk score {breakdown.get('score', report.get('risk_score', 0))}/100 "
        f"({', '.join(f'{c['name'].lower()} {c['value']}/{c['max']}' for c in breakdown.get('components', []))}). "
        f"{len(flagged)} indicator(s) were flagged by reputation sources and "
        f"{len(yara_alerts)} file(s) matched a YARA rule. "
        "Assessed: this is an automated triage, and the findings below are "
        "ordered by severity rather than by investigative relevance."
    )

    gaps: list[str] = []
    if coverage:
        gaps.append(
            f"Logging coverage {coverage.get('score')}/100 — {coverage.get('verdict')}."
        )
        if coverage.get("gaps"):
            gaps.append("No visibility on: " + ", ".join(coverage["gaps"]) +
                        ". Activity relying on these cannot be excluded.")
    if not flagged:
        gaps.append("No indicator was confirmed by an external source; the "
                    "verdict rests on Sigma correlation alone.")
    if report.get("self_noise"):
        gaps.append(f"{report['self_noise']} event(s) produced by the triage "
                    "tooling itself were excluded from the counts.")

    return {
        "generated_by": "local",
        "verdict": report.get("verdict", "Undetermined"),
        "confidence": confidence,
        "confidence_rationale": (
            "Derived from the number of agreeing sources and the logging "
            f"coverage. {'; '.join(gaps) if gaps else 'No limitation recorded.'}"
        ),
        "summary": summary,
        "attack_story": tactics or ["No ATT&CK tactic could be inferred from rule titles."],
        "key_findings": key,
        "iocs_to_block": [
            {"value": i["value"], "type": i["type"],
             "reason": f"{i.get('threat')} — {(i.get('rules') or ['no context'])[0]}"}
            for i in flagged[:15]
        ],
        "containment": [
            "Isolate the host from the network while keeping it powered on.",
            "Preserve the collection archive and the timeline before any remediation.",
            "Reset every account that opened a session during the window above.",
            "Block the indicators listed below at the perimeter.",
        ],
        "next_steps": [
            "Compare the timeline against a clean host built from the same image.",
            "Hunt the flagged indicators across the rest of the estate.",
            "Review the parent processes of the critical alerts in the reading pane.",
        ],
        "evidence_gaps": gaps or ["No limitation recorded."],
        "false_positive_risk": (
            "Administration tooling, security scanners and pentest labs trigger "
            "rules that look much like an intruder's. Before escalating, confirm "
            "that the flagged binaries and accounts are not part of a sanctioned "
            "activity on this host."
        ),
    }


async def _call_anthropic(payload: str, key: str, model: str) -> tuple[str | None, str]:
    body = {
        "model": model,
        "max_tokens": 3000,
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": payload}],
    }
    headers = {
        "x-api-key": key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    async with httpx.AsyncClient(timeout=180.0) as client:
        response = await client.post(ANTHROPIC_URL, headers=headers, json=body)
    if response.status_code >= 400:
        return None, _error_detail(response)
    text = "".join(
        block.get("text", "")
        for block in response.json().get("content", [])
        if block.get("type") == "text"
    )
    return text, ""


async def _call_openai(payload: str, key: str, model: str, base_url: str) -> tuple[str | None, str]:
    """OpenAI /chat/completions dialect — Groq, Mistral, Ollama, OpenRouter…"""
    url = base_url.rstrip("/") + "/chat/completions"
    body = {
        "model": model,
        "max_tokens": 3000,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": payload},
        ],
    }
    headers = {"content-type": "application/json"}
    if key:  # un service local n'en demande pas
        headers["authorization"] = f"Bearer {key}"

    async with httpx.AsyncClient(timeout=300.0) as client:
        response = await client.post(url, headers=headers, json=body)
    if response.status_code >= 400:
        return None, _error_detail(response)
    choices = response.json().get("choices") or []
    if not choices:
        return None, "empty response"
    return (choices[0].get("message") or {}).get("content", ""), ""


def _is_too_large(error: str | None) -> bool:
    """Recognise a size rejection whatever the provider's wording."""
    if not error:
        return False
    lowered = error.lower()
    return ("413" in lowered or "too large" in lowered or "too long" in lowered
            or "context length" in lowered or "maximum context" in lowered
            or "rate limit" in lowered and "token" in lowered)


def _error_detail(response: httpx.Response) -> str:
    try:
        data = response.json()
        message = data.get("error", {})
        detail = message.get("message") if isinstance(message, dict) else str(message)
    except ValueError:
        detail = response.text[:200]
    return f"HTTP {response.status_code} : {detail}"


async def analyse(
    report: dict,
    api_key: str = "",
    model: str = "claude-sonnet-4-6",
    thor: dict | None = None,
    context: dict | None = None,
    provider: str = "anthropic",
    base_url: str = "",
    max_chars: int = 0,
    system: dict | None = None,
) -> dict:
    """Summarise the triage. The AI is optional: with no reachable provider the
    local report takes over and the analyst still gets a write-up."""
    provider = (provider or "anthropic").lower()
    if provider in ("aucun", "local", ""):
        provider = "none"

    spec = PROVIDERS.get(provider)
    if spec is None:
        result = local_report(report, thor, system)
        result["note"] = (f"Unknown provider '{provider}'. Accepted values: "
                          + ", ".join(PROVIDERS) + ". Local summary.")
        return result

    if spec["dialect"] == "local":
        result = local_report(report, thor, system)
        result["note"] = "Local summary (no AI provider selected)."
        return result

    # L'adresse du fournisseur choisi prime ; l'analyste peut la surcharger.
    endpoint = base_url.strip() or spec["base_url"]
    if spec["dialect"] == "openai" and not endpoint:
        result = local_report(report, thor, system)
        result["note"] = (f"{spec['label']}: no base URL configured. Local summary.")
        return result

    if spec["needs_key"] and not api_key:
        result = local_report(report, thor, system)
        result["note"] = f"No {spec['label']} key configured — local summary."
        return result

    model = model or spec["default_model"]

    # Free tiers cap tokens per minute — Groq allows 12 000. Rather than
    # failing, we retry with a progressively tighter summary: fewer alerts,
    # fewer indicators, shorter details. The verdict survives; only the
    # supporting evidence thins out.
    budgets = [(40, 30, 220), (18, 14, 130), (8, 8, 80), (4, 5, 50)]
    # An explicit setting wins; otherwise the provider's own ceiling applies.
    ceiling = max_chars or spec.get("max_chars", 0)
    if ceiling:
        fitting = [b for b in budgets
                   if len(_payload(report, thor, context or {}, *b)) <= ceiling]
        budgets = fitting or budgets[-1:]

    text = error = None
    for attempt, (n_findings, n_iocs, detail) in enumerate(budgets):
        payload = _payload(report, thor, context or {}, n_findings, n_iocs, detail)
        if ceiling and len(payload) > ceiling:
            # Last resort: even the tightest budget overflows. Better a
            # truncated summary than no summary at all.
            payload = payload[:ceiling] + '\n… (truncated)"}'

        try:
            if spec["dialect"] == "anthropic":
                text, error = await _call_anthropic(payload, api_key, model)
            else:
                text, error = await _call_openai(payload, api_key, model, endpoint)
        except httpx.HTTPError as exc:
            result = local_report(report, thor, system)
            result["note"] = f"Provider unreachable ({exc.__class__.__name__}) — local summary."
            return result

        if text is not None:
            break
        if not _is_too_large(error) or attempt == len(budgets) - 1:
            break

    if text is None:
        result = local_report(report, thor, system)
        hint = ""
        if _is_too_large(error):
            hint = (" The summary was trimmed several times and still exceeds the "
                    "provider's limit — pick a model with a larger context, or "
                    "lower « Indicators to check ».")
        result["note"] = f"{spec['label']} — {error} · local summary.{hint}"
        return result

    parsed = _extract_json(text)
    if not parsed:
        result = local_report(report, thor, system)
        result["note"] = "Model reply could not be parsed — local summary."
        return result

    parsed["generated_by"] = f"{model} · {spec['label']}"
    return parsed
