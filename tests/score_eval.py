"""Does the risk score separate small incidents from big ones? Measure it.

    python tests/score_eval.py <hayabusa verbose CSV> [--json out.json]

Build the CSV once from the public sample logs (Yamato-Security/
hayabusa-sample-evtx, about 600 real attack recordings):

    hayabusa dfir-timeline -d hayabusa-sample-evtx -o all.csv -p verbose -w -q -U

Each recording is one technique on one lab host. From them the script builds
cases whose expected gravity is known by construction:

  quiet       a recording whose detections are all low or informational
  single      one technique
  stage-2/3   two or three techniques from different ATT&CK folders
  chain-5/8   five or eight techniques from different folders: a full intrusion
  noisy       one technique whose detections are repeated 20 times

and scores every case with the current model and with candidate models. A good
model ranks the tiers in order, keeps single techniques away from the top,
does not reward repetition, and uses the whole 0-100 range.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dfirconsole import timeline  # noqa: E402

MITRE = {"InitAccess": "Initial Access", "Exec": "Execution", "Persis": "Persistence",
         "PrivEsc": "Privilege Escalation", "Evas": "Defense Evasion", "Stealth": "Defense Evasion",
         "DefImpair": "Defense Evasion", "CredAccess": "Credential Access", "Disc": "Discovery",
         "LatMov": "Lateral Movement", "Collect": "Collection", "C2": "Command and Control",
         "Exfil": "Exfiltration", "Impact": "Impact", "Recon": "Reconnaissance",
         "ResDev": "Resource Development"}
DECISIVE = timeline.TimelineReport.DECISIVE_TACTICS
TIERS = ["quiet", "single", "stage-2", "stage-3", "chain-5", "chain-8"]
TIER_RANK = {t: i for i, t in enumerate(TIERS)}


# --- features of one case --------------------------------------------------
def features(rows: list[dict], cols: dict[str, str]) -> dict:
    report = timeline.TimelineReport()
    distinct: dict[str, set] = defaultdict(set)
    mitre_alert: set[str] = set()
    for row in rows:
        report.ingest(row, cols)
        level = timeline._level(row.get("Level", ""))
        distinct[level].add(row.get("RuleTitle", ""))
        if level in ("critical", "high", "medium"):
            for tag in (row.get("MitreTactics") or "").split(" ¦ "):
                if tag.strip() in MITRE:
                    mitre_alert.add(MITRE[tag.strip()])
    return {
        "levels": Counter(report.levels),
        "distinct": {k: len(v) for k, v in distinct.items()},
        "tactics_keywords": set(report.tactics),
        "tactics_mitre": mitre_alert,
    }


# --- models ------------------------------------------------------------------
W = timeline.LEVEL_WEIGHT


def sev_current(f):
    raw = sum(W[lvl] * n for lvl, n in f["levels"].items())
    return min(45, round(6.5 * raw ** 0.5)) if raw else 0


def sev_distinct(f, k=40.0):
    """Distinct rules, saturating curve: repetition adds nothing."""
    d = f["distinct"]
    raw = 8 * d.get("critical", 0) + 3 * d.get("high", 0) + 1 * d.get("medium", 0)
    return round(45 * (1 - math.exp(-raw / k)))


def sev_hybrid(f, k=40.0):
    """Distinct rules, plus a small log bonus for volume."""
    d = f["distinct"]
    raw = 8 * d.get("critical", 0) + 3 * d.get("high", 0) + 1 * d.get("medium", 0)
    volume = sum(f["levels"].get(l, 0) for l in ("critical", "high", "medium"))
    raw += 2 * math.log1p(volume)
    return round(45 * (1 - math.exp(-raw / k)))


def chain_current(tactics):
    return min(25, 3 * len(tactics) + 3 * len(tactics & DECISIVE))


def chain_soft(tactics, k=6.0):
    breadth = len(tactics) + len(tactics & DECISIVE)
    return round(25 * (1 - math.exp(-breadth / k)))


def shipped(f):
    """The model Kage ships, through its own code."""
    report = timeline.TimelineReport()
    report.levels = Counter(f["levels"])
    report.distinct_rules = {k: f["distinct"].get(k, 0) for k in ("critical", "high", "medium")}
    report.tactics = Counter({t: 1 for t in f["tactics_mitre"]})
    return report.score_breakdown()["score"]


MODELS = {
    "current (keywords, counts)":
        lambda f: sev_current(f) + chain_current(f["tactics_keywords"]),
    "current curve, MITRE column":
        lambda f: sev_current(f) + chain_current(f["tactics_mitre"]),
    "distinct rules, keywords":
        lambda f: sev_distinct(f) + chain_current(f["tactics_keywords"]),
    "distinct rules, MITRE":
        lambda f: sev_distinct(f) + chain_current(f["tactics_mitre"]),
    "distinct rules, MITRE, soft chain":
        lambda f: sev_distinct(f) + chain_soft(f["tactics_mitre"]),
    "hybrid volume, MITRE, soft chain":
        lambda f: sev_hybrid(f) + chain_soft(f["tactics_mitre"]),
    "SHIPPED (dfirconsole.timeline)": shipped,
}


# --- cases -------------------------------------------------------------------
def build_cases(path: Path, seed: int = 7) -> tuple[list[dict], dict[str, str]]:
    by_file: dict[str, list[dict]] = defaultdict(list)
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        cols = timeline._map_columns(reader.fieldnames or [])
        for row in reader:
            by_file[row["EvtxFile"]].append(row)

    def folder(name: str) -> str:
        parts = Path(name.replace("\\", "/")).parts
        return parts[-2] if len(parts) >= 2 else "root"

    alerting = {f: rows for f, rows in by_file.items()
                if any(timeline._level(r["Level"]) in ("critical", "high", "medium") for r in rows)}
    quiet = [f for f in by_file if f not in alerting]
    groups: dict[str, list[str]] = defaultdict(list)
    for f in alerting:
        groups[folder(f)].append(f)

    rng = random.Random(seed)
    cases = [{"tier": "quiet", "rows": by_file[f], "name": f} for f in quiet]
    cases += [{"tier": "single", "rows": rows, "name": f} for f, rows in alerting.items()]
    names = [g for g in groups if len(groups[g]) >= 1]
    for tier, k in (("stage-2", 2), ("stage-3", 3), ("chain-5", 5), ("chain-8", 8)):
        for _ in range(120):
            picked = rng.sample(names, min(k, len(names)))
            files = [rng.choice(groups[g]) for g in picked]
            cases.append({"tier": tier, "name": " + ".join(Path(f).name for f in files),
                          "rows": [r for f in files for r in by_file[f]]})
    for f in rng.sample(list(alerting), min(60, len(alerting))):
        cases.append({"tier": "noisy", "name": f, "rows": alerting[f] * 20, "base": f})
    return cases, cols


def spearman(xs: list[float], ys: list[float]) -> float:
    def ranks(v):
        order = sorted(range(len(v)), key=lambda i: v[i])
        r = [0.0] * len(v)
        i = 0
        while i < len(v):
            j = i
            while j + 1 < len(v) and v[order[j + 1]] == v[order[i]]:
                j += 1
            for k in range(i, j + 1):
                r[order[k]] = (i + j) / 2
            i = j + 1
        return r
    rx, ry = ranks(xs), ranks(ys)
    mx, my = statistics.mean(rx), statistics.mean(ry)
    num = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    den = math.sqrt(sum((a - mx) ** 2 for a in rx) * sum((b - my) ** 2 for b in ry))
    return num / den if den else 0.0


def evaluate(cases: list[dict], cols: dict[str, str]) -> dict:
    for case in cases:
        case["f"] = features(case["rows"], cols)
    single_score = {}
    results = {}
    for name, model in MODELS.items():
        scores = defaultdict(list)
        for case in cases:
            case.setdefault("scores", {})[name] = model(case["f"])
            scores[case["tier"]].append(case["scores"][name])
            if case["tier"] == "single":
                single_score[(name, case["name"])] = case["scores"][name]
        ranked = [c for c in cases if c["tier"] in TIER_RANK]
        rho = spearman([TIER_RANK[c["tier"]] for c in ranked], [c["scores"][name] for c in ranked])
        # How often a full intrusion outranks a single technique (ties count half).
        wins = 0.0
        pairs = 0
        for a in scores["chain-8"]:
            for b in scores["single"]:
                wins += 1 if a > b else 0.5 if a == b else 0
                pairs += 1
        noisy_gain = [c["scores"][name] - single_score[(name, c["base"])]
                      for c in cases if c["tier"] == "noisy"]
        everything = [s for t in scores.values() for s in t]
        results[name] = {
            "median": {t: statistics.median(scores[t]) for t in TIERS + ["noisy"] if scores[t]},
            "single >= 70": round(100 * sum(s >= 70 for s in scores["single"]) / len(scores["single"]), 1),
            "chain-8 >= 70": round(100 * sum(s >= 70 for s in scores["chain-8"]) / len(scores["chain-8"]), 1),
            "chain-8 beats single": round(100 * wins / pairs, 1),
            "spearman": round(rho, 3),
            "noisy gain (median)": statistics.median(noisy_gain),
            "distinct scores": len(set(everything)),
            "share of top 3 values": round(100 * sum(n for _, n in Counter(everything).most_common(3)) / len(everything), 1),
        }
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("csv", type=Path)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    cases, cols = build_cases(args.csv)
    counts = Counter(c["tier"] for c in cases)
    print("cases:", dict(counts))
    results = evaluate(cases, cols)
    for name, r in results.items():
        med = " ".join(f"{t}:{v:g}" for t, v in r["median"].items())
        print(f"\n{name}\n  medians  {med}")
        print(f"  single>=70 {r['single >= 70']}%   chain-8>=70 {r['chain-8 >= 70']}%   "
              f"chain-8 beats single {r['chain-8 beats single']}%   spearman {r['spearman']}")
        print(f"  noisy gain {r['noisy gain (median)']}   distinct scores {r['distinct scores']}   "
              f"top-3 values hold {r['share of top 3 values']}% of cases")
    if args.json:
        args.json.write_text(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
