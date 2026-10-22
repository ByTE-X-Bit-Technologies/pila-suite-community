"""
BXB Security Score — Host scoring engine (Free / Community edition)
==================================================================

Pure, deterministic scoring logic. No I/O, no framework. Given the raw
signals gathered by the collector + the prove step, it produces:

  * five plain-language category sub-scores (0-100)
  * one weighted overall score (0-100) and a letter grade
  * a ranked list of the highest-impact fixes
  * a one-line verdict

This is the "Score" in Scan -> Score -> Fix -> Prove. It is intentionally
free of any dependency on the proprietary engines so the Community build can
compute a real grade on a single host with nothing else installed. When wired
into pila-suite at home, the richer AESP/GHOST numbers can be fed in through
`Signals` without changing the grade maths.

Design notes
------------
* Everything is a float 0-100 internally; grades are derived once at the end.
* `CATEGORY_WEIGHTS` is the single knob that decides how the five categories
  roll into the headline number. Keep it summing to 1.0.
* Fix impact is estimated honestly: for each weak category we compute how much
  the *overall* score would rise if that category were lifted to a realistic
  target, then rank by that delta. No invented numbers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
import math


# ── Category model ────────────────────────────────────────────────────────────

# The five plain categories the user sees. Internal key -> display label.
CATEGORIES = {
    "attack_coverage": "Attack coverage",
    "visibility": "Visibility / logging",
    "response_readiness": "Response readiness",
    "config_hardening": "Config hardening",
    "patch_posture": "Patch & vuln posture",
}

# One-line plain explanation of what each category actually measures (shown in the UI).
CATEGORY_METHOD = {
    "attack_coverage": "Emulates host-safe attacker techniques and checks whether this host's telemetry caught them.",
    "visibility": "Checks that the log sources needed to see an attack are present and reporting.",
    "response_readiness": "Looks for the means to contain an incident here: endpoint detection, an isolation path, and an IR playbook.",
    "config_hardening": "Runs host hardening checks (firewall, remote login, automatic updates) and scores the pass rate.",
    "patch_posture": "Counts pending security updates and flags an end-of-life OS.",
}

# How each category contributes to the headline score. Sums to 1.0.
# Attack coverage is weighted highest because it is the thing the Prove step
# actually measures end-to-end (did a real technique get caught).
CATEGORY_WEIGHTS = {
    "attack_coverage": 0.30,
    "visibility": 0.20,
    "response_readiness": 0.20,
    "config_hardening": 0.15,
    "patch_posture": 0.15,
}

# Realistic "good" target per category, used only for fix-impact estimates.
# We never promise 100; we promise the gap to a sensible target is closable.
CATEGORY_TARGETS = {
    "attack_coverage": 85.0,
    "visibility": 90.0,
    "response_readiness": 80.0,
    "config_hardening": 90.0,
    "patch_posture": 85.0,
}


# ── Inputs ──────────────────────────────────────────────────────────────────

@dataclass
class ProveResult:
    """Outcome of the Prove step: safe emulation + detection check."""
    techniques_total: int = 0
    techniques_detected: int = 0
    missed: list[dict] = field(default_factory=list)  # [{id,name,tactic}]

    @property
    def coverage_pct(self) -> float:
        if self.techniques_total <= 0:
            return 0.0
        return 100.0 * self.techniques_detected / self.techniques_total


@dataclass
class Signals:
    """
    Everything the collector + prove step learned about one host, normalized.

    Any field left at its default simply contributes a conservative score for
    that category, so a partial scan still produces an honest (lower) grade
    rather than crashing.
    """
    # Visibility: which expected log sources are present & healthy.
    expected_log_sources: list[str] = field(default_factory=list)
    present_log_sources: list[str] = field(default_factory=list)

    # Config hardening: list of {id,label,passed,weight,fix} checks.
    hardening_checks: list[dict] = field(default_factory=list)

    # Response readiness: presence of containment capability on the host.
    has_edr: bool = False
    has_isolation_path: bool = False   # e.g. host firewall can quarantine
    has_ir_playbook: bool = False

    # Patch posture.
    pending_security_updates: Optional[int] = None  # None = unknown
    vuln_severities: Optional[dict] = None  # Pro: per-severity CVE counts from the SIEM
    os_end_of_life: bool = False

    # Attack coverage comes straight from the prove step.
    prove: ProveResult = field(default_factory=ProveResult)

    # Optional: a richer attack-coverage number from the real AESP engine,
    # supplied once wired into pila-suite. Overrides prove-derived coverage.
    aesp_effectiveness: Optional[float] = None

    # Whether attack-coverage was actually measured on this host. When False
    # (e.g. the AESP emulation collector has not run here yet), attack coverage
    # is excluded from the weighted score and the remaining categories are
    # renormalized, so an un-run test never reads as an insecure host.
    attack_coverage_collected: bool = True

    host_label: str = "this machine"

    # Asset liveness (Pro network collector sets these).
    last_seen: Optional[str] = None       # epoch-ms string of last report, None = unknown
    profile: str = "intermittent"         # "always-on" | "intermittent"
    state: str = "active"                 # "active" | "dormant" | "missing"


# ── Category scorers ──────────────────────────────────────────────────────────

def _clamp(v: float) -> float:
    return max(0.0, min(100.0, v))


def score_attack_coverage(s: Signals) -> float:
    if s.aesp_effectiveness is not None:
        return _clamp(s.aesp_effectiveness)
    return _clamp(s.prove.coverage_pct)


def score_visibility(s: Signals) -> float:
    expected = s.expected_log_sources or []
    if not expected:
        # Nothing declared as expected -> we can't see much; score low-ish
        # but not zero (the host may still be sending something).
        return 35.0 if s.present_log_sources else 10.0
    present = set(s.present_log_sources)
    got = sum(1 for e in expected if e in present)
    return _clamp(100.0 * got / len(expected))


def score_response_readiness(s: Signals) -> float:
    # Three roughly-equal pillars of being able to respond on this host.
    pillars = [s.has_edr, s.has_isolation_path, s.has_ir_playbook]
    return _clamp(100.0 * sum(1 for p in pillars if p) / len(pillars))


def score_config_hardening(s: Signals) -> float:
    checks = s.hardening_checks or []
    if not checks:
        return 50.0  # unknown -> neutral-low
    total_w = sum(float(c.get("weight", 1)) for c in checks) or 1.0
    passed_w = sum(float(c.get("weight", 1)) for c in checks if c.get("passed"))
    return _clamp(100.0 * passed_w / total_w)


def score_patch_posture(s: Signals) -> float:
    if s.os_end_of_life:
        return 10.0
    # Pro: severity-weighted CVE load from the SIEM (can be hundreds-thousands),
    # scored on a log curve so every real reduction moves the number.
    sev = s.vuln_severities
    if sev is not None:
        load = (10.0 * int(sev.get("Critical", 0))
                + 3.0 * int(sev.get("High", 0))
                + 1.0 * int(sev.get("Medium", 0))
                + 0.2 * int(sev.get("Low", 0)))
        if load <= 0:
            return 100.0
        return _clamp(100.0 - 22.0 * math.log10(1.0 + load))
    # Free: count of pending OS security updates on a single host.
    n = s.pending_security_updates
    if n is None:
        return 55.0  # unknown -> neutral-low
    if n <= 0:
        return 100.0
    return _clamp(max(20.0, 100.0 - 8.0 * n))


_SCORERS = {
    "attack_coverage": score_attack_coverage,
    "visibility": score_visibility,
    "response_readiness": score_response_readiness,
    "config_hardening": score_config_hardening,
    "patch_posture": score_patch_posture,
}


# ── Grade mapping ──────────────────────────────────────────────────────────────

# (min_score, letter). Checked high -> low.
_GRADE_BANDS = [
    (93, "A"), (90, "A−"),
    (87, "B+"), (83, "B"), (80, "B−"),
    (77, "C+"), (73, "C"), (70, "C−"),
    (67, "D+"), (63, "D"), (60, "D−"),
    (0, "F"),
]

# Grade colors reused by the UI (kept here so score + color never disagree).
_GRADE_COLOR = {
    "A": "#34d399", "A−": "#34d399",
    "B+": "#34d399", "B": "#34d399", "B−": "#34d399",
    "C+": "#f59e0b", "C": "#f59e0b", "C−": "#f59e0b",
    "D+": "#f87171", "D": "#f87171", "D−": "#f87171",
    "F": "#f87171",
}


def grade_for(score: float) -> str:
    for threshold, letter in _GRADE_BANDS:
        if score >= threshold:
            return letter
    return "F"


def color_for_grade(letter: str) -> str:
    return _GRADE_COLOR.get(letter, "#8b97a9")


# ── Fixes ──────────────────────────────────────────────────────────────────────

# Default remediation copy per category, used when the collector did not attach
# a specific finding. Specific findings (e.g. a failed hardening check with its
# own `fix`) always take precedence.
_CATEGORY_FIX = {
    "attack_coverage": (
        "Close your biggest detection gap",
        "Emulated attacker techniques went undetected. Add the matching "
        "detection rules, then re-scan to confirm they fire.",
    ),
    "visibility": (
        "Turn on the logging you're missing",
        "Key log sources aren't reaching the scorer, so attacks would be "
        "invisible. Enable the missing source and re-scan.",
    ),
    "response_readiness": (
        "Create one containment path",
        "There's no quick way to isolate this host if it's hit. Define a single "
        "isolate-and-collect step so response readiness isn't zero.",
    ),
    "config_hardening": (
        "Harden the weakest setting",
        "A common attack path is left open by configuration. Tighten it and "
        "re-scan.",
    ),
    "patch_posture": (
        "Apply pending security updates",
        "Outstanding security updates leave known holes. Patch and re-scan.",
    ),
}


def _impact_of_lifting(sub: dict, cat: str) -> float:
    """
    How many overall points we'd gain by lifting `cat` from its current value
    to its realistic target. This is the honest fix-impact estimate.
    """
    current = sub[cat]
    target = CATEGORY_TARGETS[cat]
    if target <= current:
        return 0.0
    return (target - current) * CATEGORY_WEIGHTS[cat]


def build_fixes(signals: Signals, sub: dict, limit: int = 3) -> list[dict]:
    """
    Rank fixes by estimated overall-score impact. A specific failed hardening
    check surfaces as its own fix; otherwise we fall back to the category-level
    remediation. Returns up to `limit` items, each:
        {impact: "+N", title, desc, category}
    """
    candidates: list[tuple[float, dict]] = []

    # 1) Specific failed hardening checks (most actionable).
    for c in signals.hardening_checks or []:
        if not c.get("passed"):
            # weight within hardening -> share of the hardening lift
            gain = _impact_of_lifting(sub, "config_hardening")
            # Title reads as an action (the fix itself); desc gives context.
            # Falls back to the control label only if no fix text is provided.
            action = c.get("fix") or ("Harden: " + c.get("label", "a setting"))
            candidates.append((gain, {
                "title": action,
                "desc": "Flagged by the config-hardening check on this host — closing it removes a common attack path.",
                "category": "config_hardening",
            }))

    # 2) Missed techniques (attack coverage).
    for m in signals.prove.missed:
        gain = _impact_of_lifting(sub, "attack_coverage") / max(1, len(signals.prove.missed))
        candidates.append((gain, {
            "title": f"Detect {m.get('name', m.get('id', 'an attacker technique'))}",
            "desc": (f"Technique {m.get('id', '')} ran and nothing alerted. "
                     "Add the matching rule and re-scan."),
            "category": "attack_coverage",
        }))

    # 3) Category-level fallbacks for every weak category.
    for cat in CATEGORIES:
        gain = _impact_of_lifting(sub, cat)
        if gain <= 0:
            continue
        title, desc = _CATEGORY_FIX[cat]
        # Make the attack-coverage copy match the real detected/total so it
        # never contradicts the score or the findings line.
        if cat == "attack_coverage":
            p = signals.prove
            if p.techniques_total:
                undetected = p.techniques_total - p.techniques_detected
                desc = (f"{undetected} of {p.techniques_total} emulated attacker techniques "
                        f"went undetected (only {p.techniques_detected} caught). Add detection "
                        "rules for the misses, then re-scan to confirm they fire.")
        candidates.append((gain, {"title": title, "desc": desc, "category": cat}))

    # Dedupe by title, keep the highest-impact instance.
    best: dict[str, tuple[float, dict]] = {}
    for gain, item in candidates:
        key = item["title"]
        if key not in best or gain > best[key][0]:
            best[key] = (gain, item)

    ranked = sorted(best.values(), key=lambda t: t[0], reverse=True)
    out = []
    for gain, item in ranked[:limit]:
        pts = max(1, round(gain))
        out.append({"impact": f"+{pts}", **item})
    return out


# ── Verdict copy ───────────────────────────────────────────────────────────────

def _verdict(score: float, sub: dict, host_label: str) -> str:
    weakest = min(CATEGORIES, key=lambda c: sub[c])
    weak_label = CATEGORIES[weakest].split(" / ")[0].lower()
    if score >= 80:
        return f"Solid on {host_label} — a couple of gaps worth closing, starting with {weak_label}."
    if score >= 60:
        return f"Real gaps on {host_label} — {weak_label} is the weak link to fix first."
    return f"{host_label.capitalize()} has serious exposure — {weak_label} needs attention now."


# ── Top-level entry point ──────────────────────────────────────────────────────

def compute(signals: Signals) -> dict:
    """
    Run the whole Score step. Returns a JSON-ready dict the API serves directly:

        {
          "score": 68, "grade": "B-", "grade_color": "#34d399",
          "verdict": "...", "host_label": "this machine",
          "categories": [{key,label,value,color}, ...],
          "fixes": [{impact,title,desc,category}, ...],
          "prove": {total, detected, coverage_pct, missed:[...]}
        }
    """
    sub = {cat: round(_SCORERS[cat](signals), 1) for cat in CATEGORIES}

    # Which categories were actually measured. Attack coverage can be marked
    # uncollected (no emulation run yet); it is then dropped from the weighted
    # score and the remaining weights are renormalized so the grade reflects
    # only what we measured, rather than penalizing an un-run test.
    ac_collected = getattr(signals, "attack_coverage_collected", True)
    scored_cats = [c for c in CATEGORIES if not (c == "attack_coverage" and not ac_collected)]
    weight_sum = sum(CATEGORY_WEIGHTS[c] for c in scored_cats) or 1.0
    overall = sum(sub[c] * CATEGORY_WEIGHTS[c] for c in scored_cats) / weight_sum
    overall_i = int(round(overall))
    letter = grade_for(overall)

    def _findings(cat):
        s = signals
        if cat == "attack_coverage":
            out = [f"{s.prove.techniques_detected} of {s.prove.techniques_total} emulated techniques detected"]
            if s.aesp_effectiveness is not None:
                out.append(f"AESP effectiveness {int(round(s.aesp_effectiveness))}")
            if s.prove.missed:
                out.append("missed: " + ", ".join(m.get("name", m.get("id", "?")) for m in s.prove.missed[:3]))
            return out
        if cat == "visibility":
            exp = s.expected_log_sources or []
            pres = set(s.present_log_sources)
            got = [e for e in exp if e in pres]
            missing = [e for e in exp if e not in pres]
            out = [f"{len(got)} of {len(exp)} log sources present"] if exp else ["no expected sources declared"]
            if got:
                out.append("have: " + ", ".join(got))
            if missing:
                out.append("missing: " + ", ".join(missing))
            return out
        if cat == "response_readiness":
            return [
                "EDR present" if s.has_edr else "no EDR",
                "isolation path" if s.has_isolation_path else "no isolation path",
                "IR playbook" if s.has_ir_playbook else "no IR playbook",
            ]
        if cat == "config_hardening":
            checks = s.hardening_checks or []
            if not checks:
                return ["no hardening checks available"]
            return [("pass: " if c.get("passed") else "FAIL: ") + c.get("label", "check") for c in checks]
        if cat == "patch_posture":
            if s.os_end_of_life:
                return ["OS is end-of-life"]
            sev = s.vuln_severities
            if sev is not None:
                parts = [f"{sev.get(k, 0)} {k}" for k in ("Critical", "High", "Medium", "Low") if sev.get(k, 0)]
                return parts or ["no open vulnerabilities"]
            n = s.pending_security_updates
            if n is None:
                return ["pending updates unknown"]
            return ["no pending security updates"] if n == 0 else [f"{n} pending security update(s)"]
        return []

    categories = []
    for cat in CATEGORIES:
        if cat == "attack_coverage" and not ac_collected:
            categories.append({
                "key": cat,
                "label": CATEGORIES[cat],
                "value": None,
                "collected": False,
                "color": "#8b97a9",
                "method": CATEGORY_METHOD[cat],
                "findings": ["Not yet collected — the attack-emulation (AESP) "
                             "collector has not run on this host. Excluded from "
                             "the score until it does."],
            })
            continue
        v = int(round(sub[cat]))
        categories.append({
            "key": cat,
            "label": CATEGORIES[cat],
            "value": v,
            "collected": True,
            "color": ("#34d399" if v >= 70 else "#f59e0b" if v >= 50 else "#f87171"),
            "method": CATEGORY_METHOD[cat],
            "findings": _findings(cat),
        })

    return {
        "score": overall_i,
        "grade": letter,
        "grade_color": color_for_grade(letter),
        "verdict": _verdict(overall, sub, signals.host_label),
        "host_label": signals.host_label,
        "categories": categories,
        "fixes": [f for f in build_fixes(signals, sub)
                  if not (f.get("category") == "attack_coverage" and not ac_collected)],
        "prove": {
            "total": signals.prove.techniques_total,
            "detected": signals.prove.techniques_detected,
            "coverage_pct": round(signals.prove.coverage_pct, 1),
            "missed": signals.prove.missed,
        },
    }


if __name__ == "__main__":
    # Smoke test with a representative single-host signal set.
    import json
    demo = Signals(
        host_label="this machine",
        expected_log_sources=["Windows event logs", "Microsoft Defender", "Host firewall"],
        present_log_sources=["Windows event logs", "Microsoft Defender"],
        hardening_checks=[
            {"id": "fw_on", "label": "Host firewall enabled", "passed": True, "weight": 2},
            {"id": "smb_in", "label": "Inbound SMB blocked", "passed": False, "weight": 2,
             "fix": "Block inbound TCP 445 for this network profile."},
            {"id": "pslog", "label": "PowerShell script-block logging on", "passed": False, "weight": 1,
             "fix": "Enable script-block logging in Group Policy."},
            {"id": "rdp", "label": "RDP restricted / NLA on", "passed": True, "weight": 1},
        ],
        has_edr=True, has_isolation_path=True, has_ir_playbook=False,
        pending_security_updates=3, os_end_of_life=False,
        prove=ProveResult(
            techniques_total=8, techniques_detected=5,
            missed=[
                {"id": "T1003", "name": "credential dumping", "tactic": "Credential Access"},
                {"id": "T1021.002", "name": "SMB lateral movement", "tactic": "Lateral Movement"},
                {"id": "T1059.001", "name": "PowerShell execution", "tactic": "Execution"},
            ],
        ),
    )
    print(json.dumps(compute(demo), indent=2, ensure_ascii=False))
