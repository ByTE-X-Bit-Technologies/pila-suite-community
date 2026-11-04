"""
PILA Suite - Host scoring engine (Community edition)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
import math


# The categories the user sees. Internal key -> display label.
CATEGORIES = {
    "attack_coverage": "Detection coverage",
    "visibility": "Visibility / logging",
    "response_readiness": "Response readiness",
    "config_hardening": "Config hardening",
    "patch_posture": "Patch & vuln posture",
}

CATEGORY_METHOD = {
    "attack_coverage": "Checks whether your detection telemetry would catch common MITRE ATT&CK techniques (Pro emulates them to confirm).",
    "visibility": "Checks that the log sources needed to see an attack are present and reporting.",
    "response_readiness": "Looks for the means to contain an incident here: endpoint detection, an isolation path, and an IR playbook.",
    "config_hardening": "Runs host hardening checks (firewall, remote login, automatic updates) and scores the pass rate.",
    "patch_posture": "Counts pending security updates and flags an end-of-life OS.",
}

CATEGORY_WEIGHTS = {
    "attack_coverage": 0.30,
    "visibility": 0.20,
    "response_readiness": 0.20,
    "config_hardening": 0.15,
    "patch_posture": 0.15,
}

CATEGORY_TARGETS = {
    "attack_coverage": 85.0,
    "visibility": 90.0,
    "response_readiness": 80.0,
    "config_hardening": 90.0,
    "patch_posture": 85.0,
}


@dataclass
class ProveResult:
    # techniques_total = JUDGED techniques (covered + confirmed gaps). Techniques
    # we have no telemetry to judge are held in `unknown` and excluded from the
    # score, so a blind spot never reads as a failure. core_total = the full
    # technique set for this edition (judged + unknown) for honest reporting.
    techniques_total: int = 0
    techniques_detected: int = 0
    covered: list[dict] = field(default_factory=list)
    missed: list[dict] = field(default_factory=list)
    unknown: list[dict] = field(default_factory=list)
    core_total: int = 0

    @property
    def coverage_pct(self) -> float:
        if self.techniques_total <= 0:
            return 0.0
        return 100.0 * self.techniques_detected / self.techniques_total


@dataclass
class Signals:
    expected_log_sources: list[str] = field(default_factory=list)
    present_log_sources: list[str] = field(default_factory=list)
    hardening_checks: list[dict] = field(default_factory=list)
    has_edr: bool = False
    has_isolation_path: bool = False
    has_ir_playbook: bool = False
    pending_security_updates: Optional[int] = None
    vuln_severities: Optional[dict] = None
    os_end_of_life: bool = False
    prove: ProveResult = field(default_factory=ProveResult)
    aesp_effectiveness: Optional[float] = None
    attack_coverage_collected: bool = True
    response_collected: bool = True
    # True only when this host's coverage came from a REAL emulation result
    # (live LMEP proof), not the presence estimate. Drives the honest
    # "proven" vs "estimated" distinction — a Full key alone does not make
    # coverage "proven"; an actual emulation engagement does.
    coverage_proven: bool = False
    host_label: str = "this machine"
    last_seen: Optional[str] = None
    profile: str = "intermittent"
    state: str = "active"


def _clamp(v: float) -> float:
    return max(0.0, min(100.0, v))


def score_attack_coverage(s: Signals) -> float:
    if s.aesp_effectiveness is not None:
        return _clamp(s.aesp_effectiveness)
    return _clamp(s.prove.coverage_pct)


def score_visibility(s: Signals) -> float:
    expected = s.expected_log_sources or []
    if not expected:
        return 35.0 if s.present_log_sources else 10.0
    present = set(s.present_log_sources)
    got = sum(1 for e in expected if e in present)
    return _clamp(100.0 * got / len(expected))


def score_response_readiness(s: Signals) -> float:
    pillars = [s.has_edr, s.has_isolation_path, s.has_ir_playbook]
    return _clamp(100.0 * sum(1 for p in pillars if p) / len(pillars))


def score_config_hardening(s: Signals) -> float:
    checks = s.hardening_checks or []
    if not checks:
        return 50.0
    total_w = sum(float(c.get("weight", 1)) for c in checks) or 1.0
    passed_w = sum(float(c.get("weight", 1)) for c in checks if c.get("passed"))
    return _clamp(100.0 * passed_w / total_w)


def score_patch_posture(s: Signals) -> float:
    if s.os_end_of_life:
        return 10.0
    sev = s.vuln_severities
    if sev is not None:
        load = (10.0 * int(sev.get("Critical", 0))
                + 3.0 * int(sev.get("High", 0))
                + 1.0 * int(sev.get("Medium", 0))
                + 0.2 * int(sev.get("Low", 0)))
        if load <= 0:
            return 100.0
        return _clamp(100.0 - 22.0 * math.log10(1.0 + load))
    n = s.pending_security_updates
    if n is None:
        return 55.0
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

_GRADE_BANDS = [
    (93, "A"), (90, "A-"),
    (87, "B+"), (83, "B"), (80, "B-"),
    (77, "C+"), (73, "C"), (70, "C-"),
    (67, "D+"), (63, "D"), (60, "D-"),
    (0, "F"),
]

_GRADE_COLOR = {
    "A": "#34d399", "A-": "#34d399",
    "B+": "#34d399", "B": "#34d399", "B-": "#34d399",
    "C+": "#f59e0b", "C": "#f59e0b", "C-": "#f59e0b",
    "D+": "#f87171", "D": "#f87171", "D-": "#f87171",
    "F": "#f87171",
}


def grade_for(score: float) -> str:
    for threshold, letter in _GRADE_BANDS:
        if score >= threshold:
            return letter
    return "F"


def color_for_grade(letter: str) -> str:
    return _GRADE_COLOR.get(letter, "#8b97a9")


_CATEGORY_FIX = {
    "attack_coverage": (
        "Close your biggest detection gap",
        "Some techniques have no telemetry that would catch them. Enable the "
        "matching logging/EDR and re-scan.",
    ),
    "visibility": (
        "Turn on the logging you're missing",
        "Key detection sources aren't present, so attacks would be invisible. "
        "Enable the missing source and re-scan.",
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
    current = sub[cat]
    target = CATEGORY_TARGETS[cat]
    if target <= current:
        return 0.0
    return (target - current) * CATEGORY_WEIGHTS[cat]


def build_fixes(signals: Signals, sub: dict, scored_cats, limit: int = 3) -> list[dict]:
    candidates: list[tuple[float, dict]] = []

    for c in signals.hardening_checks or []:
        if not c.get("passed"):
            gain = _impact_of_lifting(sub, "config_hardening")
            action = c.get("fix") or ("Harden: " + c.get("label", "a setting"))
            candidates.append((gain, {
                "title": action,
                "desc": "Flagged by the config-hardening check on this host - closing it removes a common attack path.",
                "category": "config_hardening",
            }))

    for m in signals.prove.missed:
        gain = _impact_of_lifting(sub, "attack_coverage") / max(1, len(signals.prove.missed))
        name = m.get("name", m.get("id", "an attacker technique"))
        tid = m.get("id", "")
        fix = m.get("fix")
        if fix:
            desc = f"No telemetry here would catch {name} ({tid}). To cover it, {fix}, then re-scan."
        else:
            desc = f"Technique {tid} would go undetected. Add the matching rule and re-scan."
        candidates.append((gain, {
            "title": f"Cover {name}",
            "desc": desc,
            "category": "attack_coverage",
        }))

    for cat in scored_cats:
        gain = _impact_of_lifting(sub, cat)
        if gain <= 0:
            continue
        title, desc = _CATEGORY_FIX[cat]
        if cat == "attack_coverage":
            p = signals.prove
            if p.techniques_total:
                undetected = p.techniques_total - p.techniques_detected
                desc = (f"{undetected} of {p.techniques_total} techniques have no detection "
                        f"coverage ({p.techniques_detected} covered). Enable the missing "
                        "telemetry for the gaps, then re-scan.")
        candidates.append((gain, {"title": title, "desc": desc, "category": cat}))

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


def _verdict(score: float, sub: dict, host_label: str, scored_cats) -> str:
    weakest = min(scored_cats, key=lambda c: sub[c])
    weak_label = CATEGORIES[weakest].split(" / ")[0].lower()
    if score >= 80:
        return f"Solid on {host_label} - a couple of gaps worth closing, starting with {weak_label}."
    if score >= 60:
        return f"Real gaps on {host_label} - {weak_label} is the weak link to fix first."
    return f"{host_label.capitalize()} has serious exposure - {weak_label} needs attention now."


def _category_collected(cat: str, s: Signals) -> bool:
    """Whether this category was actually measured on this host. Uncollected
    categories are dropped from the score and omitted from the UI, so the grade
    reflects only what the edition measures (Community measures detection, not hygiene)."""
    if cat == "attack_coverage":
        return getattr(s, "attack_coverage_collected", True)
    if cat == "config_hardening":
        return bool(s.hardening_checks)
    if cat == "patch_posture":
        return (s.pending_security_updates is not None
                or s.vuln_severities is not None
                or bool(s.os_end_of_life))
    if cat == "response_readiness":
        # Without endpoint telemetry (e.g. Wazuh off) we can't confirm EDR,
        # isolation or an IR playbook — so response readiness is "not assessed",
        # not a zero. The discovery layer sets this flag.
        return getattr(s, "response_collected", True)
    return True  # visibility always measured


def compute(signals: Signals) -> dict:
    sub = {cat: round(_SCORERS[cat](signals), 1) for cat in CATEGORIES}

    collected = {cat: _category_collected(cat, signals) for cat in CATEGORIES}
    scored_cats = [c for c in CATEGORIES if collected[c]]
    # The headline grade is a WEIGHTED BLEND of every category we actually
    # measured — detection coverage is the heaviest input (weight 0.30) but no
    # longer the sole driver, so a perfect detection estimate can't mask failing
    # response/config/patch posture. Categories we couldn't measure are excluded
    # and the remaining weights renormalize, so a blind spot never counts as a
    # zero. Detection coverage still stands on its own as a category and in the
    # PROVE panel ("your detection coverage is X%").
    weight_sum = sum(CATEGORY_WEIGHTS[c] for c in scored_cats) or 1.0
    overall = sum(sub[c] * CATEGORY_WEIGHTS[c] for c in scored_cats) / weight_sum
    overall_i = int(round(overall))
    letter = grade_for(overall)

    def _findings(cat):
        s = signals
        if cat == "attack_coverage":
            p = s.prove
            out = [f"{p.techniques_detected} of {p.techniques_total} judged techniques covered"]
            if s.aesp_effectiveness is not None:
                out.append(f"AESP effectiveness {int(round(s.aesp_effectiveness))}")
            if p.missed:
                out.append("gaps: " + ", ".join(m.get("name", m.get("id", "?")) for m in p.missed[:3]))
            if p.unknown:
                out.append(f"{len(p.unknown)} need deeper visibility to judge (not counted)")
            out.append("presence-based estimate - Pro confirms by live emulation")
            return out
        if cat == "visibility":
            exp = s.expected_log_sources or []
            pres = set(s.present_log_sources)
            got = [e for e in exp if e in pres]
            missing = [e for e in exp if e not in pres]
            out = [f"{len(got)} of {len(exp)} detection sources present"] if exp else ["no expected sources declared"]
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
        if not collected[cat]:
            continue  # omit uncollected categories entirely (e.g. hygiene in Community)
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
        "verdict": _verdict(overall, sub, signals.host_label, scored_cats),
        "host_label": signals.host_label,
        "categories": categories,
        "fixes": build_fixes(signals, sub, scored_cats),
        "prove": {
            "total": signals.prove.techniques_total,
            "detected": signals.prove.techniques_detected,
            "coverage_pct": round(signals.prove.coverage_pct, 1),
            "covered": signals.prove.covered,
            "missed": signals.prove.missed,
            "unknown": signals.prove.unknown,
            "unknown_count": len(signals.prove.unknown),
            "core_total": signals.prove.core_total or (
                signals.prove.techniques_total + len(signals.prove.unknown)),
        },
    }
