"""
BXB Security Score - engine hooks (Free / Community edition)
============================================================

Thin adapters between the Free Security Score app and a licensed BXB engine.
In the Free/Community build these run in standalone sample mode: there is no
live emulation, so results are derived from what the local collector actually
found. A licensed build replaces the sample path with the real engine at
deploy time; nothing else in the app changes.

The Free tier is Host-scope only, so every call here is scoped to the local
machine. Network/Fleet scope is a licensed concern and is not reachable here.
"""

from __future__ import annotations

from typing import Optional

from .scoring import ProveResult, Signals


# Host-safe MITRE ATT&CK technique set for the Free Prove step. Deliberately
# small and non-destructive. (Technique IDs are public ATT&CK references.)
HOST_SAFE_TECHNIQUES = [
    {"id": "T1059.001", "name": "PowerShell execution", "tactic": "Execution"},
    {"id": "T1003", "name": "credential dumping", "tactic": "Credential Access"},
    {"id": "T1021.002", "name": "SMB lateral movement", "tactic": "Lateral Movement"},
    {"id": "T1547.001", "name": "registry run-key persistence", "tactic": "Persistence"},
    {"id": "T1112", "name": "registry modification", "tactic": "Defense Evasion"},
    {"id": "T1016", "name": "network config discovery", "tactic": "Discovery"},
    {"id": "T1053.005", "name": "scheduled task", "tactic": "Execution"},
    {"id": "T1070.001", "name": "event-log clearing", "tactic": "Defense Evasion"},
]


def run_prove(signals: Signals) -> ProveResult:
    """Scan step 4: emulate host-safe techniques and check whether the host's
    own telemetry caught them. The Community build runs the sample path."""
    try:
        return _run_prove_real(signals)
    except Exception:
        return _run_prove_sample(signals)


def _run_prove_real(signals: Signals) -> ProveResult:
    # A licensed build wires its host-safe emulator in here. In the Community
    # build it is intentionally unavailable, so the sample path below is used.
    raise ImportError("live emulator not available in the Community build")


def _run_prove_sample(signals: Signals) -> ProveResult:
    """Representative result for standalone/demo mode. Detection is inferred
    from what the collector actually found, so the result stays honest and
    reactive to the real host rather than canned."""
    present = set(signals.present_log_sources)
    passed = {c["id"] for c in (signals.hardening_checks or []) if c.get("passed")}

    missed: list[dict] = []
    detected = 0
    for t in HOST_SAFE_TECHNIQUES:
        if _sample_would_catch(t["id"], present, passed):
            detected += 1
        else:
            missed.append(t)
    return ProveResult(
        techniques_total=len(HOST_SAFE_TECHNIQUES),
        techniques_detected=detected,
        missed=missed,
    )


def _sample_would_catch(tid: str, present: set, passed: set) -> bool:
    # Deterministic mapping of technique -> the control that would catch it.
    needs_any = {
        "T1059.001": {"pslog"},
        "T1003": {"edr"},
        "T1021.002": {"smb_in", "fw_on"},
        "T1547.001": {"edr"},
        "T1112": {"edr"},
        "T1016": set(),
        "T1053.005": {"pslog", "edr"},
        "T1070.001": {"fw_on"},
    }
    req = needs_any.get(tid, set())
    if not req:
        # discovery-style: caught if any logging is present at all
        return bool(present)
    return bool(req & passed)


def aesp_effectiveness(signals: Signals) -> Optional[float]:
    """Optional richer attack-coverage number from a licensed engine. Returns
    None in the Community build so the scorer falls back to prove-derived
    coverage."""
    return None


def enrich(signals: Signals) -> Signals:
    """Run the engine-backed steps and fold them into the signals.

    Standalone Free has no live emulation + detection. The control-inventory
    estimate is NOT a measured detection result, so it must not feed the
    attack-coverage score: mark it not-collected and the scorer excludes it and
    renormalizes (the UI then shows "not yet collected"). A licensed build uses
    the measured result instead.
    """
    try:
        signals.prove = _run_prove_real(signals)
        signals.attack_coverage_collected = True
    except Exception:
        signals.attack_coverage_collected = False
    eff = aesp_effectiveness(signals)
    if eff is not None:
        signals.aesp_effectiveness = eff
        signals.attack_coverage_collected = True
    return signals
