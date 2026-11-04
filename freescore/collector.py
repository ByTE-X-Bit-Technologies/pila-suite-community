"""
PILA Suite - Host detection-coverage collector (Community edition)
=========================================================================

This is the "Scan" step. It inventories the host's DETECTION telemetry
(read-only, local, no SIEM, nothing leaves the machine) and maps it to a set of
common MITRE ATT&CK techniques to produce a detection-COVERAGE result: for each
technique, do you have at least one telemetry source that would catch it?

It does NOT check host hygiene (firewall / disk encryption / patch level) -
that is the BXB Posture Scanner's job, a separate product. PILA answers
"would I SEE the attack," not "are my settings safe."

No attack is executed. Live emulation (LMEP), which proves a subset of these
techniques, is a PILA Suite Full feature; Community assesses detectability
from the telemetry present.

Platform support:
  * Windows - WORKING (PowerShell, read-only)
  * Linux   - WORKING (auditd / journald / sysmon-for-linux / EDR process)
  * macOS   - minimal (reports unknown -> conservative/blind)
"""

from __future__ import annotations

import platform
import shutil
import subprocess
from typing import Optional

from .scoring import Signals, ProveResult


# ── shell helpers ───────────────────────────────────────────────────────────

def _run(cmd: list[str], timeout: int = 8) -> Optional[str]:
    if not cmd or shutil.which(cmd[0]) is None:
        return None
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout, check=False)
        return out.stdout
    except Exception:
        return None


def _ps(script: str, timeout: int = 25) -> Optional[str]:
    for shell in ("powershell", "pwsh"):
        if shutil.which(shell) is None:
            continue
        try:
            out = subprocess.run(
                [shell, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, timeout=timeout, check=False)
            return (out.stdout or "").strip()
        except Exception:
            continue
    return None


def current_os() -> str:
    return {"Linux": "linux", "Windows": "windows", "Darwin": "macos"}.get(
        platform.system(), "unknown")


# ── detection-coverage model (shared across platforms) ──────────────────────
# Each technique is "covered" if ANY of its detector telemetry flags is present.
# Detector keys are generic so Windows and Linux map their own sources onto them.

_TECHNIQUES = [
    ("T1059.001", "PowerShell abuse",           ["scriptblock", "modulelog", "sysmon", "edr"]),
    ("T1059.003", "Command-shell execution",    ["proc_audit", "cmdline", "sysmon", "edr"]),
    ("T1047",     "WMI / remote execution",     ["sysmon", "edr"]),
    ("T1003.001", "LSASS credential dumping",   ["edr", "sysmon"]),
    ("T1055",     "Process injection",          ["edr", "sysmon"]),
    ("T1547.001", "Run-key persistence",        ["sysmon", "edr"]),
    ("T1053.005", "Scheduled-task persistence", ["proc_audit", "sysmon", "edr"]),
    ("T1021.002", "Lateral movement (SMB/remote login)", ["logon_audit", "edr"]),
    ("T1136",     "New account creation",       ["acct_audit"]),
    ("T1685.005", "Clearing the audit log",     ["seclog", "edr"]),
    ("T1548",     "Privilege escalation",       ["proc_audit", "cmdline", "sysmon", "edr"]),
    ("T1218",     "Trusted-binary proxy exec",  ["proc_audit", "cmdline", "sysmon", "edr"]),
]

_DETECTOR_FIX = {
    "scriptblock": "enable PowerShell script-block logging",
    "modulelog": "enable PowerShell module logging",
    "cmdline": "capture the command line in process-creation events",
    "proc_audit": "enable process-creation / execution auditing",
    "sysmon": "deploy Sysmon with a detection configuration",
    "edr": "turn on endpoint detection (Defender real-time, or an EDR)",
    "logon_audit": "enable logon auditing",
    "acct_audit": "enable account-management auditing",
    "seclog": "keep the Security / audit log enabled",
}

# Sources shown in the Visibility panel (a readable subset of the detectors).
_VIS_SOURCES = [
    ("edr", "Endpoint detection (EDR / Defender)"),
    ("sysmon", "Sysmon"),
    ("scriptblock", "PowerShell script-block logging"),
    ("proc_audit", "Process / execution auditing"),
    ("logon_audit", "Logon auditing"),
    ("acct_audit", "Account-management auditing"),
]


# Readable source label for "via <source>" on a covered technique.
_DETECTOR_LABEL = {
    "scriptblock": "PowerShell script-block logging",
    "modulelog": "PowerShell module logging",
    "cmdline": "command-line auditing",
    "proc_audit": "process-creation auditing",
    "sysmon": "Sysmon",
    "edr": "Endpoint detection (EDR / Defender)",
    "logon_audit": "logon auditing",
    "acct_audit": "account-management auditing",
    "seclog": "Security / audit log",
}


def _coverage(tele: dict) -> ProveResult:
    detected = 0
    covered: list[dict] = []
    missed: list[dict] = []
    for tid, name, dets in _TECHNIQUES:
        hit = next((d for d in dets if tele.get(d) is True), None)
        if hit is not None:
            detected += 1
            covered.append({"id": tid, "name": name,
                            "via": _DETECTOR_LABEL.get(hit, hit)})
        else:
            fixkey = next((d for d in dets if tele.get(d) is not True), dets[0])
            missed.append({"id": tid, "name": name, "tactic": "",
                           "fix": _DETECTOR_FIX.get(fixkey, "add detection telemetry")})
    return ProveResult(techniques_total=len(_TECHNIQUES),
                       techniques_detected=detected,
                       covered=covered, missed=missed)


def _signals_from_tele(host: str, tele: dict) -> Signals:
    expected = [lab for _, lab in _VIS_SOURCES]
    present = [lab for key, lab in _VIS_SOURCES if tele.get(key) is True]
    return Signals(
        host_label=host,
        expected_log_sources=expected,
        present_log_sources=present,
        hardening_checks=[],              # hygiene is the Scanner's job -> dropped
        has_edr=bool(tele.get("edr")),
        has_isolation_path=False,         # containment/response not assessed in Community -> dropped
        has_ir_playbook=False,
        pending_security_updates=None,    # patch posture is the Scanner's job -> dropped
        os_end_of_life=False,
        prove=_coverage(tele),
        attack_coverage_collected=True,   # we DID assess detection coverage
        response_collected=False,         # response readiness not assessed in Community -> dropped
    )


# ── Windows telemetry (read-only PowerShell) ────────────────────────────────

def _reg_dword(path: str, name: str) -> Optional[int]:
    out = _ps("(Get-ItemProperty '%s' -Name %s -ErrorAction SilentlyContinue).%s"
              % (path, name, name))
    if not out:
        return None
    try:
        return int(out.strip())
    except Exception:
        return None


def _auditpol_success(subcat: str) -> Optional[bool]:
    out = _ps('auditpol /get /subcategory:"%s"' % subcat)
    if not out:
        return None
    low = out.lower()
    if "no auditing" in low:
        return False
    if "success" in low:
        return True
    return None


def _collect_windows() -> Signals:
    host = platform.node() or "this machine"
    tele = {
        "scriptblock": _reg_dword(
            r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
            "EnableScriptBlockLogging") == 1,
        "modulelog": _reg_dword(
            r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging",
            "EnableModuleLogging") == 1,
        "cmdline": _reg_dword(
            r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
            "ProcessCreationIncludeCmdLine_Enabled") == 1,
        "sysmon": (lambda r: r == "True")(_ps(
            "if (Get-Service -Name Sysmon,Sysmon64 -ErrorAction SilentlyContinue) {'True'} else {'False'}")),
        "edr": (lambda r: isinstance(r, str) and r.strip().lower() == "true")(_ps(
            "$s=Get-MpComputerStatus -ErrorAction Stop; '{0}' -f $s.RealTimeProtectionEnabled")),
        "proc_audit": _auditpol_success("Process Creation"),
        "logon_audit": _auditpol_success("Logon"),
        "acct_audit": _auditpol_success("User Account Management"),
        "seclog": True,  # Security log always present; 1102 is non-configurable
    }
    return _signals_from_tele(host, tele)


# ── Linux telemetry (auditd / journald / sysmon-for-linux / EDR) ────────────

def _linux_auditctl_rules() -> str:
    return (_run(["auditctl", "-l"]) or "")


def _collect_linux() -> Signals:
    host = platform.node() or "this machine"
    rules = _linux_auditctl_rules().lower()
    auditd = (_run(["pgrep", "-x", "auditd"]) is not None)
    edr = any(_run(["pgrep", "-x", p]) for p in
              ("wazuh-agentd", "falcon-sensor", "osqueryd"))
    sysmon = (_run(["pgrep", "-x", "sysmon"]) is not None
              or _run(["pgrep", "-x", "sysmonforlinux"]) is not None)
    journald = (_run(["journalctl", "--no-pager", "-n", "1"]) is not None)
    tele = {
        "scriptblock": False,  # Windows-specific
        "modulelog": False,
        "cmdline": ("execve" in rules),
        "proc_audit": ("execve" in rules) or (auditd and not rules),
        "sysmon": sysmon,
        "edr": bool(edr),
        "logon_audit": journald or ("tty_audit" in rules) or auditd,
        "acct_audit": ("/etc/passwd" in rules) or ("/etc/shadow" in rules)
                      or ("identity" in rules) or auditd,
        "seclog": journald or auditd,
    }
    return _signals_from_tele(host, tele)


def _collect_macos() -> Signals:
    host = platform.node() or "this machine"
    tele = {k: False for k in (
        "scriptblock", "modulelog", "cmdline", "proc_audit",
        "logon_audit", "acct_audit")}
    tele["sysmon"] = False
    tele["edr"] = False
    tele["seclog"] = True
    return _signals_from_tele(host, tele)


# ── public API ──────────────────────────────────────────────────────────────

def collect() -> Signals:
    osname = current_os()
    try:
        if osname == "windows":
            return _collect_windows()
        if osname == "linux":
            return _collect_linux()
        if osname == "macos":
            return _collect_macos()
    except Exception:
        pass
    return _signals_from_tele(platform.node() or "this machine",
                              {k: None for k in _DETECTOR_FIX})


def attach_prove(signals: Signals, prove: ProveResult) -> Signals:
    signals.prove = prove
    return signals


if __name__ == "__main__":
    import json
    from .scoring import compute
    sig = collect()
    print("[collector] OS=%s host=%s" % (current_os(), sig.host_label))
    print(json.dumps(compute(sig), indent=2, ensure_ascii=False))
