"""
BXB Security Score — Host collector (Free / Community edition)
==============================================================

The "bring your own telemetry" layer for a single host. It reads what the
machine already produces — no SIEM required — and normalizes it into the
`Signals` shape the scorer consumes.

Platform support in this build:
  * Linux  — WORKING: journald (via `journalctl`), ufw/nftables firewall state,
             pending apt/dnf security updates.
  * Windows — STUB: structure + commands marked TODO (wevtutil / Defender /
             Get-NetFirewallProfile). Runs, returns conservative unknowns.
  * macOS  — STUB: structure + commands marked TODO (`log show`, pfctl,
             softwareupdate).

Every reader is defensive: if a command is missing or denied, it records the
source as "not present" rather than raising, so a partial scan still scores.

Nothing here reaches the network. Loopback/local only — that is the whole point
of the Host (Free) tier.
"""

from __future__ import annotations

import platform
import shutil
import subprocess
from typing import Optional

from .scoring import Signals, ProveResult


# ── small helpers ─────────────────────────────────────────────────────────────

def _run(cmd: list[str], timeout: int = 8) -> Optional[str]:
    """Run a read-only command, return stdout or None on any failure."""
    if not cmd or shutil.which(cmd[0]) is None:
        return None
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return out.stdout
    except Exception:
        return None


def current_os() -> str:
    return {"Linux": "linux", "Windows": "windows", "Darwin": "macos"}.get(
        platform.system(), "unknown"
    )


# ── Linux readers (working) ────────────────────────────────────────────────────

def _linux_log_sources() -> tuple[list[str], list[str]]:
    expected = ["System log (journald)", "Auth log", "Firewall log"]
    present: list[str] = []
    j = _run(["journalctl", "--no-pager", "-n", "1"])
    if j is not None:
        present.append("System log (journald)")
    auth = _run(["journalctl", "--no-pager", "-n", "1", "SYSLOG_FACILITY=10"])
    if auth:
        present.append("Auth log")
    # firewall log presence inferred from ufw/nft being active (below)
    return expected, present


def _linux_firewall_active() -> Optional[bool]:
    ufw = _run(["ufw", "status"])
    if ufw is not None:
        return "Status: active" in ufw
    nft = _run(["nft", "list", "ruleset"])
    if nft is not None:
        return bool(nft.strip())
    return None


def _linux_pending_security_updates() -> Optional[int]:
    # Debian/Ubuntu
    apt = _run(["apt-get", "-s", "upgrade"])
    if apt is not None:
        return sum(1 for line in apt.splitlines()
                   if line.startswith("Inst ") and "security" in line.lower())
    # Fedora/RHEL
    dnf = _run(["dnf", "-q", "updateinfo", "list", "security"])
    if dnf is not None:
        return sum(1 for line in dnf.splitlines() if line.strip())
    return None


def _collect_linux() -> Signals:
    expected, present = _linux_log_sources()
    fw = _linux_firewall_active()
    if fw:
        present.append("Firewall log")

    hardening = [
        {"id": "fw_on", "label": "Host firewall enabled", "weight": 2,
         "passed": bool(fw),
         "fix": "Enable the host firewall (ufw enable / nft default-drop)."},
        {"id": "ssh_root", "label": "SSH root login disabled", "weight": 2,
         "passed": _linux_ssh_root_disabled(),
         "fix": "Set PermitRootLogin no in /etc/ssh/sshd_config and reload sshd."},
        {"id": "auto_updates", "label": "Automatic security updates on", "weight": 1,
         "passed": _linux_unattended_upgrades(),
         "fix": "Enable unattended-upgrades (or dnf-automatic) for security updates."},
    ]

    return Signals(
        host_label=platform.node() or "this machine",
        expected_log_sources=expected,
        present_log_sources=present,
        hardening_checks=hardening,
        has_edr=_linux_has_edr(),
        has_isolation_path=bool(fw),      # a live firewall gives an isolate path
        has_ir_playbook=False,            # unknown locally -> not claimed
        pending_security_updates=_linux_pending_security_updates(),
        os_end_of_life=False,
    )


def _linux_ssh_root_disabled() -> bool:
    out = _run(["sshd", "-T"]) or ""
    return "permitrootlogin no" in out.lower()


def _linux_unattended_upgrades() -> bool:
    return shutil.which("unattended-upgrade") is not None or \
        shutil.which("dnf-automatic") is not None


def _linux_has_edr() -> bool:
    for proc in ("wazuh-agentd", "falcon-sensor", "osqueryd", "auditd"):
        if _run(["pgrep", "-x", proc]):
            return True
    return False


# ── Windows reader (stub) ──────────────────────────────────────────────────────

def _collect_windows() -> Signals:
    # TODO(when-home): implement with these read-only commands, parsed defensively:
    #   * Windows event logs present:  wevtutil el   /  Get-WinEvent -ListLog *
    #   * Defender status:             Get-MpComputerStatus  (AMRunningMode, RealTimeProtectionEnabled)
    #   * Firewall profiles:           Get-NetFirewallProfile  (Enabled per profile)
    #   * Inbound SMB rule:            Get-NetFirewallRule for TCP 445
    #   * Script-block logging:        registry HKLM\...\PowerShell\ScriptBlockLogging
    #   * Pending updates:             Get-WindowsUpdate / COM Microsoft.Update.Session
    #   * EOL:                         Get-ComputerInfo OsName/Version vs EOL table
    # Until implemented, return conservative unknowns so the grade is honest-low.
    return Signals(
        host_label=platform.node() or "this machine",
        expected_log_sources=["Windows event logs", "Microsoft Defender", "Host firewall"],
        present_log_sources=[],
        hardening_checks=[
            {"id": "fw_on", "label": "Host firewall enabled", "weight": 2, "passed": False,
             "fix": "Enable Windows Defender Firewall on all profiles."},
            {"id": "smb_in", "label": "Inbound SMB blocked", "weight": 2, "passed": False,
             "fix": "Block inbound TCP 445 for the active network profile."},
            {"id": "pslog", "label": "PowerShell script-block logging on", "weight": 1, "passed": False,
             "fix": "Enable script-block logging via Group Policy."},
        ],
        has_edr=False, has_isolation_path=False, has_ir_playbook=False,
        pending_security_updates=None, os_end_of_life=False,
    )


# ── macOS reader (stub) ──────────────────────────────────────────────────────

def _collect_macos() -> Signals:
    # TODO(when-home): `log show --last 1m`, `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate`,
    #   `softwareupdate -l`, SIP status `csrutil status`, FileVault `fdesetup status`.
    return Signals(
        host_label=platform.node() or "this machine",
        expected_log_sources=["Unified log", "Application firewall", "Gatekeeper"],
        present_log_sources=[],
        hardening_checks=[
            {"id": "fw_on", "label": "Application firewall on", "weight": 2, "passed": False,
             "fix": "Enable the macOS application firewall."},
            {"id": "filevault", "label": "FileVault enabled", "weight": 1, "passed": False,
             "fix": "Turn on FileVault disk encryption."},
        ],
        has_edr=False, has_isolation_path=False, has_ir_playbook=False,
        pending_security_updates=None, os_end_of_life=False,
    )


# ── public API ────────────────────────────────────────────────────────────────

def collect() -> Signals:
    """Gather host signals for the current OS. Never raises."""
    osname = current_os()
    try:
        if osname == "linux":
            return _collect_linux()
        if osname == "windows":
            return _collect_windows()
        if osname == "macos":
            return _collect_macos()
    except Exception:
        pass
    # Unknown OS or failure -> empty signals (scores low, honest).
    return Signals(host_label=platform.node() or "this machine")


def attach_prove(signals: Signals, prove: ProveResult) -> Signals:
    """Fold a Prove result into the signals before scoring."""
    signals.prove = prove
    return signals


if __name__ == "__main__":
    import json
    from .scoring import compute
    sig = collect()
    print(f"[collector] OS={current_os()} host={sig.host_label}")
    print(json.dumps(compute(sig), indent=2, ensure_ascii=False))
