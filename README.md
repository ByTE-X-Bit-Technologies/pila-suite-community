# PILA Suite - Community Edition

A free, local detection-coverage check for the computer you're on. It works out
which of 12 common MITRE ATT&CK techniques (across 7 tactics) this machine's own
telemetry would detect, and gives you a deterministic 0-100 score, a letter
grade, and the fixes that matter most.

## What it does

1. **Scan** - reads this machine's detection telemetry, read-only: endpoint
   detection (EDR / Microsoft Defender), Sysmon, PowerShell logging, and
   process, logon and account-management auditing. Nothing leaves the machine.
2. **Score** - a 0-100 score and letter grade from two categories:
   **Detection coverage** (how many of the 12 techniques a present telemetry
   source would catch; 60% of the score) and **Visibility / logging** (how many
   of the expected detection sources are present; 40%).
3. **Fix** - the highest-impact changes, ranked by how much each would raise
   the score.
4. **Coverage** - which of the 12 techniques your telemetry would catch, and
   which it would miss.

## Honesty

Community estimates detectability from the telemetry that is present - no
attack is executed. It does not check host hygiene (firewall, disk encryption,
patches - that is the BXB Posture Scanner) or incident-response readiness, so
those are not part of the score. Anything it cannot measure is left out rather
than guessed.

## Install

```
pip install -r requirements.txt
uvicorn freescore.server:app --host 127.0.0.1 --port 8090
```
Open http://127.0.0.1:8090.

## Scope

Community is **Host scope** - the local machine only. Network- and Fleet-scope
scanning, continuous monitoring, trend history, and live attack-emulation are
part of PILA Suite's paid editions (Essentials, Full, Enterprise).

## License

See `LICENSE`. (C) ByTE X Bit Technologies LLC.
