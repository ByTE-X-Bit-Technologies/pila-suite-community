# PILA Suite - Community Edition

Scan, score, fix, and prove your security posture. The Community edition runs
Host-scope on the machine it's installed on and produces a real, deterministic
letter grade from locally collected signals.

## What it does

Four steps:
1. **Scan** - inventory the host's log sources, hardening controls, EDR/firewall state, and patch posture.
2. **Score** - a weighted 0-100 score across five categories (attack coverage, visibility, response readiness, config hardening, patch posture) with a letter grade.
3. **Fix** - prioritized, specific remediation steps for what dragged the score down.
4. **Prove** - a host-safe check of whether the machine's own telemetry would catch a small set of non-destructive MITRE ATT&CK techniques.

## Honesty

The Community edition measures what it can see locally. The Prove step runs in
**sample mode** - detection is *inferred* from the controls the scan actually
found, never fabricated - and any category it can't measure is shown as
"not yet collected" and excluded from the score rather than filled with a guess.
A category never shows a number it didn't truly measure.

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
