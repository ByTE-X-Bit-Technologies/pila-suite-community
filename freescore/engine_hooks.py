"""
PILA Suite - engine hooks (Community edition).

In the detection-coverage model the collector already produces the coverage
result (the "Test"), so enrich() is a pass-through. A licensed build swaps this
for live emulation that executes the techniques and confirms detection.
"""
from __future__ import annotations
from .scoring import Signals


def enrich(signals: Signals) -> Signals:
    # Collector owns the coverage assessment; nothing to add in the Community build.
    return signals
