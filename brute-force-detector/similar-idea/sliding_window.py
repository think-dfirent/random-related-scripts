"""Worked example: a sliding-window counter for ONE stream of events.

Question it answers: "at which moments had this client received
>= threshold NXDOMAIN responses within the last `window`?"
(Many NXDOMAINs in a short time from one host is a classic DGA-malware signal.)
"""

from collections import deque
from datetime import datetime, timedelta


def burst_moments(
    timestamps: list[datetime],
    threshold: int,
    window: timedelta,
) -> list[datetime]:
    """Return every timestamp at which the window holds >= threshold events.

    Assumes timestamps are sorted ascending and timezone-aware.
    """
    recent: deque[datetime] = deque()  # events inside the window, oldest on the left
    moments: list[datetime] = []

    for ts in timestamps:
        recent.append(ts)
        # Slide: measure age against the NEWEST event, drop what is too old.
        # `while`, not `if`: several old events can expire at once.
        # `>` (not `>=`) keeps an event exactly `window` old -> inclusive edge.
        while ts - recent[0] > window:
            recent.popleft()
        if len(recent) >= threshold:
            moments.append(ts)

    return moments
