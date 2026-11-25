"""Brute-force detector (#2): failed password logins burst, then a success.

Design: DESIGN-brute-force.md. Input is SshEvent objects from ssh_log_parser,
never log text, so the detector does not depend on the log format.
"""

from collections import defaultdict, deque
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta

from ssh_log_parser import SshEvent

# Methods that mean "the client guessed a secret". publickey etc. are excluded:
# an ssh-agent offering several keys produces failures on a normal login.
GUESSABLE_METHODS: frozenset[str] = frozenset({"password", "keyboard-interactive"})


@dataclass(frozen=True, slots=True)
class Alert:
    src_ip: str
    first_failure: datetime  # start of the qualifying window, not of the campaign
    last_failure: datetime
    failure_count: int  # failures inside the qualifying window
    users_tried: frozenset[str]
    hostnames: frozenset[str]
    success_time: datetime
    success_user: str
    success_hostname: str

    @property
    def technique(self) -> str:
        """T1110.001 (guessing) if one user was tried, else T1110.003 (spraying)."""
        if len(self.users_tried) == 1:
            return "T1110.001"
        return "T1110.003"


def detect(
    events: Iterable[SshEvent],
    *,
    threshold: int = 5,
    window: timedelta = timedelta(seconds=60),
    success_window: timedelta = timedelta(seconds=60),
) -> list[Alert]:
    """Return one Alert per burst of >= threshold guessable failures from one
    src_ip within `window`, followed by a guessable success from the same
    src_ip within `success_window` after the last failure. Both windows are
    inclusive. Sorted events before detection
    """
    recent_by_ip: defaultdict[str, deque[SshEvent]] = defaultdict(deque)
    alerts: list[Alert] = []
    events = sorted(events, key=lambda e: (e.timestamp, e.result == "success"))
    for event in events:
        if event.method not in GUESSABLE_METHODS:
            continue
        recent_failure_events = recent_by_ip[event.src_ip]
        if event.result == "failure":
            recent_failure_events.append(event)
            while event.timestamp - recent_failure_events[0].timestamp > window:
                recent_failure_events.popleft()
        elif (
            event.result == "success"
            and len(recent_failure_events) >= threshold
            and event.timestamp - recent_failure_events[-1].timestamp <= success_window
        ):
            alert = Alert(
                src_ip=event.src_ip,
                first_failure=recent_failure_events[0].timestamp,
                last_failure=recent_failure_events[-1].timestamp,
                failure_count=len(recent_failure_events),
                users_tried=frozenset(ev.user for ev in recent_failure_events),
                hostnames=frozenset(ev.hostname for ev in recent_failure_events),
                success_time=event.timestamp,
                success_user=event.user,
                success_hostname=event.hostname,
            )
            alerts.append(alert)
            recent_failure_events.clear()

    return alerts
