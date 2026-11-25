from datetime import UTC, datetime, timedelta

import pytest
from brute_force import Alert, detect
from ssh_log_parser import AuthMethod, AuthResult, SshEvent

BASE = datetime(2026, 11, 25, 10, 0, 0, tzinfo=UTC)


def at(seconds: float) -> datetime:
    return BASE + timedelta(seconds=seconds)


def make_event(
    seconds: float,
    result: AuthResult,
    *,
    user: str = "root",
    ip: str = "203.0.113.5",
    method: AuthMethod = "password",
    host: str = "web01",
) -> SshEvent:
    """One SshEvent `seconds` after BASE. Defaults = the common attack case."""
    return SshEvent(
        timestamp=at(seconds),
        hostname=host,
        pid=1000,
        result=result,
        method=method,
        user=user,
        invalid_user=False,
        src_ip=ip,
        src_port=50000,
    )


def failures(*seconds: float, **kwargs) -> list[SshEvent]:
    """failures(0, 10, 20) -> three failure events with the same defaults."""
    return [make_event(s, "failure", **kwargs) for s in seconds]


def successes(*seconds: float, **kwargs) -> list[SshEvent]:
    """failures(0, 10, 20) -> three failure events with the same defaults."""
    return [make_event(s, "success", **kwargs) for s in seconds]


def test_four_failures_then_success_is_below_threshold() -> None:
    events = [*failures(0, 10, 20, 30), make_event(40, "success")]
    assert detect(events) == []


def test_five_failures_then_success_alerts() -> None:
    events = [*failures(0, 10, 20, 30, 40), make_event(50, "success")]

    assert detect(events) == [
        Alert(
            src_ip="203.0.113.5",
            first_failure=at(0),
            last_failure=at(40),
            failure_count=5,
            users_tried=frozenset({"root"}),
            hostnames=frozenset({"web01"}),
            success_time=at(50),
            success_user="root",
            success_hostname="web01",
        )
    ]


@pytest.mark.parametrize(
    ("events", "expected_counts"),
    [
        pytest.param(
            [
                *failures(0, 10, 20, 30, 40),
                *successes(45, 61, 62),
            ],
            1,
            id="5 failures and 3 success -> 1 alert",
        ),
        pytest.param(
            [
                *failures(0, 10, 20, 30),
                make_event(50, "success"),
                make_event(55, "failure"),
                make_event(70, "success"),
            ],
            1,
            id="4 failures and 1 success, then another failure, then success -> 1 alert",
        ),
        pytest.param(
            [
                *failures(0, 10, 20, 30),
                make_event(40, "success"),
                make_event(40, "failure"),
            ],
            1,
            id="tie-breaking: 4 failures and sucess and failure come in parallel",
        ),
        pytest.param(
            [
                *failures(0, 10, 20, 30, 61),
                make_event(62, "success"),
            ],
            0,
            id="the fifth failure exceeds window -> no alert",
        ),
        pytest.param(
            [
                *failures(0, 10, 20, 30, 50),
                make_event(111, "success"),
            ],
            0,
            id="success after the window is purged -> no alert",
        ),
        pytest.param(
            [
                *failures(10, 20, 30, 40, 50, method="publickey"),
                make_event(100, "success", method="password"),
            ],
            0,
            id="5 publickey failure events, 1 success password event -> no alert",
        ),
        pytest.param(
            [
                *failures(40, 30, 55, 0, 10),
                make_event(60, "success"),
            ],
            1,
            id="unsorted timestamp, success in the window time still counts -> alert",
        ),
        pytest.param(
            [
                *failures(40, 30, 55, 0, 10, ip="203.0.113.8"),
                *failures(40, 30, 55, 0, 10),
                make_event(60, "success"),
                make_event(60, "success", ip="203.0.113.8"),
            ],
            2,
            id="interleaved IPs still count -> 2 alerts",
        ),
        pytest.param(
            [
                *failures(40, 30, 55, 0, 10, ip="203.0.113.8"),
                *failures(40),
                make_event(60, "success"),
                make_event(60, "success", ip="203.0.113.8"),
            ],
            1,
            id="interleaved IPs still count, one satisfies the condition -> 1 alert",
        ),
    ],
)
def test_expected_alert_numbers(events, expected_counts) -> None:
    alerts = detect(events)
    assert len(alerts) == expected_counts


@pytest.mark.parametrize(
    ("events", "expected_technique"),
    [
        pytest.param(
            [
                make_event(0, "failure", user="root"),
                make_event(10, "failure", user="admin"),
                make_event(20, "failure", user="sc"),
                make_event(30, "failure", user="client"),
                make_event(40, "failure", user="john_doe"),
                make_event(50, "success", user="root"),
            ],
            "T1110.003",
            id="5 different users failed and 1 user success -> T1110.003",
        ),
        pytest.param(
            [*failures(10, 20, 30, 40, 50), make_event(50, "success")],
            "T1110.001",
            id="5 failures and 1 success on one user -> T1110.001",
        ),
    ],
)
def test_alert_technique(events, expected_technique) -> None:
    alerts = detect(events)
    assert alerts[0].technique == expected_technique
