import pytest
from datetime import UTC, datetime, timedelta

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


# TODO (you): turn the remaining rows of the design note into tests.
# Add `import pytest` at the top when you start. Suggested shape for rows that only check "how many alerts":
#
# @pytest.mark.parametrize(
#     ("events", "expected_count"),
#     [
#         pytest.param([...], 0, id="61 s -> first failure slid out"),
#         ...
#     ],
# )
# def test_alert_count(events: list[SshEvent], expected_count: int) -> None:
#     assert len(detect(events)) == expected_count
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
                make_event(55, "failure"),
                make_event(70, "success"),
            ],
            1,
            id="4 failures and 1 success, then another failure, then success -> 1 alert",
        ),
    ],
)
def test_expected_alert_numbers(events, expected_counts) -> None:
    assert len(detect(events)) == expected_counts
