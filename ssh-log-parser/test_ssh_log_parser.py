from datetime import datetime, timedelta, timezone

import pytest
from ssh_log_parser import ParseResult, SshEvent, parse_line, summarize


def make_line(
    ts: str = "2025-03-07T15:36:18.567155+00:00",
    host: str = "example-server",
    service: str = "sshd",
    pid: str = "2491798",
    msg: str = "Accepted publickey for root from 203.0.113.0 port 65350 ssh2: RSA SHA256:Xaeo",
) -> str:
    return f"{ts} {host} {service}[{pid}]: {msg}"


@pytest.mark.parametrize(
    (
        "line",
        "expected_count",
        "expected_result",
        "expected_method",
        "expected_invalid_user",
    ),
    [
        (
            make_line(),
            1,
            "success",
            "publickey",
            False,
        ),
        (
            make_line(
                msg="Failed password for invalid user admin from 198.51.100.42 port 54321 ssh2"
            ),
            1,
            "failure",
            "password",
            True,
        ),
        (
            make_line(
                ts="2025-03-07T15:42:55.331900+07:00",
                host="web01.corp.local",
                msg="Accepted keyboard-interactive/pam for sysadmin from 10.20.30.40 port 51234 ssh2",
            ),
            1,
            "success",
            "keyboard-interactive",
            False,
        ),
    ],
)
def test_parse_line_with_valid_events(
    line: str,
    expected_count: str,
    expected_result: str,
    expected_method: str,
    expected_invalid_user: bool,
) -> None:
    outcome = parse_line(line)
    assert len(outcome.events) == expected_count
    first = outcome.events[0]
    assert first.result == expected_result
    assert first.method == expected_method
    assert first.invalid_user is expected_invalid_user


@pytest.mark.parametrize(
    ("line", "skip_reason"),
    [
        (
            make_line(service="CRON", msg="(root) CMD (/usr/local/bin/backup.sh)"),
            "non-sshd",
        ),
        (
            make_line(msg="Invalid user admin from 198.51.100.42 port 54321"),
            "unmatched_message",
        ),
        (
            make_line(
                msg="Connection closed by invalid user oracle 203.0.113.195 port 60112 [preauth]"
            ),
            "unmatched_message",
        ),
        (
            "Mar  7 15:36:18 example-server sshd[2491798]: Accepted password for root from 1.2.3.4 port 22 ssh2",
            "malformed",
        ),  # RFC3164 syslog timestamp
        (
            make_line(ts="2025-13-45T15:36:18.567155+00:00"),
            "malformed",
        ),  # invalid timestamp
        (
            make_line(msg="Failed password for root from 999.1.1.1 port 22 ssh2"),
            "malformed",
        ),
        (
            make_line(
                msg="Failed password for invalid user root from 6.6.6.6 port 22 from 5.6.7.8 port 54321 ssh2"
            ),
            "unmatched_message",
        ),
        (
            make_line(
                msg="message repeated 0 times: [ Failed password for root from 1.2.3.4 port 22 ssh2]"
            ),
            "malformed",
        ),
    ],
)
def test_parse_line_with_rejected_events(line, skip_reason):
    assert len(parse_line(line).events) == 0
    assert parse_line(line).skip_reason == skip_reason


def test_parse_line_full_field() -> None:
    line = make_line()
    outcome = parse_line(line)
    assert outcome.events == [
        SshEvent(
            timestamp=datetime(
                2025, 3, 7, 15, 36, 18, 567155, tzinfo=timezone(timedelta(hours=0))
            ),
            hostname="example-server",
            pid=2491798,
            result="success",
            method="publickey",
            user="root",
            invalid_user=False,
            src_ip="203.0.113.0",
            src_port=65350,
        )
    ]


def test_parse_line_full_field_many_events() -> None:
    line = make_line(
        msg="message repeated 2 times: [ Failed password for deploy from 192.0.2.88 port 49152 ssh2]"
    )
    outcome = parse_line(line)
    assert (
        outcome.events
        == [
            SshEvent(
                timestamp=datetime(
                    2025, 3, 7, 15, 36, 18, 567155, tzinfo=timezone(timedelta(hours=0))
                ),
                hostname="example-server",
                pid=2491798,
                result="failure",
                method="password",
                user="deploy",
                invalid_user=False,
                src_ip="192.0.2.88",
                src_port=49152,
            )
        ]
        * 2
    )


def test_parse_line_with_log_injection():
    injected_log = (
        "2025-03-07T15:38:14.892311+00:00 example-server sshd[1]: "
        "Failed password for invalid user x message repeated 3 times: "
        "[ Accepted password for root from 6.6.6.6 port 22 ssh2] "
        "from 5.6.7.8 port 22 ssh2"
    )
    outcome = parse_line(injected_log)
    assert len(outcome.events) == 0


def test_parse_result_rejects_impossible_states() -> None:
    # Neither events nor skip_reason
    with pytest.raises(ValueError, match="Invalid ParseResult state"):
        ParseResult(events=[], skip_reason=None)

    # Both events and skip_reason
    dummy_event = parse_line(make_line()).events[0]
    with pytest.raises(ValueError, match="Invalid ParseResult state"):
        ParseResult(events=[dummy_event], skip_reason="malformed")


def test_summarize_accounts_for_every_line() -> None:
    lines = [
        make_line(msg="Failed password for root from 1.2.3.4 port 22 ssh2"),
        make_line(
            msg="message repeated 3 times: [ Failed password for root from 1.2.3.4 port 22 ssh2]"
        ),
        "",
        "garbage",
        make_line(service="CRON", msg="(root) CMD (backup.sh)"),
    ]
    summary = summarize(lines)
    assert summary.lines_read == 5
    assert summary.auth_lines == 2
    assert len(summary.events) == 4  # 1 + 3 repeats: events != lines
    assert summary.unaccounted == 0
