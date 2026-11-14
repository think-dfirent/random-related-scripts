import ipaddress
import json
import re
import sys
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, cast, get_args

DATE_TIME = (
    r"(?P<date_time>\d{4}-\d{2}-\d{2}T(?:\d{2}:){2}\d{2}\.\d{6}[\+\-]\d{2}:\d{2})"
)
HOST_NAME = r"(?P<host_name>\S+)"
SERVICE = r"(?P<service_name>[A-Za-z0-9_.-]+)\[(?P<process_id>\d+)\]"
MESSAGE = r"(?P<message>.*)"

ENVELOPE = re.compile(rf"^{DATE_TIME}\s{HOST_NAME}\s{SERVICE}:\s{MESSAGE}$")
REPEATED_MESSAGE = re.compile(
    r"^message repeated (?P<repeated_count>\d+) times: \[\s*(?P<inner_msg>.*?)\]$",
)
AuthResult = Literal["success", "failure"]
AuthMethod = Literal[
    "password",
    "publickey",
    "keyboard-interactive",
    "hostbased",
    "gssapi-with-mic",
    "none",
    "other",
]

_RESULT_MAP: dict[str, AuthResult] = {
    "Accepted": "success",
    "Failed": "failure",
}
VALID_AUTH_METHODS: tuple[str, ...] = get_args(AuthMethod)
SkipReason = Literal["malformed", "non-sshd", "unmatched_message"]


@dataclass(frozen=True, slots=True)
class SshEvent:
    """Known limitation: on only-key servers, username probes produce only
    "Invalid user" + Connection closed ....[preauth] with no Failed line,
    so they generate no SshEvent."""

    timestamp: datetime
    hostname: str
    pid: int
    result: AuthResult
    method: AuthMethod
    user: str
    invalid_user: bool
    src_ip: str
    src_port: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "host.name": self.hostname,
            "pid": self.pid,
            "result": self.result,
            "method": self.method,
            "user": self.user,
            "invalid.user": self.invalid_user,
            "src.ip": self.src_ip,
            "src.port": self.src_port,
        }


@dataclass(frozen=True, slots=True)
class ParseResult:
    events: list[SshEvent]
    skip_reason: SkipReason | None = None

    def __post_init__(self) -> None:
        has_events = bool(self.events)
        has_reason = self.skip_reason is not None
        if has_events == has_reason:
            raise ValueError(
                f"Invalid ParseResult state: must provide either non-empty events "
                f"or a skip_reason, got events={len(self.events)}, "
                f"skip_reason={self.skip_reason!r}"
            )


def parse_envelope(line: str) -> dict[str, Any] | None:
    """Split syslog line into timestamp/host/service/pid/message."""
    match = ENVELOPE.search(line.strip())
    if not match:
        return None
    return match.groupdict()


AUTH_MESSAGE = re.compile(
    r"""
    ^(?P<result>Accepted|Failed)\s
    (?P<method>\S+)\s
    for\s(?P<invalid_user>invalid\suser\s)?(?P<user>[A-Za-z0-9_.-]+)\s
    from\s(?P<src_ip>\S+)\s
    port\s(?P<src_port>\d+)\s
    ssh2(?::\s.*)?$
""",
    re.VERBOSE,
)


def parse_message(message: str) -> tuple[dict[str, str | None], int] | None:
    repeated_message = REPEATED_MESSAGE.search(message)
    repeated_count = 1
    if repeated_message:
        message = repeated_message.group("inner_msg")
        repeated_count = int(repeated_message.group("repeated_count"))

    match = AUTH_MESSAGE.search(message)
    if not match:
        return None
    return match.groupdict(), repeated_count


def parse_auth_method(raw_method: str | None) -> AuthMethod:
    """Normalize and validate the sshd method"""
    if not raw_method:
        return "other"
    method = raw_method.strip().lower()
    if method.startswith("keyboard-interactive"):
        return "keyboard-interactive"
    if method in VALID_AUTH_METHODS:
        return cast(AuthMethod, method)
    return "other"


def parse_line(line: str) -> ParseResult:
    envelope = parse_envelope(line)
    if envelope is None:
        return ParseResult(events=[], skip_reason="malformed")
    if envelope["service_name"] != "sshd":
        return ParseResult(events=[], skip_reason="non-sshd")
    parsed = parse_message(envelope["message"])
    if not parsed:
        return ParseResult(events=[], skip_reason="unmatched_message")
    parsed_message, repeat_count = parsed
    if repeat_count < 1:
        return ParseResult(events=[], skip_reason="malformed")
    try:
        timestamp = datetime.fromisoformat(envelope["date_time"])
        ipaddress.ip_address(parsed_message["src_ip"])
    except ValueError:
        return ParseResult(events=[], skip_reason="malformed")
    event_result = _RESULT_MAP[parsed_message["result"]]
    event_method = parse_auth_method(parsed_message["method"])
    event = SshEvent(
        timestamp=timestamp,
        hostname=envelope["host_name"],
        pid=int(envelope["process_id"]),
        result=event_result,
        method=event_method,
        user=parsed_message["user"],
        invalid_user=parsed_message["invalid_user"] is not None,
        src_ip=parsed_message["src_ip"],
        src_port=int(parsed_message["src_port"]),
    )
    return ParseResult(events=[event] * repeat_count, skip_reason=None)


@dataclass
class Summary:
    """Line-level accounting for one input. Every line lands in exactly one bucket."""

    lines_read: int = 0
    blank_lines: int = 0
    auth_lines: int = 0
    events: list[SshEvent] = field(default_factory=list)
    ignored: list[tuple[int, SkipReason, str]] = field(default_factory=list)
    malformed: list[tuple[int, str]] = field(default_factory=list)

    @property
    def unaccounted(self) -> int:
        accounted = (
            self.blank_lines + self.auth_lines + len(self.ignored) + len(self.malformed)
        )
        return self.lines_read - accounted

    def to_json(self, indent: int = 4) -> str:
        return json.dumps([ev.to_dict() for ev in self.events], indent=indent)


def summarize(lines: Iterable[str]) -> Summary:
    summary = Summary()
    for line_num, raw_line in enumerate(lines, start=1):
        summary.lines_read += 1
        line = raw_line.strip()
        if not line:
            summary.blank_lines += 1
            continue
        outcome = parse_line(line)
        if outcome.events:
            summary.auth_lines += 1
            summary.events.extend(outcome.events)
        elif outcome.skip_reason == "malformed":
            summary.malformed.append((line_num, line))
        elif outcome.skip_reason is not None:
            summary.ignored.append((line_num, outcome.skip_reason, line))
    return summary


def print_summary(summary: Summary) -> None:
    results = Counter(event.result for event in summary.events)
    reasons = Counter(reason for _, reason, _ in summary.ignored)
    reason_text = ", ".join(f"{r} {n}" for r, n in sorted(reasons.items()))

    # Result -> stdout
    print(f"Lines read: {summary.lines_read}")
    print(
        f"Auth lines: {summary.auth_lines} -> events: {len(summary.events)} "
        f"(success {results['success']}, failure {results['failure']})"
    )
    print(f"Ignored: {len(summary.ignored)} ({reason_text})")
    print(f"Malformed: {len(summary.malformed)}")
    print(f"Blank: {summary.blank_lines}")

    # Diagnostics -> stderr, one self-contained line each
    for line_num, reason, content in summary.ignored:
        print(f"line {line_num}: ignored ({reason}): {content}", file=sys.stderr)
    for line_num, content in summary.malformed:
        print(f"line {line_num}: malformed: {content}", file=sys.stderr)
    if summary.unaccounted:
        print(f"BUG: {summary.unaccounted} line(s) not accounted for", file=sys.stderr)


def main() -> int:
    sample = Path(__file__).with_name("ssh_log_sample.txt")
    output_path = Path(__file__).with_name("parsed_ssh_logs.json")
    with open(sample, encoding="utf-8") as file:
        summary = summarize(file)
        with open(output_path, "w", encoding="utf-8") as out:
            out.write(summary.to_json())
    print_summary(summary)
    return 1 if summary.unaccounted else 0


if __name__ == "__main__":
    sys.exit(main())
