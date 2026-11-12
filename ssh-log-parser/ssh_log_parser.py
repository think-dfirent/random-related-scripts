import ipaddress
import json
import re
from collections import Counter
from dataclasses import dataclass
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
    for\s(?P<invalid_user>invalid\suser\s)?(?P<user>\S*)\s
    from\s(?P<src_ip>\S+)\s
    port\s(?P<src_port>\d+)
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
    event_list = []
    envelope = parse_envelope(line)
    if envelope is None:
        return ParseResult(events=[], skip_reason="malformed")
    if envelope["service_name"] != "sshd":
        return ParseResult(events=[], skip_reason="non-sshd")
    parsed = parse_message(envelope["message"])
    if not parsed:
        return ParseResult(events=[], skip_reason="unmatched_message")
    parsed_message, repeat_count = parsed
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


def main():
    sample = Path(__file__).with_name("ssh_log_sample.txt").resolve()
    output_path = Path(__file__).with_name("parsed_ssh_log.json").resolve()
    parsed_logs: list[dict[str, Any]] = []
    ignored_lines: dict[int, tuple[SkipReason, str]] = {}
    malformed_lines: dict[int, str] = {}
    with open(sample, "r", encoding="utf-8") as file:
        for line_num, raw_line in enumerate(file, start=1):
            line = raw_line.strip()
            if not line:
                malformed_lines[line_num] = "<empty line>"
                continue
            outcome = parse_line(line)
            if outcome.events:
                parsed_logs.extend(ev.to_dict() for ev in outcome.events)
            elif outcome.skip_reason == "malformed":
                malformed_lines[line_num] = line
            elif outcome.skip_reason is not None:
                ignored_lines[line_num] = (outcome.skip_reason, line)

    with open(output_path, "w", encoding="utf-8") as parsed_file:
        json.dump(parsed_logs, parsed_file, indent=4)
    skipped_lines = len(ignored_lines) + len(malformed_lines)
    total = len(parsed_logs) + skipped_lines
    counts = Counter(log["result"] for log in parsed_logs)
    success_count = counts["success"]
    failure_count = counts["failure"]
    print(f"Total: {total}")
    print(
        f"Auth events: {len(parsed_logs)} (success {success_count}, failure {failure_count})"
    )
    print(f"Skipped lines: {skipped_lines}")
    print(f"    Ignored lines: {len(ignored_lines)}")
    print(f"    Malformed lines: {len(malformed_lines)}")
    print("Ingored: ")
    for line_num, (reason, content) in ignored_lines.items():
        print(f"    [Ignored - {reason}] Line {line_num}: {content}")
    print("Malformed: ")
    for line_num, content in malformed_lines.items():
        print(f"    [Malformed] Line {line_num}: {content}")


if __name__ == "__main__":
    main()
