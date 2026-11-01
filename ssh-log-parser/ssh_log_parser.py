import json
import re
import sys
from typing import Any, Literal, get_args, cast
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


DATE_TIME = r"(?P<date_time>\d{4}-\d{2}-\d{2}T(?:\d{2}:){2}\d{2}\.\d{6}\+\d{2}:\d{2})"
HOST_NAME = r"(?P<host_name>[a-zA-Z0-9-]+)"
SERVICE = r"(?P<service_name>[a-z-]+)\[(?P<process_id>\d+)\]"
MESSAGE = r"(?P<message>.*)"

ENVELOPE = re.compile(rf"^{DATE_TIME}\s{HOST_NAME}\s{SERVICE}:\s{MESSAGE}$")

AuthResult = Literal["success", "failure"]
AuthMethod = Literal["password", "publickey", "keyboard-interactive", "hostbased", "gssapi-with-mic", "none","other"]
@dataclass(frozen=True, slots=True)
class SshEvent:
    """Known limitation: on only-key servers, username probes product only
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
    

def parse_envelope(line: str) -> dict[str, Any] | None:
    """Split syslog line into timestamp/host/service/pid/message."""
    match = ENVELOPE.search(line.strip())
    if not match: 
        return None
    return match.groupdict()

AUTH_MESSAGE = re.compile(r"""
    ^(?P<result>Accepted|Failed)\s
    (?P<method>\S+)\s
    for\s(?P<invalid_user>invalid\suser\s)?(?P<user>\S*)\s
    from\s(?P<src_ip>\S+)\s
    port\s(?P<src_port>\d+)
""", re.VERBOSE)

def parse_ssh_message(message: str) -> dict[str, str | None] | None:
    match = AUTH_MESSAGE.search(message)
    if not match:
        return None
    return match.groupdict()

_RESULT_MAP: dict[str, AuthResult] = {
    "Accepted": "success",
    "Failed": "failure",
}
VALID_AUTH_METHODS: tuple[str, ...] = get_args(AuthMethod)
def parse_auth_method(raw_method: str | None) -> AuthMethod:
    """Normalize and validate the extracted sshd auth method."""
    if not raw_method:
        return "other"

    cleaned = raw_method.strip().lower()

    # sshd frequently logs 'keyboard-interactive/pam'
    if cleaned.startswith("keyboard-interactive"):
        return "keyboard-interactive"

    if cleaned in VALID_AUTH_METHODS:
        return cast(AuthMethod, cleaned)

    return "other"

def parse_line(line: str) -> SshEvent | None:    
    envelope = parse_envelope(line)
    if envelope is None or envelope["service_name"]!="sshd":
        return None
    parsed_message = parse_ssh_message(envelope["message"])
    if not parsed_message:
        return None
    event_result = _RESULT_MAP[parsed_message["result"]]
    event_method = parse_auth_method(parsed_message["method"])
    return SshEvent(
        timestamp=datetime.fromisoformat(envelope['date_time']),
        hostname=envelope["host_name"],
        pid= int(envelope["process_id"]),
        result = event_result,
        method = event_method,
        user= parsed_message["user"],
        invalid_user = parsed_message["invalid_user"] is not None,
        src_ip = parsed_message["src_ip"],
        src_port = int(parsed_message["src_port"]),
    )
def main():
    sample = Path(__file__).with_name("ssh_log_sample.txt").resolve()
    output_path = Path(__file__).with_name("parsed_ssh_log.json").resolve()
    parsed_logs = []   
    with open (sample, "r", encoding="utf-8") as file:
        for line in file:
            parsed_dict = parse_envelope(line)
            if not parsed_dict:
                print(f"Skipped unmatched line: {line}")
                continue
            else:
                parsed_logs.append(parsed_dict)
    with open(output_path, "w", encoding="utf-8") as parsed_file:
        json.dump(parsed_logs, parsed_file, indent=4)    

if __name__ == "__main__":
    main()

        
        