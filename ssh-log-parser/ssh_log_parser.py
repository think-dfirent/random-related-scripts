import json
import re
import sys
from typing import Any
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


date_time = r"?P<date_time>\d{4}-\d{2}-\d{2}T(?:\d{2}:){2}\d{2}\.\d{6}\+\d{2}\:\d{2}"
host_name = r"?P<host_name>[a-zA-Z0-9\-]+"
service = r"(?P<service_name>[a-z\-]+)\[(?P<process_id>\d+)\]"
message = r"?P<message>.*"

ENVELOPE = re.compile(rf"({date_time})\s({host_name})\s{service}\:\s({message})")
 

@dataclass(frozen=True)
class SshEvent:
    timestamp: datetime
    hostname: str
    service: str
    pid: int
    result: str
    user: str
    src_ip: int
    src_port: int
    #there can be a lot more
    

def parse_envelop(line: str) -> dict[str, Any] | None:
    """Split syslog line into timestamp/host/service/pid/message."""
    line = line.strip()
    if not line:
        return None
    match = ENVELOPE.search(line)
    if not match: 
        print(f"Skipped unmatched line: {line}")
        return None
    else:
        parsed_dict = {
            "date.time": match.group("date_time"),
            "host.name": match.group("host_name"),
            "service.name": match.group("service_name"),
            "process.id": match.group("process_id"),
            "message": match.group("message"),
        }
    return parsed_dict

def main():
    sample = Path(__file__).with_name("ssh_log_sample.txt").resolve()
    output_path = Path(__file__).with_name("parsed_ssh_log.json").resolve()
    parsed_logs = []   
    with open (sample, "r", encoding="utf-8") as file:
        for line in file:
            parsed_dict = parse_envelop(line)
            if not parsed_dict:
                continue
            else:
                parsed_logs.append(parsed_dict)
    with open(output_path, "w", encoding="utf-8") as parsed_file:
        json.dump(parsed_logs, parsed_file, indent=4)    

if __name__ == "__main__":
    main()

        
        