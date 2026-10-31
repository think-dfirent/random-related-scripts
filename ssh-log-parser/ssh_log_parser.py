import re
from pathlib import Path
import json
date_time = r"?P<date_time>\d{4}-\d{2}-\d{2}T(?:\d{2}:){2}\d{2}\.\d{6}\+\d{2}\:\d{2}"
host_name = r"?P<host_name>[a-zA-Z0-9\-]+"
service = r"(?P<service_name>[a-z\-]+)\[(?P<process_id>\d+)\]"
message = r"?P<message>.*"

pattern = re.compile(rf"({date_time})\s({host_name})\s{service}\:\s({message})")
sample = Path(__file__).with_name("ssh_log_sample.txt").resolve()
output_path = Path(__file__).with_name("parsed_ssh_log.json").resolve()
parsed_logs = []
with open (sample, "r", encoding="utf-8") as file:
    
    for line in file:
        line = line.strip()
        if not line:
            continue
        match = pattern.search(line)
        if not match: 
            print(f"Skipped unmatched line: {line}")
            continue
        else:
            parsed_dict = {
                "date.time": match.group("date_time"),
                "host.name": match.group("host_name"),
                "service.name": match.group("service_name"),
                "process.id": match.group("process_id"),
                "message": match.group("message"),
            }
            parsed_logs.append(parsed_dict)
with open(output_path, "w", encoding="utf-8") as parsed_file:
    json.dump(parsed_logs, parsed_file, indent=4)

        
        