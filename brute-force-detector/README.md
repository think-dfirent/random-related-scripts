# brute-force-detector

Finds SSH password brute force that **succeeded**: a burst of failed
password logins from one source IP, followed by a successful login from
that IP. Practice problem #2 of a SOC detection track; it consumes
[`ssh-log-parser`](../ssh-log-parser) (#1) as a library.

Design decisions and their reasons: [DESIGN-brute-force.md](DESIGN-brute-force.md).

## Rule (defaults)

> = 5 failed `password`/`keyboard-interactive` logins from one `src_ip`
> within 60 s, then a successful login from the same `src_ip` within 60 s
> of the last failure. publickey failures are ignored. One alert per burst.
> ATT&CK: T1110.001 (one user tried) or T1110.003 (several), then T1078.

## Setup (PowerShell)

```powershell
cd random-related-scripts
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install pytest
pip install -e .\ssh-log-parser    # makes `import ssh_log_parser` work from any folder
```

## Run the tests

```powershell
python -m pytest brute-force-detector
```

## Use it as a library

```python
from pathlib import Path

from brute_force import detect
from ssh_log_parser import parse_line

lines = Path("auth.log").read_text(encoding="utf-8").splitlines()
events = [event for line in lines for event in parse_line(line).events]

for alert in detect(events, threshold=5):
    print(alert.src_ip, alert.technique, alert.success_user, alert.success_time)
```

Run it from `brute-force-detector/` (or put `brute_force.py` on the path);
a CLI comes with problem #8. On `ssh-log-parser/ssh_log_sample.txt` it
reports no alerts: the sample has no 5-failure burst followed by a success.

## Known gaps

See "Known gaps" in [DESIGN-brute-force.md](DESIGN-brute-force.md):
distributed brute force, low-and-slow spraying, and alert fields that
describe only the last 60 s of a longer attack.
