# ssh-log-parser

Turns raw OpenSSH (`sshd`) log lines into structured authentication events, and accounts for every line it could not turn into one.

Practice problem #1 of a SOC detection track. Problem #2, a brute-force detector, imports this module as a library.

**Purpose:** answer _"who tried to log in, from where, how, and did it work?"_ without reading `auth.log` by eye, and never drop a line silently. Every input line lands in exactly one bucket, and the tool reports how many lines went into each.

## Quick start

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install pytest ruff

python ssh_log_parser.py              # summary on screen, details on stderr
python ssh_log_parser.py 2>$null      # summary only
python ssh_log_parser.py 2> skipped.txt
pytest
```

The script reads `ssh_log_sample.txt` next to it and has no command-line arguments yet. Adding a CLI is problem #8.

## Output

| Channel                    | Content                                                                                                             |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| **stdout**                 | Human-readable summary (the result)                                                                                 |
| **stderr**                 | One self-contained line per ignored or malformed input line (diagnostics)                                           |
| **`parsed_ssh_logs.json`** | All auth events as a JSON array, written next to the script (git-ignored)                                           |
| **exit code**              | `0` = every line was accounted for; `1` = a bug left some line in no bucket (a `BUG:` line on stderr says how many) |

Sample run on `ssh_log_sample.txt`:

```
Lines read: 22
Auth lines: 10 -> events: 17 (success 3, failure 14)
Ignored: 10 (non-sshd 3, unmatched_message 7)
Malformed: 1
Blank: 1
```

stderr (truncated):

```
line 5: ignored (non-sshd): 2025-03-07T15:36:18.630644+00:00 example-server systemd-logind[808]: New session ...
line 7: ignored (unmatched_message): 2025-03-07T15:38:12.441022+00:00 example-server sshd[2491901]: Invalid user admin ...
line 22: malformed: --- CORRUPTED SYSLOG LINE WITHOUT TIMESTAMP OR ENVELOPE ---
```

The summary reports **lines** and **events** as separate numbers on purpose. One `message repeated N times` line produces several events.

## Line buckets

| Bucket                       | Meaning                                                 | Example                                                                        |
| ---------------------------- | ------------------------------------------------------- | ------------------------------------------------------------------------------ |
| auth                         | `sshd` `Accepted`/`Failed` line → 1 or more `SshEvent`s | `Failed password for root from 1.2.3.4 port 22 ssh2`                           |
| ignored: `non-sshd`          | Valid syslog envelope, other service                    | `CRON[...]`, `sudo[...]`, `systemd-logind[...]`                                |
| ignored: `unmatched_message` | `sshd` line that is not an auth result                  | `session opened`, `Invalid user ...`, `Connection closed ... [preauth]`        |
| malformed                    | Line we refuse to interpret                             | No/bad envelope, classic syslog, impossible date, invalid IP, repeat count < 1 |
| blank                        | Empty or whitespace-only line                           |                                                                                |

## Event schema

`SshEvent` (frozen dataclass). JSON keys from `to_dict()` are shown in brackets:

| Field                           | Type                                                                                             | Notes                                               |
| ------------------------------- | ------------------------------------------------------------------------------------------------ | --------------------------------------------------- |
| `timestamp` (`timestamp`)       | timezone-aware `datetime`                                                                        | ISO 8601 string in JSON                             |
| `hostname` (`host.name`)        | `str`                                                                                            | Short name or FQDN                                  |
| `pid` (`pid`)                   | `int`                                                                                            | sshd process id                                     |
| `result` (`result`)             | `"success"` \| `"failure"`                                                                       | From `Accepted` / `Failed`                          |
| `method` (`method`)             | `password`, `publickey`, `keyboard-interactive`, `hostbased`, `gssapi-with-mic`, `none`, `other` | `keyboard-interactive/pam` → `keyboard-interactive` |
| `user` (`user`)                 | `str`                                                                                            |                                                     |
| `invalid_user` (`invalid.user`) | `bool`                                                                                           | `True` for `... for invalid user X ...`             |
| `src_ip` (`src.ip`)             | `str`                                                                                            | Validated IPv4 or IPv6                              |
| `src_port` (`src.port`)         | `int`                                                                                            |                                                     |

## Using it as a library (for #2)

```python
from ssh_log_parser import parse_line, summarize

outcome = parse_line(line)          # ParseResult
outcome.events                      # list[SshEvent], empty if skipped
outcome.skip_reason                 # "malformed" | "non-sshd" | "unmatched_message" | None

with open("auth.log", encoding="utf-8") as f:
    summary = summarize(f)          # any Iterable[str]: a file or a list of strings
summary.events, summary.unaccounted
```

`ParseResult` enforces _either_ events _or_ a skip reason. Constructing any other combination raises `ValueError`, so no line can fall between buckets.

Consumers should import the library and not read `main()`'s stdout. stdout is for humans and its format may change.

## Decisions

1. **Timestamps: ISO 8601 with UTC offset only** (rsyslog `RSYSLOG_FileFormat`, e.g. `2025-03-07T15:36:18.567155+00:00`, `±HH:MM`, 6 fractional digits).
   Classic BSD syslog (`Mar  7 15:36:20`) is counted as **malformed**, not guessed. It has no year and no timezone, so guessing breaks at New Year and across hosts. It would also silently corrupt the time windows in #2.
2. **Output: human-readable summary for people, library API for programs.** The JSON file is a convenience copy of the events.
3. **`message repeated N times: [ ... ]`** (rsyslog `$RepeatedMsgReduction`) is expanded to **N extra events**. The original line before it has already been counted. This setting is on in Ubuntu's default `rsyslog.conf` and compresses exactly the identical `Failed password` lines a brute-force run produces on one connection.
4. **Untrusted text never decides how a line is parsed.** The username is attacker-controlled, so both regexes are anchored at **both ends** and the username is restricted to `[A-Za-z0-9_.-]+`. Lines such as
   `Failed password for invalid user root from 6.6.6.6 port 22 ssh2 from 5.6.7.8 port 4444 ssh2`
   are rejected instead of attributing a fake source IP. Regression tests cover both known injection variants.
5. **Nothing is dropped silently.** Every line is counted in exactly one bucket, `Summary.unaccounted` must be 0, and the exit code reflects it.

## Known gaps

Documented on purpose. Not planned for #1.

- **Repeated-message timestamps:** all N expanded events carry the time the summary line was written, not the time of each attempt. Those times are lost in the source log.
- **No deduplication:** byte-identical lines (e.g. from a forwarding duplicate) are counted twice. The sample's last `message repeated` lines are such duplicates.
- **Username whitelist:** usernames outside `[A-Za-z0-9_.-]` (e.g. `admin$`, `user@corp`) make the line `unmatched_message`. This is safe, but those failed attempts are not counted as events.
- **Injection attempts are not flagged:** they land in `unmatched_message` together with harmless sshd lines. A dedicated `suspicious` bucket would surface them to analysts.
- **Key-only servers:** username probes produce only `Invalid user ...` + `Connection closed ... [preauth]`, with no `Failed` line, so they generate no event.
- **Memory:** `message repeated N times` creates N event objects, and the whole file is held in memory. Fine for single log files, but not for streaming.
- **Input path is hard-coded** to `ssh_log_sample.txt` (CLI comes in #8).

## Tests

```powershell
pytest -q
```

Tests target the public API (`parse_line`, `summarize`, `ParseResult`). A `make_line()` helper builds a valid line, and each rejection row changes **one** field. Covered:

- valid events: publickey, password on an invalid user, `keyboard-interactive/pam`, FQDN host, `+07:00` offset
- full field-by-field `SshEvent` checks, including repeated-message expansion
- rejections: non-sshd, sshd non-auth, classic syslog, impossible date, invalid IP, `repeated 0 times`, injection variants
- `ParseResult` refuses impossible states
- `summarize` accounts for every line and reports lines ≠ events

## Files

```
ssh_log_parser.py        parser library + main()
test_ssh_log_parser.py   pytest suite
ssh_log_sample.txt       sample input incl. edge cases and injection lines
```
