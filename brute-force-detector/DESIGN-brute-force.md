# Brute-force detector (#2) — design note v1

## Rule

Alert when one `src_ip` has >= `threshold` (5) failed password logins within
`window` (60 s), followed by a successful password login from the same
`src_ip` (any user) within `success_window` (60 s) after the last failure.

- "Password logins" = methods `password` and `keyboard-interactive`
  (`GUESSABLE_METHODS`). publickey, hostbased, gssapi-with-mic and none are
  ignored, as failures and as successes. Reason: brute force guesses
  secrets; a rejected public key is not a guess, and an ssh-agent holding
  several keys produces publickey failures on a normal login.
- Failures for invalid (non-existent) users count. They are the core of
  password spraying and username guessing.

## Grouping key: src_ip

Catches both guessing (one IP -> one user, T1110.001) and fast spraying
(one IP -> many users, T1110.003). Cost: more false positives from shared
IPs (NAT, VPN, bastion). src_ip + user would be more precise but blind to
spraying.

## Boundaries

- Threshold is inclusive: 5 failures trigger, 4 do not.
- Window is inclusive: `last_failure - first_failure <= window`.
- Success window is inclusive: `success_time - last_failure <= success_window`.
- All three are keyword arguments of `detect()` with these defaults.

## Ordering and duplicates

- Events are sorted by `(timestamp, result == "success")`: on a tie, the
  failure sorts first, so a success logged in the same second as the 5th
  failure still follows it.
- Timestamps are timezone-aware (from #1); never compared as strings.
- `message repeated N times` copies count as N failures. Caveat: they all
  carry the summary line's timestamp, not the real attempt times.
- v1 holds all events in memory. Fine for one log file.

## State per src_ip

A deque of recent failures, pruned on every new failure (anything older
than `window` relative to the newest failure is dropped).

- **Success that alerts** -> the deque is cleared. One alert per burst:
  5 failures + 3 successes -> 1 alert. No cooldown: a cooldown adds state
  and would hide a real second burst.
- **Success that does not alert** (too few failures, OR the success came
  more than `success_window` after the last failure) -> nothing changes.
  Reason: the success is attacker-controllable (a known low-value account,
  or a colleague behind the same NAT). If any success reset the count, an
  attacker could guess 4 times, log in with a known account, and repeat
  forever below the threshold. The sliding window already forgets old
  failures, so clearing adds only the evasion.
  Cost: a user who mistypes 4 times, logs in, mistypes once more and logs
  in again within 60 s raises an alert. Rare and cheap to triage.
- Failures with no success -> no alert in v1 (a lower-severity
  "failure burst" rule is a v2 candidate).

## Output: Alert (frozen dataclass)

| field            | type           | meaning                                   |
| ---------------- | -------------- | ----------------------------------------- |
| src_ip           | str            | grouping key                              |
| first_failure    | datetime       | oldest failure in the deque at alert time |
| last_failure     | datetime       |                                           |
| failure_count    | int            | failures in the deque at alert time       |
| users_tried      | frozenset[str] | users in the deque at alert time          |
| hostnames        | frozenset[str] | target hosts (sshd's syslog host)         |
| success_time     | datetime       |                                           |
| success_user     | str            | the account that is now compromised       |
| success_hostname | str            |                                           |

Derived: `technique` = T1110.001 if one user was tried, else T1110.003.
No destination IP: sshd auth lines don't log the server address.

**Open question (2026-11-25):** first_failure, failure_count, users_tried and
hostnames describe only the failures still inside the window, not the whole
attack. A 1-hour attack with 2,000 attempts reports at most the last ~60 s.
Decide: keep as rule evidence, rename, or track the whole campaign.

## Module boundary

- `brute-force-detector/` is a sibling of `ssh-log-parser/`.
  `ssh-log-parser` has a `pyproject.toml` and is installed in editable mode
  (`pip install -e ../ssh-log-parser`), so `import ssh_log_parser` works
  from any folder, for scripts and pytest alike.
- Chosen over putting both files in one folder (the first plan) because each
  problem keeps its own folder, and over `sys.path.append("../...")`
  because a relative path resolves from the current folder: the same
  command works in one folder and fails in another.
- Public interface:
  `detect(events: Iterable[SshEvent], *, threshold=5,
window=timedelta(seconds=60), success_window=timedelta(seconds=60))
-> list[Alert]`
- `detect()` takes events, not log lines: tests build SshEvent objects
  directly, and the detector never depends on the log text format.
- A CLI comes in #8.

## Detection hygiene

**Data source:** sshd authentication logs (`/var/log/auth.log` on
Debian/Ubuntu, `/var/log/secure` on RHEL, or journald), ISO 8601
timestamps, default `LogLevel INFO`.

**Blind spots:** key-only servers log username probes as
"Invalid user" + preauth close with no Failed line, so no events.
RepeatedMsgReduction compresses attempts (see #1).

**Likely false positives and tuning:**
| false positive | tuning |
|-------------------------------------------------------------|----------------------------------------------------------|
| Script/service account with a stale password, then fixed | allowlist (src_ip, user) pairs for automation |
| Shared egress IP (NAT, VPN, bastion): many users' typos add up | per-IP threshold, or key by src_ip+user for known shared IPs |
| Vulnerability scanner with credentialed checks | allowlist scanner IPs |
| User: 4 typos, login, 1 typo, login within 60 s | accept (see "State per src_ip") |

**ATT&CK:** failures -> T1110.001 Password Guessing / T1110.003 Password
Spraying. Success -> T1078.003 Valid Accounts: Local Accounts (T1078.002 if
the host authenticates against a domain). Internet-facing SSH also maps to
T1133 External Remote Services.

## Known gaps (v1)

- Distributed brute force (many IPs -> one user): missed by the src_ip key.
- Low-and-slow spraying (spread over minutes or hours): missed by the 60 s window.
- Alert fields describe only the last window, not the whole attack.
