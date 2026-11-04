Decision
a) Supported: ISO 8601 timestamps with offset only (rsyslog_fileformat ); classic BSD syslog lines are counted as malformed
b) Output: human-readable
Output sample:
stdout:
Lines read: 120
Auth events: 85 (success 12, failure 73)
Ignored: 30 (other service 18, sshd non-auth 12)
Malformed: 5

stderr:
line 47: malformed: <38>Oct 11 22:14:15 my-host sshd[12345]: Accepted publickey for root from 192.168.1.50 port 54321 ssh2: RSA SHA256:abc123xyz...
