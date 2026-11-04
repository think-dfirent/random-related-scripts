import pytest
from ssh_log_parser import (
    SshEvent,
    parse_envelope,
    parse_auth_method,
    parse_line,
    parse_message,
)


def test_parse_envelope_timezone_positive_offset():
    result = parse_envelope(
        f"2025-03-07T15:36:18.567155+00:00 host sshd[2491798]: Accepted publickey for root from 203.0.113.0 port 65350 ssh2: RSA SHA256:XaeoOmXzt2fEF67opjDlcTRDUiFksXVXKxCAJSSwzch"
    )
    assert result["date_time"] == "2025-03-07T15:36:18.567155+00:00"


def test_parse_envelope_timezone_negative_offset():
    result = parse_envelope(
        f"2025-03-07T15:36:18.567155-00:00 host sshd[2491798]: Accepted publickey for root from 203.0.113.0 port 65350 ssh2: RSA SHA256:XaeoOmXzt2fEF67opjDlcTRDUiFksXVXKxCAJSSwzch"
    )
    assert result["date_time"] == "2025-03-07T15:36:18.567155-00:00"


@pytest.mark.parametrize("hostname", ["cuongns", "desktop-03"])
def test_parse_envelope_hostname(hostname):
    result = parse_envelope(
        f"2025-03-07T15:36:18.567155+00:00 {hostname} sshd[2491798]: Accepted publickey for root from 203.0.113.0 port 65350 ssh2: RSA SHA256:XaeoOmXzt2fEF67opjDlcTRDUiFksXVXKxCAJSSwzch"
    )
    assert result.get("host_name") == hostname

@pytest.mark.parametrize("service_name", [""])