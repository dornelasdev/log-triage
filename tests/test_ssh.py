from logtriage.parsers.ssh import parse_message_ssh


def test_parse_failed_ssh_login():
    message = "Failed password for analyst from 203.0.113.10 port 61827 ssh2"

    result = parse_message_ssh(message)

    assert result["event_type"] == "Failed"
    assert result["user_validity"] == "valid"
    assert result["username"] == "analyst"
    assert result["source_ip"] == "203.0.113.10"
    assert result["source_port"] == "61827"
    assert result["protocol"] == "ssh2"


def test_parse_failed_invalid_user_ssh_login():
    message = "Failed password for invalid user ghost from 2001:db8:85a3::8a2e:370:7334 port 60004 ssh2"

    result = parse_message_ssh(message)

    assert result["event_type"] == "Failed"
    assert result["user_validity"] == "invalid"
    assert result["username"] == "ghost"
    assert result["source_ip"] == "2001:db8:85a3::8a2e:370:7334"


def test_parse_accepted_ssh_login():
    message = "Accepted password for analyst from 203.0.113.10 port 61840 ssh2"

    result = parse_message_ssh(message)

    assert result["event_type"] == "Accepted"
    assert result["username"] == "analyst"
    assert result["source_ip"] == "203.0.113.10"


def test_parse_ssh_session_opened():
    message = "pam_unix(sshd:session): session opened for user analyst(uid=1000) by analyst(uid=0)"

    result = parse_message_ssh(message)

    assert result["event_type"] == "ssh_session_opened"
    assert result["username"] == "analyst"
    assert result["uid"] == "1000"
    assert result["target_user"] == "analyst"


def test_parse_ssh_invalid_ip_returns_none():
    message = "Failed password for analyst from 999.999.999.999 port 61827 ssh2"

    assert parse_message_ssh(message) is None


def test_parse_unsupported_ssh_message_returns_none():
    message = "Connection closed by authenticating user analyst 203.0.113.10 port 61827 [preauth]"

    assert parse_message_ssh(message) is None
