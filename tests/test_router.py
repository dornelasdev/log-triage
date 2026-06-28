from logtriage.router import route_message


def test_route_supported_ssh_message():
    message = "Accepted password for analyst from 203.0.113.10 port 61840 ssh2"

    parsed_message, reason = route_message("sshd", message, "all")

    assert parsed_message["event_type"] == "Accepted"
    assert reason is None


def test_route_filtered_service():
    message = '(analyst) CMD (/usr/bin/echo "log-triage-test")'

    parsed_message, reason = route_message("CRON", message, "sshd")

    assert parsed_message is None
    assert reason == "service_filtered_by_type"


def test_route_unknown_service():
    parsed_message, reason = route_message("pkexec", "some message", "all")

    assert parsed_message is None
    assert reason == "unknown_service"


def test_route_message_no_match():
    message = "Connection closed by authenticating user analyst 203.0.113.10 port 61827 [preauth]"

    parsed_message, reason = route_message("sshd", message, "all")

    assert parsed_message is None
    assert reason == "message_no_match"
