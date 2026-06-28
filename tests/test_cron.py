from logtriage.parsers.cron import parse_message_cron


def test_parse_cron_cmd():
    message = '(analyst) CMD (/usr/bin/echo "log-triage-test")'

    result = parse_message_cron(message)

    assert result["event_type"] == "cron_command"
    assert result["username"] == "analyst"
    assert result["command"] == '/usr/bin/echo "log-triage-test"'


def test_parse_cron_start():
    message = "(root) START (/usr/local/bin/backup.sh)"

    result = parse_message_cron(message)

    assert result["event_type"] == "cron_start"
    assert result["username"] == "root"
    assert result["command"] == "/usr/local/bin/backup.sh"


def test_parse_unsupported_cron_message_returns_none():
    message = "(CRON) INFO (Running @reboot jobs)"

    assert parse_message_cron(message) is None
