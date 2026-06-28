from logtriage.parsers.header import parse_log_line


def test_parse_legacy_syslog_header():
    line = "Jun 27 13:51:07 ubuntu-vm sshd[5354]: Failed password for analyst from 203.0.113.10 port 61827 ssh2"

    result = parse_log_line(line)

    assert result["timestamp"] == "Jun 27 13:51:07"
    assert result["hostname"] == "ubuntu-vm"
    assert result["service"] == "sshd"
    assert result["pid"] == "5354"
    assert result["message"] == "Failed password for analyst from 203.0.113.10 port 61827 ssh2"
    assert "T13:51:07" in result["iso_timestamp"]


def test_parse_iso_header():
    line = "2026-06-27T13:55:01.394782+01:00 ubuntu-vm CRON[5933]: (analyst) CMD (/usr/bin/echo test)"

    result = parse_log_line(line)

    assert result["timestamp"] == "2026-06-27T13:55:01.394782+01:00"
    assert result["iso_timestamp"] == "2026-06-27T13:55:01.394782+01:00"
    assert result["hostname"] == "ubuntu-vm"
    assert result["service"] == "CRON"
    assert result["pid"] == "5933"


def test_parse_header_without_pid():
    line = "Jan 10 06:22:11 server sudo: analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/usr/bin/id"

    result = parse_log_line(line)

    assert result["service"] == "sudo"
    assert result["pid"] is None
    assert result["message"] == "analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/usr/bin/id"


def test_parse_invalid_header_returns_none():
    assert parse_log_line("not a valid auth log line") is None
