from logtriage.parsers.sudo import parse_message_sudo


def test_parse_sudo_auth_failure():
    message = "pam_unix(sudo:auth): authentication failure; logname=analyst uid=1000 euid=0 tty=/dev/pts/0 ruser=analyst rhost= user=analyst"

    result = parse_message_sudo(message)

    assert result["event_type"] == "authentication_failure"
    assert result["username"] == "analyst"
    assert result["logname"] == "analyst"
    assert result["uid"] == "1000"
    assert result["tty"] == "/dev/pts/0"


def test_parse_sudo_command_execution():
    message = "analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/usr/bin/tail -f /var/log/auth.log"

    result = parse_message_sudo(message)

    assert result["event_type"] == "command_executed"
    assert result["username"] == "analyst"
    assert result["tty"] == "pts/0"
    assert result["target_user"] == "root"
    assert result["command"] == "/usr/bin/tail -f /var/log/auth.log"
    assert result["pwd"] == "/home/analyst"


def test_parse_unsupported_sudo_message_returns_none():
    message = "pam_unix(sudo:session): session closed for user root"

    assert parse_message_sudo(message) is None
