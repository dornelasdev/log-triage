import re


sudo_message_pattern = re.compile(
    r"^pam_unix\(sudo:auth\): authentication failure; "
    r"logname=(?P<logname>\S*) "
    r"uid=(?P<uid>\d+) "
    r"euid=(?P<euid>\d+) "
    r"tty=(?P<tty>\S+) "
    r"ruser=(?P<ruser>\S*) "
    r"rhost=(?P<rhost>\S*) "
    r"user=(?P<user>\S+)$"
)

sudo_command_pattern = re.compile(
    r"^(?P<username>\S+)\s*:\s*"
    r"TTY=(?P<tty>[^;]+)\s*;\s*"
    r"PWD=(?P<pwd>[^;]+)\s*;\s*"
    r"USER=(?P<target_user>[^;]+)\s*;\s*"
    r"COMMAND=(?P<command>.+)$"
)

def parse_message_sudo(str_message):

    match = sudo_message_pattern.match(str_message)
    if match:
       return {
        "event_type": "authentication_failure",
        "username": match.group("user"),
        "logname": match.group("logname"),
        "uid": match.group("uid"),
        "euid": match.group("euid"),
        "tty": match.group("tty"),
        "ruser": match.group("ruser"),
        "rhost": match.group("rhost"),
        "target_user": None,
        "command": None,
        "pwd": None,
    }

    match = sudo_command_pattern.match(str_message)
    if match:
        return {
        "event_type": "command_executed",
        "username": match.group("username"),
        "logname": None,
        "uid": None,
        "euid": None,
        "tty": match.group("tty").strip(),
        "ruser": None,
        "rhost": None,
        "target_user": match.group("target_user").strip(),
        "command": match.group("command").strip(),
        "pwd": match.group("pwd").strip(),
    }

    return None
