import re

cron_message_pattern = re.compile(
    r"^\((?P<username>[^)]+)\)\s(?P<cron_action>CMD|START)\s+\((?P<command>.+)\)$"
)

def parse_message_cron(str_message):

    match = cron_message_pattern.match(str_message)
    if not match:
        return None

    action = match.group("cron_action")
    event_type = "cron_command" if action == "CMD" else "cron_start"

    return {
        "event_type": event_type,
        "username": match.group("username"),
        "logname": None,
        "uid": None,
        "euid": None,
        "tty": None,
        "ruser": None,
        "rhost": None,
        "target_user": None,
        "command": match.group("command").strip(),
        "pwd": None,
    }
