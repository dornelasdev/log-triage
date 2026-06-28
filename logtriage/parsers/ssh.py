import ipaddress
import re


ssh_message_pattern = re.compile(
    r"^(?P<event_type>Accepted|Failed) password for "
    r"(?:(?P<user_validity>invalid) user )?"
    r"(?P<username>\S+) "
    r"from (?P<source_ip>\S+) "
    r"port (?P<source_port>\d+) "
    r"(?P<protocol>\S+)$"
)

ssh_session_opened_pattern = re.compile(
    r"^pam_unix\(sshd:session\): session opened for user "
    r"(?P<username>\S+)\(uid=(?P<uid>\d+)\) by "
    r"(?P<target_user>\S+)\(uid=(?P<target_uid>\d+)\)$"
)


def parse_message_ssh(str_message):
    match = ssh_message_pattern.match(str_message)
    if match:
        user_validity = match.group("user_validity") or "valid"

        try:
            ipaddress.ip_address(match.group("source_ip"))
        except ValueError:
            return None

        return {
            "event_type": match.group("event_type"),
            "user_validity": user_validity,
            "username": match.group("username"),
            "source_ip": match.group("source_ip"),
            "source_port": match.group("source_port"),
            "protocol": match.group("protocol"),
        }

    match = ssh_session_opened_pattern.match(str_message)
    if match:
        return {
            "event_type": "ssh_session_opened",
            "user_validity": None,
            "username": match.group("username"),
            "source_ip": None,
            "source_port": None,
            "protocol": None,
            "uid": match.group("uid"),
            "target_user": match.group("target_user"),
        }

    return None
