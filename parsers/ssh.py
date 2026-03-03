import re
import ipaddress

ssh_message_pattern = re.compile(
        r"^(?P<event_type>Accepted|Failed) password for "
        r"(?:(?P<user_validity>invalid) user )?"
        r"(?P<username>\S+) "
        r"from (?P<source_ip>\S+) "
        r"port (?P<source_port>\d+) "
        r"(?P<protocol>\S+)$"
)

def parse_message_ssh(str_message):

    match = ssh_message_pattern.match(str_message)
    if not match:
        return None

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
