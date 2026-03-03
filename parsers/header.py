import re

regex_timestamp = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}")

header_pattern = re.compile(
        r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<service>[\w.-]+)(?:\[(?P<pid>\d+)\])?:\s+"
        r"(?P<message>.+)$"
)

def parse_log_line(line):

    match = header_pattern.match(line)

    if not match:
        return None

    return {
        "timestamp": match.group("timestamp"),
        "hostname": match.group("hostname"),
        "service": match.group("service"),
        "pid": match.group("pid"),
        "message": match.group("message")
    }
