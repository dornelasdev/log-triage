import re
from datetime import datetime
from zoneinfo import ZoneInfo


LEGACY_TIMESTAMP = r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
ISO_TIMESTAMP = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?[+-]\d{2}:\d{2}"

regex_timestamp = re.compile(rf"^(?:{LEGACY_TIMESTAMP}|{ISO_TIMESTAMP})")

header_pattern = re.compile(
    rf"^(?P<timestamp>{LEGACY_TIMESTAMP}|{ISO_TIMESTAMP})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<service>[\w.-]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.+)$"
)


def iso_timestamp(ts: str, year: int | None = None, tz_name: str = "Europe/Lisbon") -> str:
    if "T" in ts:
        return datetime.fromisoformat(ts).isoformat()

    if year is None:
        year = datetime.now().year
    dt = datetime.strptime(f"{year} {ts}", "%Y %b %d %H:%M:%S")
    dt = dt.replace(tzinfo=ZoneInfo(tz_name))
    return dt.isoformat()


def parse_log_line(line):
    match = header_pattern.match(line)
    if not match:
        return None

    raw_ts = match.group("timestamp")
    iso_ts = iso_timestamp(raw_ts)

    return {
        "timestamp": raw_ts,
        "iso_timestamp": iso_ts,
        "hostname": match.group("hostname"),
        "service": match.group("service"),
        "pid": match.group("pid"),
        "message": match.group("message"),
    }
