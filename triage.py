import csv
import json
import os
import re

# MAIN FUNCTION
def main():
    events = []
    lines_skipped = 0
    log_file = "sample-logs/auth.log"

    regex_timestamp = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}")

    with open(log_file, "r") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue

            if not regex_timestamp.match(line):
                lines_skipped += 1
                print("Skipped line:", repr(line))
                continue

            parsed_header = parse_log_line(line)
            if parsed_header is None:
                lines_skipped += 1
                continue

            parsed_message = parse_message_ssh(parsed_header["message"])
            if parsed_message is None:
                lines_skipped += 1
                continue

            event = { **parsed_header, **parsed_message }

            events.append(event)

    with open("outputs/parsed_events.json", "w") as json_file:
        json.dump(events, json_file, indent=4)

    fieldnames = ["timestamp", "hostname", "service", "pid", "event_type",
                    "user_validity", "username", "source_ip", "source_port", "protocol", "message"]

    with open("outputs/parsed_events.csv", "w", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(events)

    print(f"{lines_skipped} line(s) were not properly parsed.")

def parse_log_line(line):

    header_pattern = re.compile(
        r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<service>\w+)\[(?P<pid>\d+)\]:\s+"
        r"(?P<message>.+)$"
    )

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

def parse_message_ssh(str_message):

    pattern = re.compile(
        r"^(?P<event_type>Accepted|Failed) password for " # captures if "Accepted" or "Failed"
        r"(?:(?P<user_validity>invalid) user )?" # "invalid user", group user_validity
        r"(?P<username>\S+) " # username
        r"from (?P<source_ip>\d+\.\d+\.\d+\.\d+) " # IPv4
        r"port (?P<source_port>\d+) " # port
        r"(?P<protocol>\S+)$" # protocol, usually ssh2
    )

    match = pattern.match(str_message)
    if not match:
        return None

    user_validity = match.group("user_validity") or "valid"

    return {
        "event_type": match.group("event_type"),
        "user_validity": user_validity,
        "username": match.group("username"),
        "source_ip": match.group("source_ip"),
        "source_port": match.group("source_port"),
        "protocol": match.group("protocol"),
    }

if __name__ == "__main__":
    main()
