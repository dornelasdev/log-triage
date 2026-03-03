import csv
import json
from parsers.header import parse_log_line, regex_timestamp
from parsers.ssh import parse_message_ssh
from parsers.sudo import parse_message_sudo
from parsers.cron import parse_message_cron

log_file = "sample-logs/auth.log"
fieldnames = ["timestamp", "hostname", "service", "pid", "event_type",
                "user_validity", "username", "source_ip", "source_port", "protocol", "message",
                    "logname", "uid", "euid", "tty", "ruser", "rhost", "target_user", "command", "pwd"]

def main():
    events = []
    lines_skipped = 0

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

            parsed_message = parse_message_by_service(parsed_header["service"], parsed_header["message"])

            if parsed_message is None:
                lines_skipped += 1
                continue

            event = { **parsed_header, **parsed_message }

            events.append(event)

    with open("outputs/parsed_events.json", "w") as json_file:
        json.dump(events, json_file, indent=4)

    with open("outputs/parsed_events.csv", "w", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(events)

    print(f"{lines_skipped} line(s) were not properly parsed.")

def parse_message_by_service(service, message):
    if service == "sshd":
        return parse_message_ssh(message)
    if service == "sudo":
        return parse_message_sudo(message)
    if service in ("CRON", "cron", "crond"):
        return parse_message_cron(message)
    return None

if __name__ == "__main__":
    main()
