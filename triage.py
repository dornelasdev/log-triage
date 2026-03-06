import csv
import json
import argparse
from collections import Counter
from parsers.header import parse_log_line, regex_timestamp
from parsers.ssh import parse_message_ssh
from parsers.sudo import parse_message_sudo
from parsers.cron import parse_message_cron

log_file = "sample-logs/auth.log"
fieldnames = ["timestamp", "iso_timestamp", "hostname", "service", "pid", "event_type",
                "user_validity", "username", "source_ip", "source_port", "protocol", "message",
                    "logname", "uid", "euid", "tty", "ruser", "rhost", "target_user", "command", "pwd"]
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"

def main():
    args = get_args()

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

            parsed_message = parse_message_by_service(parsed_header["service"], parsed_header["message"], args.type)

            if parsed_message is None:
                lines_skipped += 1
                continue

            event = { **parsed_header, **parsed_message }

            events.append(event)

    write_json, write_csv = get_output(args)
    if write_json:
        with open("outputs/parsed_events.json", "w") as json_file:
            json.dump(events, json_file, indent=4)

    if write_csv:
        with open("outputs/parsed_events.csv", "w", newline="") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(events)

    summary(events, lines_skipped)

def parse_message_by_service(service, message, selected_type):
    service_key = "cron" if service in ("CRON", "cron", "crond") else service
    if selected_type != "all" and service_key != selected_type:
        return None
    if service == "sshd":
        return parse_message_ssh(message)
    if service == "sudo":
        return parse_message_sudo(message)
    if service in ("CRON", "cron", "crond"):
        return parse_message_cron(message)
    return None

def get_output(args):
    if args.output:
        if args.output == "json":
            return True, False
        if args.output == "csv":
            return False, True
        return True, True

    answer = input("Output format? [json/csv/both]: ").strip().lower()
    if answer == "json":
        return True, False
    if answer == "csv":
        return False, True
    return True, True

def get_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-o", "--output",
        choices=["json", "csv", "both"],
        help="Select output format: json, csv or both",
    )

    parser.add_argument(
        "-t", "--type",
        choices=["all", "sshd", "sudo", "cron"],
        default="all",
        help="Filter logs by service type"
    )

    return parser.parse_args()

def summary(events, lines_skipped):
    by_service = Counter(event.get("service", "unknown") for event in events)
    by_event_type = Counter(event.get("event_type", "unknown") for event in events)

    print(f"\n{BOLD}{GREEN}--- Summary ---{RESET}")
    print(f"Total events parsed: {len(events)}")
    print(f"Lines skipped: {lines_skipped}")

    print(f"\n{BOLD}{YELLOW}By service:{RESET}")
    for service, count in sorted(by_service.items()):
        print(f"- {service}: {count}")

    print(f"\n{BOLD}{CYAN}By event_type:{RESET}")
    for event_type, count in sorted(by_event_type.items()):
        print(f"- {event_type}: {count}")

if __name__ == "__main__":
    main()
