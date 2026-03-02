import csv
import json
import os
import re
import ipaddress

log_file = "sample-logs/auth.log"
fieldnames = ["timestamp", "hostname", "service", "pid", "event_type",
                "user_validity", "username", "source_ip", "source_port", "protocol", "message",
                    "logname", "uid", "euid", "tty", "ruser", "rhost", "target_user", "command", "pwd"]

regex_timestamp = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}")
header_pattern = re.compile(
        r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<service>[\w.-]+)(?:\[(?P<pid>\d+)\])?:\s+"
        r"(?P<message>.+)$"
)
ssh_message_pattern = re.compile(
        r"^(?P<event_type>Accepted|Failed) password for " # captures if "Accepted" or "Failed"
        r"(?:(?P<user_validity>invalid) user )?" # "invalid user", group user_validity
        r"(?P<username>\S+) " # username
        r"from (?P<source_ip>\d+\.\d+\.\d+\.\d+) " # IPv4
        r"port (?P<source_port>\d+) " # port
        r"(?P<protocol>\S+)$" # protocol, usually ssh2
)

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

# MAIN FUNCTION
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

            if parsed_header["service"] == "sshd":
                parsed_message = parse_message_ssh(parsed_header["message"])
            elif parsed_header["service"] == "sudo":
                parsed_message = parse_message_sudo(parsed_header["message"])
            else:
                parsed_message = None

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

def parse_message_ssh(str_message):

    match = ssh_message_pattern.match(str_message)
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

if __name__ == "__main__":
    main()
