import argparse
from pathlib import Path

from logtriage.config import DEFAULT_INPUT_FILE


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
        help="Filter logs by service type",
    )

    parser.add_argument(
        "-i", "--input",
        default=DEFAULT_INPUT_FILE,
        type=Path,
        help="Path to the log file to parse",
    )

    return parser.parse_args()


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
