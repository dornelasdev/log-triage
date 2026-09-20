import argparse
from pathlib import Path

from logtriage.config import (
    DEFAULT_INPUT_FILE,
    DEFAULT_SSH_THRESHOLD,
    DEFAULT_SSH_WINDOW_SECONDS,
)


def positive_int(value):
    parsed_value = int(value)
    if parsed_value <= 0:
        raise argparse.ArgumentTypeError("value must be a positive integer")
    return parsed_value


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

    parser.add_argument(
        "--export-summary",
        action="store_true",
        help="Export the terminal summary and detections to outputs/summary.json",
    )

    parser.add_argument(
        "--ssh-threshold",
        type=positive_int,
        default=DEFAULT_SSH_THRESHOLD,
        help=f"Failed SSH attempts required for detection (default: {DEFAULT_SSH_THRESHOLD})",
    )

    parser.add_argument(
        "--ssh-window",
        type=positive_int,
        default=DEFAULT_SSH_WINDOW_SECONDS,
        metavar="SECONDS",
        help=f"SSH detection window in seconds (default: {DEFAULT_SSH_WINDOW_SECONDS})",
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
