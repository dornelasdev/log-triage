import argparse
import sys

import pytest

from logtriage.cli import get_args, positive_int


def test_positive_int_accepts_positive_values():
    assert positive_int("5") == 5


def test_positive_int_rejects_zero():
    with pytest.raises(argparse.ArgumentTypeError, match="value must be a positive integer"):
        positive_int("0")


def test_get_args_reads_summary_and_detection_options(monkeypatch):
    monkeypatch.setattr(sys, "argv", [
        "triage.py",
        "-o", "json",
        "--export-summary",
        "--ssh-threshold", "3",
        "--ssh-window", "30",
    ])

    args = get_args()

    assert args.export_summary is True
    assert args.ssh_threshold == 3
    assert args.ssh_window == 30
