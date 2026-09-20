import json

from logtriage.summary import build_summary
from logtriage.writers import write_summary


def test_build_summary_aggregates_events():
    events = [
        {"service": "sshd", "event_type": "Failed"},
        {"service": "sshd", "event_type": "Accepted"},
        {"service": "sudo", "event_type": "command_executed"},
    ]
    detections = [{"rule": "ssh_brute_force", "source_ip": "203.0.113.10"}]

    report = build_summary(
        events,
        lines_skipped=2,
        detections=detections,
        input_file="sample-logs/auth.log",
        selected_type="all",
        ssh_threshold=5,
        ssh_window=60,
    )

    assert report["totals"] == {"events_parsed": 3, "lines_skipped": 2}
    assert report["by_service"] == {"sshd": 2, "sudo": 1}
    assert report["by_event_type"] == {
        "Accepted": 1,
        "Failed": 1,
        "command_executed": 1,
    }
    assert report["detections"] == detections


def test_write_summary_creates_json_file(tmp_path, monkeypatch):
    report = {"totals": {"events_parsed": 1}, "detections": []}
    monkeypatch.setattr("logtriage.writers.OUTPUT_DIR", tmp_path / "outputs")

    write_summary(report)

    summary_path = tmp_path / "outputs" / "summary.json"
    assert json.loads(summary_path.read_text()) == report
