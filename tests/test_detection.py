import pytest

from logtriage.detection import detect_ssh_brute_force


def ssh_event(timestamp, source_ip="203.0.113.10", event_type="Failed"):
    return {
        "iso_timestamp": timestamp,
        "hostname": "ubuntu-vm",
        "service": "sshd",
        "event_type": event_type,
        "username": "analyst",
        "source_ip": source_ip,
    }


def test_detects_failed_attempts_inside_window():
    events = [
        ssh_event("2026-09-20T10:00:40+00:00"),
        ssh_event("2026-09-20T10:00:00+00:00"),
        ssh_event("2026-09-20T10:00:30+00:00"),
        ssh_event("2026-09-20T10:00:10+00:00"),
        ssh_event("2026-09-20T10:00:20+00:00"),
    ]

    alerts = detect_ssh_brute_force(events, threshold=5, window_seconds=60)

    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == "203.0.113.10"
    assert alerts[0]["failed_attempts"] == 5
    assert alerts[0]["first_seen"] == "2026-09-20T10:00:00+00:00"
    assert alerts[0]["last_seen"] == "2026-09-20T10:00:40+00:00"


def test_does_not_detect_attempts_outside_window():
    events = [
        ssh_event(f"2026-09-20T10:0{minute}:00+00:00")
        for minute in range(5)
    ]

    alerts = detect_ssh_brute_force(events, threshold=5, window_seconds=60)

    assert alerts == []


def test_ignores_successful_ssh_events():
    events = [
        ssh_event("2026-09-20T10:00:00+00:00"),
        ssh_event("2026-09-20T10:00:10+00:00"),
        ssh_event("2026-09-20T10:00:20+00:00", event_type="Accepted"),
    ]

    alerts = detect_ssh_brute_force(events, threshold=3, window_seconds=60)

    assert alerts == []


def test_reports_each_source_ip_separately():
    events = []
    for second in (0, 10, 20):
        events.append(ssh_event(f"2026-09-20T10:00:{second:02d}+00:00"))
        events.append(
            ssh_event(
                f"2026-09-20T10:00:{second:02d}+00:00",
                source_ip="2001:db8::10",
            )
        )

    alerts = detect_ssh_brute_force(events, threshold=3, window_seconds=60)

    assert [alert["source_ip"] for alert in alerts] == [
        "2001:db8::10",
        "203.0.113.10",
    ]


def test_rejects_invalid_detection_settings():
    with pytest.raises(ValueError, match="threshold and window_seconds must be positive"):
        detect_ssh_brute_force([], threshold=0, window_seconds=60)
