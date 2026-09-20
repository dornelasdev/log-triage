from collections import defaultdict
from datetime import datetime, timedelta
import ipaddress


def detect_ssh_brute_force(events, threshold, window_seconds):
    """Return one alert per source IP using its strongest qualifying time window."""
    if threshold <= 0 or window_seconds <= 0:
        raise ValueError("threshold and window_seconds must be positive")

    attempts_by_ip = defaultdict(list)
    for event in events:
        if event.get("service") != "sshd" or event.get("event_type") != "Failed":
            continue

        source_ip = event.get("source_ip")
        timestamp = event.get("iso_timestamp")
        if not source_ip or not timestamp:
            continue

        try:
            normalized_ip = str(ipaddress.ip_address(source_ip))
            parsed_timestamp = datetime.fromisoformat(timestamp)
        except (TypeError, ValueError):
            continue

        attempts_by_ip[normalized_ip].append((parsed_timestamp, event))

    alerts = []
    window = timedelta(seconds=window_seconds)

    for source_ip, attempts in attempts_by_ip.items():
        attempts.sort(key=lambda item: item[0])
        left = 0
        best_start = 0
        best_end = -1

        for right, (current_time, _) in enumerate(attempts):
            while current_time - attempts[left][0] > window:
                left += 1

            if right - left > best_end - best_start:
                best_start = left
                best_end = right

        failed_attempts = best_end - best_start + 1
        if failed_attempts < threshold:
            continue

        detected_events = attempts[best_start:best_end + 1]
        usernames = sorted({
            event.get("username")
            for _, event in detected_events
            if event.get("username")
        })
        target_hosts = sorted({
            event.get("hostname")
            for _, event in detected_events
            if event.get("hostname")
        })

        alerts.append({
            "rule": "ssh_brute_force",
            "severity": "medium",
            "source_ip": source_ip,
            "failed_attempts": failed_attempts,
            "threshold": threshold,
            "window_seconds": window_seconds,
            "first_seen": detected_events[0][0].isoformat(),
            "last_seen": detected_events[-1][0].isoformat(),
            "usernames": usernames,
            "target_hosts": target_hosts,
        })

    return sorted(alerts, key=lambda alert: alert["source_ip"])
