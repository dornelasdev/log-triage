from collections import Counter
from datetime import datetime, timezone


RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"


def build_summary(
    events,
    lines_skipped,
    detections,
    input_file,
    selected_type,
    ssh_threshold,
    ssh_window,
):
    by_service = Counter(event.get("service", "unknown") for event in events)
    by_event_type = Counter(event.get("event_type", "unknown") for event in events)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_file": str(input_file),
        "service_filter": selected_type,
        "totals": {
            "events_parsed": len(events),
            "lines_skipped": lines_skipped,
        },
        "by_service": dict(sorted(by_service.items())),
        "by_event_type": dict(sorted(by_event_type.items())),
        "detection_config": {
            "ssh_threshold": ssh_threshold,
            "ssh_window_seconds": ssh_window,
        },
        "detections": detections,
    }


def print_summary(report):
    totals = report["totals"]

    print(f"\n{BOLD}{GREEN}--- Summary ---{RESET}")
    print(f"Total events parsed: {totals['events_parsed']}")
    print(f"Lines skipped: {totals['lines_skipped']}")

    print(f"\n{BOLD}{YELLOW}By service:{RESET}")
    for service, count in report["by_service"].items():
        print(f"- {service}: {count}")

    print(f"\n{BOLD}{CYAN}By event_type:{RESET}")
    for event_type, count in report["by_event_type"].items():
        print(f"- {event_type}: {count}")

    print(f"\n{BOLD}{YELLOW}Detections:{RESET}")
    print(f"SSH brute-force alerts: {len(report['detections'])}")
    for detection in report["detections"]:
        print(
            f"- {detection['source_ip']}: "
            f"{detection['failed_attempts']} failures in "
            f"{detection['window_seconds']} seconds"
        )
