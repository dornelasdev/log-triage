from collections import Counter


RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"


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
