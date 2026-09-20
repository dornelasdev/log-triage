from logtriage.cli import get_output
from logtriage.detection import detect_ssh_brute_force
from logtriage.parsers.header import parse_log_line, regex_timestamp
from logtriage.router import route_message
from logtriage.summary import build_summary, print_summary
from logtriage.writers import write_outputs, write_summary


def run_pipeline(args):
    write_json, write_csv = get_output(args)

    unparsed_events = []
    events = []
    lines_skipped = 0

    with open(args.input, "r") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue

            if not regex_timestamp.match(line):
                unparsed_events.append({
                    "line": line,
                    "reason": "invalid_timestamp",
                    "service_guess": None,
                })
                lines_skipped += 1
                continue

            parsed_header = parse_log_line(line)
            if parsed_header is None:
                unparsed_events.append({
                    "line": line,
                    "reason": "header_no_match",
                    "service_guess": None,
                })
                lines_skipped += 1
                continue

            parsed_message, skip_reason = route_message(
                parsed_header["service"],
                parsed_header["message"],
                args.type,
            )

            if parsed_message is None:
                unparsed_events.append({
                    "line": line,
                    "reason": skip_reason,
                    "service_guess": parsed_header["service"],
                })
                lines_skipped += 1
                continue

            event = {**parsed_header, **parsed_message}
            events.append(event)

    detections = detect_ssh_brute_force(
        events,
        threshold=args.ssh_threshold,
        window_seconds=args.ssh_window,
    )
    report = build_summary(
        events,
        lines_skipped,
        detections,
        input_file=args.input,
        selected_type=args.type,
        ssh_threshold=args.ssh_threshold,
        ssh_window=args.ssh_window,
    )

    write_outputs(events, unparsed_events, write_json, write_csv)
    if args.export_summary:
        write_summary(report)
    print_summary(report)
