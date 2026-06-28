import csv
import json

from logtriage.config import OUTPUT_DIR
from logtriage.schema import FIELDNAMES, UNPARSED_FIELDNAMES


def write_outputs(events, unparsed_events, write_json, write_csv):
    should_write_outputs = write_json or write_csv or bool(unparsed_events)
    if should_write_outputs:
        OUTPUT_DIR.mkdir(exist_ok=True)

    if write_json:
        with open(OUTPUT_DIR / "parsed_events.json", "w") as json_file:
            json.dump(events, json_file, indent=4)

    if write_csv:
        with open(OUTPUT_DIR / "parsed_events.csv", "w", newline="") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=FIELDNAMES)
            writer.writeheader()
            writer.writerows(events)

    if unparsed_events:
        with open(OUTPUT_DIR / "unparsed_events.json", "w") as f:
            json.dump(unparsed_events, f, indent=4)

        with open(OUTPUT_DIR / "unparsed_events.csv", "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=UNPARSED_FIELDNAMES)
            writer.writeheader()
            writer.writerows(unparsed_events)
