# Examples

This page shows common ways to run the tool against the included sample logs.

## Baseline Sample

File:

`sample-logs/auth.log`

Purpose:

Clean mixed auth log used as the default input sample.

Command:

```bash
python3 triage.py -i sample-logs/auth.log -t all -o both
```

Expected behavior:
- Parses supported `sshd`, `sudo`, and `cron` events.
- Generates parsed JSON/CSV outputs.
- Generates unparsed outputs only if unsupported lines are present.

## Ubuntu PoC Sample

File:

`sample-logs/ubuntu_poc.log`

Purpose:

Sanitized logs generated from an Ubuntu VM. This sample includes both supported and unsupported real-world auth log formats.

Command:

```bash
python3 triage.py -i sample-logs/ubuntu_poc.log -t all -o both
```

Expected behavior:
- Parses SSH accepted/failed password events.
- Parses sudo command execution.
- Parses cron command events.
- Reports unsupported SSH session/PAM lines as `message_no_match`.

Expected summary:
```text
Total events parsed: 6
Lines skipped: 3
```

## Service Filtering

Parse only SSH events:

```bash
python3 triage.py -i sample-logs/ubuntu_poc.log -t sshd -o json
```

Expected behavior:
- SSH password events are parsed.
- Sudo and cron lines are reported as `service_filtered_by_type`.
- Unsupported SSH session/PAM lines are reported as `message_no_match`.

## Output Selection

Generate only CSV:

```bash
python3 triage.py -i sample-logs/auth.log -t all -o csv
```

Generate only JSON:

```bash
python3 triage.py -i sample-logs/auth.log -t all -o json
```

Generate both:

```bash
python3 triage.py -i sample-logs/auth.log -t all -o both
```

## Unparsed Events

When one or more lines cannot be parsed, the tool writes them to `outputs/unparsed_events.json` and `outputs/unparsed_events.csv`.
Reason labels include:
- `invalid_timestamp`
- `header_no_match`
- `service_filtered_by_type`
- `unknown_service`
- `message_no_match`