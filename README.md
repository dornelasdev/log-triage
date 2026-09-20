# Log Triage Tool

A Python-based log parser focused on SOC L1 workflows.
It reads Linux-style auth logs, parses supported services, and exports normalized events to JSON and/or CSV.
*This project is primarily a learning-focused SOC log parsing exercise.*


## Features
- Parses syslog-style headers with optional PID:
  - `service[pid]: message`
  - `service: message`
- Supports multiple log sources:
  - `sshd`
  - `sudo`
  - `cron` / `crond` / `CRON`
- SSH parsing:
  - `Accepted` and `Failed` events.
  - `ssh_session_opened` events.
  - user validity (`valid` / `invalid`)
  - IP extraction and validation with `ipaddress` (IPv4 + IPv6)
- Sudo parsing:
  - `authentication_failure` (PAM auth failures)
  - `command_executed` (command execution format)
- Cron parsing:
  - `CMD` and `START`
- Timestamp normalization:
  - supports legacy syslog timestamps and ISO timestamps with timezone offsets.
  - keeps original `timestamp` and adds `iso_timestamp`.
- Output formats:
  - `-o csv`
  - `-o json`
  - `-o both`
  - `-i/--input` for selecting a log file
  - If no flag is provided, prompts in terminal: `json/csv/both`.
- Unparsed event reporting:
  - `invalid_timestamp`
  - `header_no_match`
  - `service_filtered_by_type`
  - `unknown_service`
  - `message_no_match`
- Rule-based SSH brute-force detection:
  - groups failed authentications by source IP.
  - detects the strongest time window for each IPv4 or IPv6 source.
  - defaults to 5 failures within 60 seconds.
  - supports configurable thresholds and time windows.
- Optional `summary.json` export with parsing totals, event breakdowns, detection settings, and alerts.


## Project Structure

- `triage.py`
  Command-line entry point.
- `logtriage/cli.py`
  CLI argument parsing and output selection.
- `logtriage/pipeline.py`
  Main parsing workflow.
- `logtriage/router.py`
  Service-based message routing.
- `logtriage/schema.py`
  Output field definitions.
- `logtriage/writers.py`
  JSON/CSV output generation.
- `logtriage/summary.py`
  Summary report construction and terminal output.
- `logtriage/detection.py`
  Rule-based SSH brute-force detection.
- `logtriage/parsers/header.py`
  Header parsing + timestamp normalization.
- `logtriage/parsers/ssh.py`
  SSH message parser and regex.
- `logtriage/parsers/sudo.py`
  Sudo auth-failure and command parser.
- `logtriage/parsers/cron.py`
  Cron message parser.
- `sample-logs/`
  Input samples, including a sanitized Ubuntu PoC log.
- `outputs/`
  Generated files created at runtime.
- `docs/`
  Examples, parser coverage, and manual validation notes.


## How It Works

1. Read each line from the selected input file.
2. Validate basic timestamp format.
3. Parse header.
4. Route message parsing by `service`.
5. Merge header + parsed message into a unified event object.
6. Evaluate parsed SSH failures against the configured detection rule.
7. Export events as CSV, JSON, or both.
8. Optionally export the summary and detections to `outputs/summary.json`.


### Usage

From project root:

```bash
python3 triage.py -o json
python3 triage.py -o csv
python3 triage.py -o both
python3 triage.py -t sshd -o json
python3 triage.py -i sample-logs/auth.log -t all -o both
python3 triage.py -i sample-logs/ubuntu_poc.log -t all -o both
python3 triage.py -i sample-logs/auth.log -o json --export-summary
python3 triage.py -i sample-logs/ubuntu_poc.log -o json --ssh-threshold 2 --ssh-window 30 --export-summary
```

Without flags:

```bash
python3 triage.py
```

The program will prompt:

```text
Output format? [json/csv/both]:
```

For runnable examples, see [docs/examples.md](docs/examples.md).
For supported and unsupported parser patterns, see [docs/parser-coverage.md](docs/parser-coverage.md).
For manual validation notes, see [docs/test-runs.md](docs/test-runs.md).

## Testing

Install development dependencies inside a virtual environment:

```bash
python -m pip install -r requirements-dev.txt
```

Run the automated test suite:

```bash
python -m pytest
```

## Output Schema

Core fields:
- timestamp
- iso_timestamp
- hostname
- service
- pid
- event_type
- username
- message

Additional fields are filled when available (for example, SSH network fields or sudo-specific fields):
- user_validity, source_ip, source_port, protocol
- logname, uid, euid, tty, ruser, rhost, target_user, command, pwd

Non-applicable fields remain empty in CSV / `null` in JSON.

The optional `outputs/summary.json` report contains:
- parsed and skipped totals
- counts by service and event type
- SSH detection configuration
- rule-based detection results

### Roadmap (Short-Term)

- Expand detection rules beyond SSH brute-force activity.
- Add configurable output paths and detection profiles.

## Known Limitations
- Parsing currently focuses on specific message formats per service.
- Unsupported formats are skipped and counted in `lines_skipped`.
- SSH brute-force detection reports one strongest qualifying window per source IP and parser run.

#### Disclaimer

- Sample logs are sanitized and used for educational purposes.
- This project does not replace SIEM tooling.
