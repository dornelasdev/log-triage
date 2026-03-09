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
  - user validity (`valid` / `invalid`)
  - IP extraction and validation with `ipaddress` (IPv4 + IPv6)
- Sudo parsing:
  - `authentication_failure` (PAM auth failures)
  - `command_executed` (command execution format)
- Cron parsing:
  - `CMD` and `START`
- Timestamp normalization:
  - keeps original `timestamp` and adds `iso_timestamp` from Europe/Lisbon timezone.
- Output formats:
  - `-o csv`
  - `-o json`
  - If no flag is provided, prompts in terminal: `json/csv/both`.


## Project Structure

- `triage.py`
  Main entry point for file reading, routing, skipped-line counter, and output generation.
- `parsers/header.py`
  Header parsing + timestamp normalization.
- `parsers/ssh.py`
  SSH message parser and regex.
- `parsers/sudo.py`
  Sudo auth-failure and command parser.
- `parsers/cron.py`
  Cron message parser.
- `sample-logs/`
  Input samples.
- `outputs/`
  Generated files.


## How It Works

1. Read each line from `log_file`.
2. Validate basic timestamp format.
3. Parse header.
4. Route message parsing by `service`.
5. Merge header + parsed message into a unified event object.
6. Export events as CSV, JSON, or both.


### Usage

From project root:

```bash
python3 triage.py -o json
python3 triage.py -o csv
python3 triage.py -o both
python3 triage.py -t sshd -o json
```

Without flags:

```bash
python3 triage.py
```

The program will prompt:

```text
Output format? [json/csv/both]:
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

### Roadmap (Short-Term)

- Add rule-based SSH brute-force detection (failures per IP within a time window).
- Add optional summary export (summary.json) in addition to terminal summary.

## Known Limitations
- Input path is still hardcoded.
- Parsing currently focuses on specific message formats per service.
- Unsupported formats are skipped and counted in `lines_skipped`.

#### Disclaimer

- Sample logs are sanitized and used for educational purposes.
- This project does not replace SIEM tooling.
