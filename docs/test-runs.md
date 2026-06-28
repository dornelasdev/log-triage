# Test Runs

## Refactor Branch Validation

**Date: Jun 28 2026**

Before running the sample files, the refactored package layout was checked with Python's bytecode compiler:

```bash
python3 -m py_compile triage.py logtriage/*.py logtriage/parsers/*.py
```

This confirms the modules can be imported and compiled after the package restructuring.

The automated pytest suite was also run after adding parser and router unit tests:

```bash
python -m pytest
```

Result:

```text
20 passed in 0.02s
```

Command:

```bash
python3 triage.py -i sample-logs/auth.log -t all -o both
```

Output:

```text
--- Summary ---
Total events parsed: 20
Lines skipped: 0

By service:
- CRON: 2
- sshd: 16
- sudo: 2

By event_type:
- Accepted: 2
- Failed: 14
- authentication_failure: 1
- command_executed: 1
- cron_command: 1
- cron_start: 1
```

This is the cleaner baseline sample. It is more controlled than the Ubuntu PoC and is useful for checking that all supported parser types still work together without skipped lines.

Command:

```bash
python3 triage.py -i sample-logs/ubuntu_poc.log -t all -o both
```


Output:

```text
--- Summary ---
Total events parsed: 7
Lines skipped: 2

By service:
- CRON: 2
- sshd: 4
- sudo: 1

By event_type:
- Accepted: 1
- Failed: 2
- command_executed: 1
- cron_command: 2
- ssh_session_opened: 1
```

This is the more realistic Ubuntu PoC sample. The username, hostname, and IP address are sanitized, but the log shapes come from real Ubuntu-generated output.

Here we filter for all supported log types with `-t all`.

Command:

```bash
python3 triage.py -i sample-logs/ubuntu_poc.log -t sshd -o json
```

Output:

```text
--- Summary ---
Total events parsed: 4
Lines skipped: 5

By service:
- sshd: 4

By event_type:
- Accepted: 1
- Failed: 2
- ssh_session_opened: 1
```

In this run, the parser focuses only on SSH-related events with `-t sshd`. Non-SSH services are intentionally skipped and reported through the unparsed-events output.

The parsed output is generated as JSON only because of `-o json`.

Command:

```bash
python3 triage.py -i sample-logs/ubuntu_poc.log -t cron -o csv
```

Output:

```text
--- Summary ---
Total events parsed: 2
Lines skipped: 7

By service:
- CRON: 2

By event_type:
- cron_command: 2
```

Here we filter only cron jobs. In the PoC sample, the parser sees two `(analyst) CMD (/usr/bin/echo "log-triage-test")` events with about one minute between them.

The parsed output is generated as CSV only because of `-o csv`.
