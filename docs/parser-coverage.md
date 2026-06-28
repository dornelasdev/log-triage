# Parser Coverage

This document describes what the parser currently supports, what it intentionally skips, and which log formats are good candidates for future expansion.

## Timestamp Formats

Supported timestamp formats:

```text
Jun 27 13:51:07
2026-06-27T13:55:01.394782+01:00
2026-06-27T13:55:01+01:00
```

Notes:
- Legacy syslog timestamps do not include a year, so the tool adds the current local year during normalization.
- ISO timestamps already include the year and timezone offset, so the tool preserves that information in `iso_timestamp`.

## Supported Services

Currently supported service routing:

| Service value | Parser |
| --- | --- |
| `sshd` | SSH parser |
| `sudo` | Sudo parser |
| `CRON` | Cron parser |
| `cron` | Cron parser |
| `crond` | Cron parser |

Unsupported services are written to unparsed outputs with `unknown_service`.

## SSH Coverage

Supported SSH message patterns:

```text
Accepted password for <username> from <source_ip> port <source_port> <protocol>
Failed password for <username> from <source_ip> port <source_port> <protocol>
Failed password for invalid user <username> from <source_ip> port <source_port> <protocol>
pam_unix(sshd:session): session opened for user <username>(uid=<uid>) by <target_user>(uid=<target_uid>)
```

Extracted fields:

- `event_type`
- `user_validity`
- `username`
- `source_ip`
- `source_port`
- `protocol`
- `uid`
- `target_user`

Notes:
- `source_ip` is validated with Python's `ipaddress` module.
- IPv4 and IPv6 addresses are both supported.

Currently unsupported SSH examples:

```text
Connection closed by authenticating user analyst 203.0.113.10 port 61827 [preauth]
PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.10  user=analyst
```

These lines pass timestamp/header parsing, but are reported as `message_no_match`.

## Sudo Coverage

Supported sudo message patterns:

```text
pam_unix(sudo:auth): authentication failure; logname=<logname> uid=<uid> euid=<euid> tty=<tty> ruser=<ruser> rhost=<rhost> user=<user>
<username> : TTY=<tty> ; PWD=<pwd> ; USER=<target_user> ; COMMAND=<command>
```

Extracted fields:

- `event_type`
- `username`
- `logname`
- `uid`
- `euid`
- `tty`
- `ruser`
- `rhost`
- `target_user`
- `command`
- `pwd`

Currently unsupported sudo examples:

```text
pam_unix(sudo:session): session opened for user root(uid=0) by analyst(uid=1000)
pam_unix(sudo:session): session closed for user root
```

## Cron Coverage

Supported cron message patterns:

```text
(<username>) CMD (<command>)
(<username>) START (<command>)
```

Extracted fields:

- `event_type`
- `username`
- `command`

Currently unsupported cron examples:

```text
(CRON) info (No MTA installed, discarding output)
(CRON) INFO (pidfile fd = 3)
(CRON) INFO (Running @reboot jobs)
pam_unix(cron:session): session opened for user analyst(uid=1000) by analyst(uid=0)
pam_unix(cron:session): session closed for user analyst
```

## Unparsed Reason Labels

The tool currently reports these reason labels:

| Reason | Meaning |
| --- | --- |
| `invalid_timestamp` | The line does not start with a supported timestamp format. |
| `header_no_match` | The timestamp looks valid, but the full log header could not be parsed. |
| `service_filtered_by_type` | The service was valid, but excluded by the selected `-t/--type` filter. |
| `unknown_service` | The service does not have a parser. |
| `message_no_match` | The service is supported, but the message does not match a supported pattern. |

## Expansion Candidates

Good next parser additions:

- SSH session closed events
- SSH pre-auth connection closed events
- SSH PAM aggregate failure lines
- Sudo session opened/closed events
- Cron info/session events
- `pkexec` / `polkit` events
