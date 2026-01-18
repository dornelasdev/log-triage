# SSH Log Triage Tool

A simple Python parsing script that converts Linux-style logs into JSON and CSV files for better visualization.

When dealing with a largen number of SSH connection log entries(and potentially other protocols), logs can quickly become overwhelming. Excessive information and inconsistent formatting may lead to confusion during analysis.

This tool is mainly designed for SOC Level 1 purposes. Precise formatting helps make information clearer and significantly improves later analysis, especially when working with CSV files.

Currently the tool only reads SSH logs, more specific auth.logs for sshd services; Future versions will support additional protocols and parameters!

## Objectives

The primary objective of this project is to test and reinforce my learning in cybersecurity techniques with a focus on foundational concepts. Reading and parsing logs is a very common activity in this field, and accurate analysis is essential for effective incident investigation.

Some of the implemented funcitions reflect ther topics I wanted to focus on, such as:
- Regular expressions(Regex)
- Event structuring.
- File handling using `with open`
- Exporting parsed data into JSON and CSV files.

## Folders and Files
- outputs/: Contains a single `.gitkeep` file. Parsed JSON and CSV files will be exported to this folder.
- sample-logs/: Contains a sanitized Linux-formatted `auth.log` file using common private IP addresses, generic usernames, and ports. You can replace this with your own `auth.log` path by modifying the `log_variable` on line 10.
- triage.py: The main entry point for the program, containing all functions and logic.

## Workflow

- First, the program reads the file specified in the assigned variable.
- A checksum process validate each line. If a line is blank or incorrectly formatted, a message will indicate that a certain number of lines were not properly parsed.
- The program then parses the **header**, which includes all information before the `:`.
- Next, it parses the **message**, which contains the SSH-related information after the `:`.
- An `event` object is built from the parsed data, and the final results are esxported.

## Main Functions on triage.py

### main()
- Initializes the event list, error handling for `lines_skipped`, and the log file to be read.
- Reads the selected log file path(by default, the auth.log inside the sample-logs folder).
- The returned values from `parse_log_line` and `parse_log_message` are processed and appended to the events list.
- Writes the parsed data into both JSON and CSV files. The CSV file will appear simple when opened in a text editor, with values separated by commas.
- Displays a warning message if any lines wre skipped during parsing.

### parse_log_line(line)

- Uses regular expressions to extract the timestamp, hostname, service, PID, and message.
- If the format matches, the line is considered properly parsed and does not increment the `lines_skipped` counter.
- Returns the parsed values in a specific order. Changing this order may brak the program.

Back in the main() function the data is stored as `parsed_header`. If the line is blank or incorrectly formatted, the `lines_skipped` counter is incremented.

### parse_message_ssh(str_message)

- Uses regex to determine the `event_type`, identifying whether the SSH connection was **Accepted** or **Failed**.
- `user_validity` handles the "user" field  that follows the word `for`.
- Extracts `username`, `source_ip`, `source_port`, and `protocol`.
- If the message matches the expected format, it is returned to the `main()` function as a parsed line.

As with the previous function, the parsed message is combined with `parsed_header`. If parsing fails, the `lines_skipped` counter is incremented.

### Exporting Results

As mentioned earlier, JSON and CSV are widely used formats for log analysis. CSV files can be easily opened in spreadsheet tools, while JSON files provide a structured and readable representation of events.

Both files are exported to the `outputs` folder. You can change the destination by modifying the paths on lines 39 and 45.

### Error Handling

The `lines_skipped` counter acts as a safeguard. For example, if a  20-line log file contains one blank or malformed line, the program will display a warning message in the terminal.

### How to Use

```
cd log-triage
python3 triage.py
```

### Future Improvements

- Add support for additional services beyond SSH.
- Detect and generate alerts for multiple authentication failures.
- Identify potential brute-force attacks based on rapid IP changes followed by successful connections
- Possible SIEM integration.

#### Disclaimer

- All logs used in the `auth.log` file are 100% fictional and sanitized, using common private IPs addresses and generic ports.
- The project was created for educational purposes only.
- It does not replace SIEM tools.
- The AI usage was basically to guide me during the regex syntax and help me understand it. Proper tests were conducted to ensure the code is robust and does not break with the current implementation.

