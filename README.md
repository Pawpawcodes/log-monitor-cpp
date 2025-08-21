Log Monitoring & Alert System (C++)

A lightweight log analysis tool built in C++17 to scan system logs, detect suspicious activities, and generate alerts.
This project demonstrates system-level programming, text parsing, and alerting — useful in cybersecurity and backend engineering.

Key Features

Detects failed login attempts

Identifies errors and critical issues in logs

Tracks suspicious IP addresses with frequency counts

Stores alerts persistently in alerts.log

Supports color-coded console output (toggle with --no-color)

Portable across Linux, macOS, and Windows (MinGW)

Repository Structure
log-monitor-cpp/
│-- log_monitor.cpp   # Main source code
│-- system.log        # Sample log file for testing
│-- alerts.log        # Generated alerts (output file)
│-- README.md         # Documentation

Build Instructions

Ensure you have a C++17 compatible compiler.

Linux / macOS
g++ -std=c++17 log_monitor.cpp -o log_monitor

Windows (MinGW / g++)
g++ -std=c++17 log_monitor.cpp -o log_monitor.exe

Usage

Run the program from the terminal:

./log_monitor --file system.log --failed 3

Options
Option	Description
--file <f>	Specify log file (default: system.log)
--failed <N>	Threshold for failed login alerts (default: 3)
--no-color	Disable colored output (useful on Windows CMD)
--help	Show usage instructions
Example
Sample Input (system.log)
Jan 21 09:12:15 server sshd[1023]: Failed password for root from 192.168.0.15 port 22
Error: Disk quota exceeded
Critical: Memory usage exceeded 95%
Jan 21 09:15:42 server sshd[1050]: Failed password for admin from 192.168.0.10 port 22

Console Output
----------------------------------
Scan Results:
  Failed logins: 2
  Errors:        1
  Criticals:     1
----------------------------------
ALERT: Multiple failed logins (2)
ALERT: 1 error(s)
CRITICAL: 1 critical issue(s)

Suspicious IPs:
   192.168.0.15 → 1 attempts
   192.168.0.10 → 1 attempts
Alerts saved to alerts.log

Alerts File (alerts.log)
ALERT: Multiple failed logins (2)
ALERT: 1 error(s)
CRITICAL: 1 critical issue(s)
----

Future Enhancements

Realtime log monitoring using <thread>

Email or Slack notifications on critical alerts

Web-based dashboard for visualization

Docker support for deployment
