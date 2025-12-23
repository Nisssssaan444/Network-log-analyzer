# Network Log Analyzer (SOC Tool)

This Python script is a lightweight ** Network Log Analyzer** designed for SOC (Security Operations Center) analysts. It mimics the behavior of a SIEM by monitoring web server access logs (Apache/Nginx) and detecting potential security threats in real-time.

## Features

The script parses **Common Log Format (CLF)** logs and applies signature-based detection for:

1.  **SQL Injection (SQLi)**: Detects patterns like `UNION SELECT`, `OR 1=1`, etc.
2.  **Vulnerability Scanning**: Identifies probing attempts via 404 error spikes.
3.  **Automated Scanners**: Flags known malicious User-Agents (e.g., `sqlmap`, `nikto`).
4.  **Authentication Failures**: Alerts on 401/403 status codes.
5.  **Server Errors**: Monitors for 5xx errors which might indicate successful exploits or DoS.

## Prerequisites

- Python 3.x
- A log file to monitor (default: `access.log` in the current directory)

## Usage

1.  **Prepare the Log File**:
    Ensure `access.log` exists. You can use the provided sample data or point the script to a real server log (e.g., `/var/log/apache2/access.log`).

2.  **Run the Analyzer**:
    ```bash
    python3 log_analyzer.py
    ```

3.  **Simulate Attacks (Optional)**:
    In a separate terminal, you can append malicious lines to the log file to test the detection:
    ```bash
    echo '10.10.10.10 - - [23/Dec/2025:20:46:00 +0545] "GET /product.php?id=1 OR 1=1 HTTP/1.1" 200 4500 "-" "Mozilla/5.0"' >> access.log
    ```

## Customization

You can modify the `NetworkLogAnalyzer` class in `log_analyzer.py` to:
- **Change Log Path**: Update the `LOG_FILE` variable at the bottom of the script.
- **Add Signatures**: Add new strings to `self.suspicious_keywords` list.
- **Adjust Logic**: Modify `analyze_threats` to add more complex rules.

## Example Output

```text
[*] SOC Monitor active. Analyzing access.log...

[!] ALERT from 10.10.10.10 at 23/Dec/2025:20:46:00 +0545
    -> [CRITICAL] Potential Injection Attack Detected: 'OR 1=1' in request
    RAW: GET /product.php?id=1' OR '1'='1 HTTP/1.1
```
