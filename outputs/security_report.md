# SSH Brute Force Detection Report

## 1. Detection Rule

This report flags an IP address as suspicious when it generates 3 or more failed SSH login attempts within 5 minutes.

## 2. Summary

- Suspicious IPs detected: 2
- Threshold: 3 failed attempts
- Time window: 5 minutes

## 3. Suspicious IPs

| IP Address | Failed Attempts | Window | Targeted Users | Time Range | Risk |
|---|---:|---:|---|---|---|
| 192.168.0.10 | 3 | 5 min | admin, root | 2026-06-10 10:01:12 ~ 2026-06-10 10:02:01 | High |
| 203.0.113.5 | 3 | 5 min | guest, user2 | 2026-06-10 10:06:15 ~ 2026-06-10 10:08:02 | High |

## 4. Graph Output

![Failed Attempts by IP](failed_attempts_by_ip.png)

## 5. Security Interpretation

The detected IP addresses generated repeated failed SSH login attempts within a short time window. This behavior may indicate SSH brute-force activity or automated password guessing attempts.

## 6. Limitations

- This tool analyzes stored log files, not real-time traffic.
- The current detection logic is threshold-based.
- Slow brute-force attacks may avoid detection.
- Distributed attacks from many IP addresses may not be detected.
- Different Linux distributions may use slightly different SSH log formats.

## 7. Ethical Use

This project is intended for defensive security education and authorized log analysis only. It should not be used for unauthorized access attempts, scanning, or attacking real systems.
