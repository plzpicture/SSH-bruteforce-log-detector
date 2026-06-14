# SSH Brute Force Detection Report

## 1. Detection Rules

### Brute Force Rule

- 3 or more failed SSH login attempts within 5 minutes.

### Password Spraying Rule

- 3 or more unique usernames attempted from the same IP within 5 minutes.

## 2. Summary

- Brute Force suspicious IPs detected: 2
- Password Spraying suspicious IPs detected: 1
- Time window: 5 minutes

## 3. Brute Force Suspicious IPs

| IP Address | Failed Attempts | Window | Targeted Users | Time Range | Risk |
|---|---:|---:|---|---|---|
| 192.168.0.10 | 3 | 5 min | admin, root | 2026-06-10 10:01:12 ~ 2026-06-10 10:02:01 | High |
| 203.0.113.5 | 3 | 5 min | guest, user2 | 2026-06-10 10:06:15 ~ 2026-06-10 10:08:02 | High |

## 4. Password Spraying Suspicious IPs

| IP Address | Unique Usernames | Window | Targeted Users | Time Range | Risk |
|---|---:|---:|---|---|---|
| 192.168.0.10 | 3 | 5 min | admin, root, test | 2026-06-10 10:01:12 ~ 2026-06-10 10:02:44 | Medium |

## 5. Graph Output

![Failed Attempts by IP](failed_attempts_by_ip.png)

## 6. MITRE ATT&CK Mapping

- T1110 - Brute Force
- T1110.003 - Password Spraying
- T1021.004 - Remote Services: SSH

## 7. Security Interpretation

Repeated failed SSH login attempts within a short time window may indicate brute-force activity. Attempts against multiple unique usernames from the same IP may indicate password spraying or account discovery behavior.

## 8. Limitations

- This tool analyzes stored log files, not real-time traffic.
- The current detection logic is threshold-based.
- Slow brute-force attacks may avoid detection.
- Distributed attacks from many IP addresses may not be detected.
- Different Linux distributions may use slightly different SSH log formats.

## 9. Ethical Use

This project is intended for defensive security education and authorized log analysis only. It should not be used for unauthorized access attempts, scanning, password guessing, or attacking real systems.
