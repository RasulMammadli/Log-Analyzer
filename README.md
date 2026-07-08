# 🛡️ Cyber-Security Log Analyzer

A lightweight, high-performance Java-based **Security Information and Event Management (SIEM)** log analysis tool. This engine parses server authentication logs in real-time, flags malicious credential stuffing activities, detects Brute Force attacks, and dynamically generates a Cyber-Security Analytics Dashboard.

---

## 🚀 Features

* **⚡ Real-Time Log Parsing:** Seamlessly processes standardized server authentication logs.
* **🕵️‍♂️ Credential Stuffing Detection:** Flags critical alerts when attackers try to guess default administrative accounts (`admin`, `root`, `administrator`, etc.).
* **🚨 Automated Brute Force Defense:** Monitors failed attempts and automatically bans malicious IPs after **3 failed attempts**.
* **🔒 Whitelist Integration:** Bypasses trusted IP addresses (e.g., local administrative machine) from security triggers.
* **📊 Analytics Dashboard:** Outputs a comprehensive security integrity percentage and diagnostic report after each analysis cycle.

---

## 🛠️ How It Works

1. The engine reads authentication data from `server.log`.
2. It screens the incoming host IP against the pre-configured `whitelist`.
3. It validates whether a failed login target matches known high-risk usernames.
4. If a threshold breach is discovered, the IP is permanently quarantined inside `blacklist.txt`.

---

## 📋 Sample Log Format

To test the system, your `server.log` should follow this structure:
```text
2026-07-07 12:00:00 INFO User admin logged in successfully from 192.168.1.5
2026-07-07 12:01:22 LOGIN_FAILED Brute force attempt from 10.0.0.42
# Compile and Run the Analyzer
java LogAnalyzer.java
==================================================
🛡️        CYBER SECURITY ANALYSIS REPORT         🛡️
==================================================
🔹 Total Logs Processed     : 7
✅ Successful Login Attempts: 0
❌ Failed Login Attempts    : 5
⚠️ Critical Alerts Triggered : 6
--------------------------------------------------
📊 System Integrity Score   : 28.57%
==================================================
