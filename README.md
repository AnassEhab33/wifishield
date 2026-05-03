# 🛡️ WifiShield — Advanced WiFi Security Auditor

A comprehensive, Python-based WiFi security auditing and active defense tool built for the **CNC 421: Ethical Hacking & Penetration Testing** course.

> All concepts are based directly on **Lecture 7 — Chapter 11: Hacking Wireless Networks** (*Hands-On Ethical Hacking and Network Defense, 3rd Edition*) and **Lecture 8 — Gaining Access: Exploitation**.

---

## 📋 Core Features & Lecture Mapping

| Module | Lecture Reference |
|--------|------------------|
| 📡 **AP Scanner** — SSID, BSSID, channel, signal, encryption | Wardriving / Network Stumbler (Ch.11) |
| 🔐 **Encryption Auditor** — WEP / TKIP / WPA2-AES detection | Ch.11: RC4 → TKIP → CCMP/AES |
| 📛 **Default SSID Detector** — Flags vendor defaults | Table 11-1 (linksys, Tsunami, MSNHOME…) |
| 📢 **SSID Broadcast Checker** | Figure 11-8: Disabling SSID broadcast |
| ⚠️ **WPS Vulnerability Detector** — Flags Reaver-crackable APs | Ch.11 page 75: Reaver attack demo |
| 🖥️ **MAC Whitelist Advisor** — ARP table device audit | Countermeasures slide (page 95) |
| 🎭 **Evil Twin Detector** — Rogue AP / Impersonation detection | Evil Twin / MitM reconnaissance |
| 🚫 **Deauth Attack Detector** — Event Log parsing for DoS | Wi-Fi Disassociation Attacks |
| 🔀 **ARP Spoofing / MitM Detector** — ARP poisoning detection | Lecture 8: MitM Attacks |
| 📊 **Security Score Report** — 0–100 score + HTML report | All modules combined |

---

## 🚀 Quick Start

### Requirements
- Python 3.8+
- Windows OS (relies on `netsh`, `arp`, and `Get-WinEvent`)
- **Administrator Privileges** (Required for flushing ARP cache and reading Event Logs)

### Install & Run

1. Clone the repository and install the required UI/templating libraries:
```powershell
git clone https://github.com/AnassEhab33/wifishield.git
cd wifishield
pip install -r requirements.txt
```

2. Run the tool **as Administrator** to ensure all active defense modules work correctly:
```powershell
python main.py
```

### Main Menu Options
```
1  Run Full Security Audit    ← scans WiFi, detects attacks, generates HTML report
2  Manage MAC Whitelist       ← define trusted local devices
3  Generate HTML Report       ← report generation only
4  Exit
```

---

## 🧪 Testing the Application (Simulations)

To demonstrate the tool's effectiveness, the repository includes scripts to simulate real attacks on your local machine.

### 1. Simulating an ARP Spoofing (MitM) Attack
This simulation deliberately poisons your local ARP table to map the Default Gateway's IP to a fake MAC address.
*   **How to run:** Open a separate PowerShell window **as Administrator** and run:
    ```powershell
    python simulate_arp_spoof.py
    ```
*   **How to test:** While the simulation is running, go to your main WifiShield terminal and press `1` to run a Full Audit. WifiShield will detect the duplicate MAC address, flash a `CRITICAL` alert, and ask if you want to apply the mitigation (flushing the ARP cache).

### 2. Simulating a Deauthentication (DoS) Attack
This script forces multiple rapid Wi-Fi disconnections to trigger Windows Event ID 11004.
*   **How to run:** Open a separate PowerShell window **as Administrator** and run:
    ```powershell
    .\simulate_deauth.ps1
    ```
*   **How to test:** Once the script finishes disconnecting you a few times, reconnect to your Wi-Fi normally. Then, run the WifiShield Full Audit (`1`). It will read the Windows Event Logs, detect the rapid disconnections, and flag an active Deauth attack.

---

## 📊 Security Scoring

Each access point receives a **0–100 security score**. Points are deducted for risky configurations:

| Issue | Deduction | Lecture Basis |
|-------|-----------|---------------|
| WEP / Open encryption | −40 pts | RC4 algorithm, IV attacks (Ch.11) |
| TKIP encryption | −20 pts | Still uses RC4, MIC countermeasures (Ch.11) |
| Default vendor SSID | −15 pts | Table 11-1 — identifiable via Network Stumbler |
| WPS enabled | −15 pts | Reaver PIN brute-force attack (Ch.11, p.75) |
| SSID broadcast ON | −10 pts | Figure 11-8 — visible to passive scanners |

---

## 🗂️ Project Structure

```text
wifi-shield/
├── main.py                  # CLI entry point (interactive dashboard)
├── requirements.txt         # Dependencies (rich, jinja2)
├── simulate_arp_spoof.py    # Python script to poison ARP cache
├── simulate_deauth.ps1      # PowerShell script to force disconnects
├── data/
│   ├── default_ssids.json   # Table 11-1 vendor databases
│   └── mac_whitelist.json   # Trusted MAC addresses
├── modules/
│   ├── scanner.py           # Core AP Scanner
│   ├── encryption_audit.py  # WEP/TKIP/WPA2-AES checker
│   ├── evil_twin_detector.py# Rogue AP detection
│   ├── arp_spoof_detector.py# ARP Poisoning / MitM detection
│   ├── deauth_detector.py   # Event log DoS detection
│   ├── ssid_checker.py      # Default SSID + broadcast detector
│   ├── wps_detector.py      # WPS vulnerability checker
│   ├── mac_auditor.py       # MAC whitelist (ARP table)
│   ├── scorer.py            # 0-100 security score calculator
│   └── report_gen.py        # HTML report generator
└── templates/
    └── report.html          # Jinja2 dark-mode report template
```

---

## ⚠️ Disclaimer

This tool is intended **strictly for educational purposes** as part of an ethical hacking course. Only audit and run simulations on networks you own or have explicit permission to test.

---

## 📚 References

- Simpson, M.T. & Antill, N. *Hands-On Ethical Hacking and Network Defense*, 3rd Edition — Chapter 11
- EJUST CNC 421: Ethical Hacking & Penetration Testing — Lecture 7 & Lecture 8
