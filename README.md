# 🛡️ WifiShield — WiFi Security Auditor

A Python-based WiFi security auditing tool built for the **CNC 421: Ethical Hacking & Penetration Testing** course.

> All concepts are based directly on **Lecture 7 — Chapter 11: Hacking Wireless Networks** (*Hands-On Ethical Hacking and Network Defense, 3rd Edition*) and **Lecture 8 — Gaining Access: Exploitation**.

---

## 📋 Features

| Module | Lecture Reference |
|--------|------------------|
| 📡 **AP Scanner** — SSID, BSSID, channel, signal, encryption | Wardriving / Network Stumbler (Ch.11) |
| 🔐 **Encryption Auditor** — WEP / TKIP / WPA2-AES detection | Ch.11: RC4 → TKIP → CCMP/AES |
| 📛 **Default SSID Detector** — Flags vendor defaults | Table 11-1 (linksys, Tsunami, MSNHOME…) |
| 📢 **SSID Broadcast Checker** | Figure 11-8: Disabling SSID broadcast |
| ⚠️ **WPS Vulnerability Detector** — Flags Reaver-crackable APs | Ch.11 page 75: Reaver attack demo |
| 🖥️ **MAC Whitelist Advisor** — ARP table device audit | Countermeasures slide (page 95) |
| 📊 **Security Score Report** — 0–100 score + HTML report | All modules combined |

---

## 🚀 Quick Start

### Requirements
- Python 3.8+
- Windows (uses `netsh wlan` and `arp -a`)

### Install & Run

```powershell
git clone https://github.com/YOUR_USERNAME/wifishield.git
cd wifishield
pip install -r requirements.txt
python main.py
```

### Menu Options
```
1  Run Full Security Audit    ← scans WiFi + generates HTML report
2  Manage MAC Whitelist       ← define trusted devices
3  Generate HTML Report       ← report only
4  Exit
```

---

## 📊 Security Scoring

Each access point receives a **0–100 security score**. Deductions:

| Issue | Deduction | Lecture Basis |
|-------|-----------|---------------|
| WEP / Open encryption | −40 pts | RC4 algorithm, IV attacks (Ch.11) |
| TKIP encryption | −20 pts | Still uses RC4, MIC countermeasures (Ch.11) |
| Default vendor SSID | −15 pts | Table 11-1 — identifiable via Network Stumbler |
| SSID broadcast ON | −10 pts | Figure 11-8 — visible to passive scanners |
| WPS enabled | −15 pts | Reaver PIN brute-force attack (Ch.11, p.75) |

---

## 🗂️ Project Structure

```
wifi-shield/
├── main.py                  # CLI entry point (rich interactive menu)
├── requirements.txt
├── data/
│   └── default_ssids.json   # Table 11-1 from lecture
├── modules/
│   ├── scanner.py           # AP Scanner
│   ├── encryption_audit.py  # WEP/TKIP/WPA2-AES checker
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

This tool is intended **strictly for educational purposes** as part of an ethical hacking course.  
Only audit networks you own or have explicit permission to test.

---

## 📚 References

- Simpson, M.T. & Antill, N. *Hands-On Ethical Hacking and Network Defense*, 3rd Edition — Chapter 11
- EJUST CNC 421: Ethical Hacking & Penetration Testing — Lecture 7 & Lecture 8
