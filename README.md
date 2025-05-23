# Network Intrusion Detection System (NIDS)

A lightweight Python-based Network Intrusion Detection System that monitors network traffic and detects potential SYN flood attacks and port scans using the `scapy` library.

---

## 🚀 Features

- ✅ Real-time packet sniffing using Scapy
- 🔍 Detection of SYN floods based on traffic volume
- 📝 Logs suspicious activity to `suspicious_activity.txt`
- 🧪 Tested with tools like `hping3` and `nmap`

---

## 🛠️ Requirements

- Python 3.8+
- [Scapy](https://scapy.readthedocs.io/)
- Root privileges (required for packet sniffing)

---

## 📦 Installation

1. **Clone the repo or create your project folder:**

```bash
git clone <your-repo-url>
cd nids
