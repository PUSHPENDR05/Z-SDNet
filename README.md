# 🛡️ Z-SDNet: Zero-Trust SDN Security Framework & DDoS Sentinel

Z-SDNet is a Software-Defined Networking (SDN) project implementing Zero-Trust network segmentation, dynamic REST-based firewalling, and automated real-time DDoS mitigation using OpenFlow 1.3.

---

## 🚀 Key Features

* **Decoupled Architecture:** Clean separation of Control Plane (Ryu Controller) and Data Plane (Open vSwitch on Mininet).
* **Zero-Trust Micro-segmentation:** Dynamic Access Control Lists (ACLs) enforced at wire-speed via Flow Table Priorities (Priorities 0, 10, 100, 200, 300).
* **Automated DDoS Sentinel:** Continuous Layer 3/4 flow-rate monitoring that auto-detects and quarantines flood attacks (>500 pkt/s).
* **Interactive Web GUI:** Real-time single-page dashboard (`dashboard.html`) to control host isolation states via Northbound WSGI REST API.

---

## ⚡ Quick Start

### 1. Launch Ryu Controller
```bash
ryu-manager controller.py --ofp-listen-host 0.0.0.0 --ofp-tcp-listen-port 6653 --wsapi-port 8080
