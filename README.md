# Z-SDNet: DDoS Sentinel & Zero-Trust Firewall

Z-SDNet is a Software-Defined Networking (SDN) security architecture implementing Zero-Trust micro-segmentation, dynamic REST-based flow control, and automated Layer 3/Layer 4 real-time DDoS mitigation using OpenFlow 1.3.

---

## 🚀 Key Features

* **Decoupled Architecture:** Clean separation of Control Plane (Ryu Controller) and Data Plane (Open vSwitch on Mininet).
* **Zero-Trust Micro-segmentation:** Dynamic Access Control Lists (ACLs) enforced at wire-speed via Flow Table Priorities (Priorities 0, 10, 100, 200, 300).
* **Automated DDoS Sentinel:** Continuous Layer 3/4 flow-rate telemetry monitoring that auto-detects and quarantines flood attacks (>500 pkt/s).
* **Interactive Web GUI:** Real-time single-page dashboard (`dashboard.html`) to monitor live traffic telemetry and manage host quarantine states via Northbound WSGI REST API.

---

## 🏗️ System Architecture & Flow Hierarchy

```text
+-------------------------------------------------------------+
|                 Web Dashboard / REST Client                 |
+-------------------------------------------------------------+
                               | (Northbound REST API :8080)
+-------------------------------------------------------------+
|                 Ryu SDN Controller Core                     |
|  [ DDoS Monitor Engine ] <---> [ Flow & Policy Manager ]   |
+-------------------------------------------------------------+
                               | (Southbound OpenFlow 1.3)
+-------------------------------------------------------------+
|           Open vSwitch (OVS) Data Plane Subsystem           |
|  Table 0: Quarantine (300) -> Custom ACL (200) -> L2/L3 (0) |
+-------------------------------------------------------------+
Flow PriorityPurpose / Traffic TypeOpenFlow Action300Blacklisted / Quarantined IPsDROP (Hardware-level drop)200Active Zero-Trust Firewall ACLsOUTPUT / DROP100Control Protocols (ARP, LLDP)NORMAL / FLOOD0Default Table-MissSend to Controller (OFP_PACKET_IN)⚡ Quick Start GuidePrerequisitesLinux / Ubuntu (or WSL on Windows)Python 3.8+Mininet & Open vSwitchRyu SDN Framework1.

1.Launch Ryu Controller
 
 Bash
 ryu-manager controller.py --ofp-tcp-listen-port 6653 --wsapi-port 8080

2. Start Mininet Topology
Bash
sudo mn --custom topo.py --topo mytopo --controller=remote,ip=127.0.0.1,port=6653 --switch=ovsk,protocols=OpenFlow13
3. Open Telemetry Dashboard
Open dashboard.html in your browser or serve it via Python:

Bash
python3 -m http.server 8000
🧪 DDoS Detection & Mitigation Verification
Simulate a SYN/UDP flood attack inside Mininet:

Bash
# Inside Mininet CLI:
mininet> h2 hping3 --flood -S -p 80 10.0.0.1
Detection: Flow stats collector catches threshold violations (>500 pkt/s).

Mitigation: Controller installs a Priority 300 DROP rule for host h2 and reflects quarantine status on the Web GUI.

🛠️ Tech Stack
Controller: Ryu SDN Framework (Python 3)

Data Plane: Open vSwitch (OVS), Mininet

Protocols: OpenFlow 1.3, TCP/IP, ARP, ICMP

Frontend: HTML5, CSS3, JavaScript (REST API)