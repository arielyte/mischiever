# Mischiever 😈

### The Network Swiss Army Knife

**Mischiever** is a modular, multithreaded offensive cybersecurity **platform** built in C++ from scratch. Unlike script-based tools, Mischiever is engineered as a unified framework where attack modules share a central "brain" (Session State) to coordinate the entire kill chain—from reconnaissance to execution.

It constructs network packets byte-by-byte using raw sockets, giving the user complete control over Layer 2 (Ethernet) and Layer 3 (IP) headers to bypass standard security filters.

---

### ⚠️ Legal Disclaimer

**This tool is created for educational purposes and authorized testing only.**
The author is not responsible for any misuse, damage, or illegal activity caused by this software. Use only on networks you own or have explicit permission to test.

---

### 🏛️ Platform Architecture

Mischiever is not just a collection of scripts; it is an Object-Oriented C2 (Command & Control) framework designed for scalability and state persistence.

* **🧠 Session-Based State Management:** Implements a central `Session` structure that holds global network truths. Configuration is set once and is instantly available to all loaded modules.
* **🔌 Polymorphic Design:** Utilizes an abstract `AttackModule` base class to enforce a unified interface (`run`, `stop`) across all tools.
* **📊 Real-Time Dashboard:** Features a dynamic TUI that displays live interface status, target configurations, and active attack flags at a glance.

---

### ⚔️ Capabilities

#### 1. Network Reconnaissance (Scanner)
* **Technique:** Implements a **Parallelized Ping Sweep** combined with Kernel ARP Table harvesting (`/proc/net/arp`).
* **Performance:** Maps an entire /24 subnet (254 hosts) in under 2 seconds without external dependencies like Nmap.
* **Integration:** Embedded directly into the configuration menu via the `find` command.

#### 2. ARP Attack Suite (MITM & DoS)
Mischiever leverages a unified ARP engine with dual operating modes:
* **Mode A: MITM (Man-in-the-Middle):** Poisons the target and gateway to intercept traffic, while automatically managing kernel `ip_forward` and `sysctl` redirects to maintain stealth.
* **Mode B: Blackhole (DoS):** Performs poisoning but deliberately drops all forwarded packets, cutting internet access without Wi-Fi disconnection.

#### 3. DNS Spoofing (The Illusionist)
* **Technique:** A sophisticated MITM extension that intercepts UDP Port 53 queries.
* **Race Condition Control:** Automatically injects `iptables` DROP rules to silence real DNS servers, ensuring the forged response (crafted with custom IP/UDP checksums) arrives first.
* **Impact:** Redirects any domain (e.g., `neverssl.com`) to an attacker-controlled IP.

#### 4. DHCP Attack Suite
* **DHCP Starvation:** Floods the network with forged DHCP Discover packets using randomized MAC addresses to exhaust the router's IP pool.
* **DHCP Lease Breaker:** Forges "DHCP Release" packets on behalf of a target IP to instantly kick specific devices off the network.

#### 5. Traffic Sniffer (Mini-Wireshark)
* **Technique:** Integrated **`libpcap`** implementation for real-time packet capture.
* **Target Highlighting:** Automatically highlights packets involving the configured Target IP in yellow.
* **Auto-Save:** Dumps sessions into timestamped `.pcap` files with automatic user-ownership (`SUDO_UID`) management.

#### 6. Transport Layer Floods (DoS)
* **SYN Flood:** Uses **Raw Sockets (`IP_HDRINCL`)** to flood targets with "HALF_OPEN" TCP connections using spoofed Source IPs.
* **ICMP Ping Flood:** Generates a high-throughput stream of ICMP Echo Requests to consume target CPU and bandwidth.

#### 7. Stateful NAT Exhaustion (Gateway DoS)
* **Technique:** A multithreaded, high-velocity UDP flood designed to attack the gateway's Port Address Translation (PAT) engine.
* **Mechanism:** Bypasses basic QoS and rate-limiting by randomizing the internal Source IP, Source Port, Destination IP, and Destination Port for every single packet. This forces the router to generate a unique 5-tuple state entry in its memory for each forged packet.
* **Impact:** Rapidly consumes all available ephemeral public ports (or exhausts router RAM), silently dropping any new legitimate internet connections from the LAN without physically severing the local network link, crashing the whole ass network in seconds.

---

### ⚙️ System Automation & Stealth
Mischiever handles the "dirty work" of Linux networking automatically:
* **Firewall Management:** Dynamically toggles `iptables` FORWARD chains to isolate or intercept traffic.
* **Kernel Tuning:** Automatically modifies `/proc/sys/net/ipv4/` (`ip_forward` and `send_redirects`) to ensure stable MITM positions.
* **Input Validation:** Built-in Regex-based IP validation and interface detection to prevent system crashes.

 ---

### 🧠 Smart Configuration Features
Mischiever replaces manual lookups with context-aware automation:
* **Auto-Gateway Detection:** Parses `/proc/net/route` to identify the default gateway (Destination `0.0.0.0`) automatically.
* **MAC Resolution:** Instantly resolves MAC addresses for Targets and Gateways using local ARP lookups.
* **Lazy Config:** Type `find` in any IP field to launch the scanner or gateway detector instantly. 

---

### 💾 Tech Stack
* **Language:** C++ (OOP, STL, Multithreading)
* **Networking:** Native Linux Raw Sockets (`SOCK_RAW`, `AF_PACKET`) & `libpcap`
* **Database:** SQLite3 (Automatic session logging)
* **System:** Direct parsing of Kernel interfaces (`/proc/net/*`) and `ioctl`.
---

### 🛠️ Installation & Usage

**Prerequisites:**

* System: Linux (Kali Linux, Ubuntu, or Arch Linux)
* Privileges: Root (Required for Raw Socket access)

```bash
# 1. Install Dependencies

# For Debian / Kali / Ubuntu:
sudo apt-get update
sudo apt-get install libpcap-dev libsqlite3-dev build-essential iptables

# For Arch Linux:
sudo pacman -S libpcap sqlite base-devel iptables imv

# 2. Compile
make

# 3. Run (Must be run as root for Raw Sockets)
sudo ./mischiever

```