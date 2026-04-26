# Mischiever

Mischiever is a Linux-only C++ command-line tool for authorized LAN lab work, educational packet analysis, and controlled networking experiments. The current codebase is a menu-driven prototype with a shared session state, a small SQLite attack-history database, a `libpcap` traffic sniffer, and several raw-socket protocol modules. It is intended for networks you own or have explicit permission to test.

## Safety And Authorized Use

Use Mischiever only in a local lab, classroom, home network you control, or another environment where you have clear written permission.

Some modules can disrupt network connectivity, change local host networking state, or generate high packet volume. Do not run this tool against public targets, third-party networks, production networks, or devices you are not authorized to test.

The project does not currently include strong runtime guardrails such as rate limits, public-target blocking, per-module confirmations, or scoped firewall rollback. Treat every active module as potentially disruptive until those safeguards are added.

## Current Features

### Interactive Menu

- Text-based main menu.
- Target configuration wizard.
- Current configuration display.
- Attack history view backed by SQLite.
- Automatic detection of the first active non-loopback IPv4 interface when possible.

### Target Configuration Helpers

The configuration flow stores values in a shared `Session` object:

- Interface.
- Target IP and MAC.
- Gateway IP and MAC.
- DHCP server IP.
- DNS server IP.
- DNS spoofing domain and redirect IP when DNS spoofing is selected.

The `find` command in configuration prompts can:

- Run a local `/24` ping sweep based on the interface IP.
- Read discovered hosts from `/proc/net/arp`.
- Detect the default gateway from `/proc/net/route`.
- Resolve MAC addresses through the local ARP cache.
- Read a DNS server from `/etc/resolv.conf`.
- Query the DHCP server through `nmcli` when available, with gateway fallback.

### Traffic Sniffer

- Uses `libpcap` for live packet capture.
- Opens the selected interface in promiscuous mode.
- Writes timestamped `.pcap` files under `sniffs/`.
- Prints a simple IPv4 packet table for TCP, UDP, ICMP, and other IPv4 packets.
- Highlights packets involving the configured target IP.
- Attempts to set pcap file ownership back to the original sudo user using `SUDO_UID` and `SUDO_GID`.

### Protocol And Lab Simulation Modules

The current modules are available through the menu:

- ARP spoofing: sends repeated forged ARP replies to the configured target and gateway. It enables IP forwarding and disables send redirects while active.
- ARP blackhole: uses the ARP poisoning flow and sets forwarding behavior so forwarded traffic is dropped.
- DNS spoofing: watches raw IPv4 UDP DNS queries and sends a forged A-record response when the requested name contains the configured domain. The menu requires ARP spoofing to be active first.
- DHCP starvation: sends DHCP Discover packets with randomized locally administered MAC addresses.
- DHCP release: sends repeated DHCP Release packets using the configured target IP/MAC and DHCP server IP.
- ICMP flood: sends ICMP Echo Request packets to the configured target IP.
- SYN flood: sends raw TCP SYN packets to the configured target IP on port 80.
- NAT table exhaustion simulation: sends randomized UDP traffic toward the configured gateway MAC from multiple threads.

These modules are for isolated, authorized lab testing only.

## Architecture Overview

The application is organized around a small set of core components:

- `src/main.cpp`: registers the Ctrl-C handler, constructs `Menu`, and starts the main loop.
- `Menu`: owns the shared `Session`, the sniffer, and a vector of attack modules. It handles display, input, configuration, module selection, logging, and start/stop flow.
- `Session`: shared mutable state for interface, target, gateway, DHCP/DNS settings, module status flags, `Database`, and `HelperFunctions`.
- `AttackModule`: abstract interface implemented by protocol modules with `run(Session*)`, `stop()`, and `get_name()`.
- `Sniffer`: background `libpcap` capture and pcap writer.
- `Database`: SQLite wrapper for attack history.
- `HelperFunctions`: interface discovery, IP/MAC validation, local scanning, gateway/DNS/DHCP lookup, and Linux networking toggles.

Protocol implementations live in `src/protocols/`, with headers in `src/headers/`.

## Build Requirements

Mischiever is built with the provided `Makefile`.

Required:

- Linux.
- `g++` with C++14 support.
- `make`.
- POSIX/Linux networking headers.
- `libpcap` development package.
- SQLite3 development package.
- pthread support.

Runtime tools used by some features:

- `ping`
- `iptables`
- `sysctl`
- `nmcli` for DHCP server detection when available
- `xdg-open` or `imv` only for optional local image easter eggs

### Debian, Ubuntu, Kali

```bash
sudo apt-get update
sudo apt-get install build-essential libpcap-dev libsqlite3-dev iptables network-manager
```

### Arch Linux

```bash
sudo pacman -S base-devel libpcap sqlite iptables networkmanager
```

## Build

```bash
make
```

The Makefile currently compiles each source file, links the `mischiever` binary, and then removes intermediate object files.

## Run

Most features require root privileges or equivalent Linux capabilities because they use raw sockets, packet capture, and networking state changes.

```bash
sudo ./mischiever
```

Run the binary from the repository root so relative paths resolve correctly:

- `mischiever_history.db` is created in the current working directory.
- Packet captures are saved under `sniffs/`.
- Optional local image files are loaded from `misc/`.

## Runtime Side Effects

Depending on the selected module, Mischiever may:

- Open raw sockets with `AF_PACKET`, `AF_INET`, `SOCK_RAW`, or protocol-specific raw sockets.
- Open a live `libpcap` capture in promiscuous mode.
- Create `sniffs/` and write `.pcap` files.
- Create or update `mischiever_history.db`.
- Read `/proc/net/arp`, `/proc/net/route`, and `/etc/resolv.conf`.
- Execute `ping` during host/MAC discovery.
- Execute `nmcli` during DHCP server discovery.
- Change `/proc/sys/net/ipv4/ip_forward`.
- Change `net.ipv4.conf.all.send_redirects` through `sysctl`.
- Insert or delete an `iptables` rule for forwarded UDP destination port 53 during DNS spoofing.
- Change the default `iptables` FORWARD policy during ARP blackhole mode.

Review your host networking state before and after lab runs, especially when using ARP, DNS, or blackhole modes.

## Attack History

Mischiever creates a SQLite database named `mischiever_history.db`. The current schema records:

- ID.
- Type.
- Date.
- Time.
- Attacker IP text.
- Victim IP text.

The database does not yet store full session configuration, duration, result status, errors, packet counts, interface, gateway, or pcap paths.

## Known Limitations

- The project is a prototype, not a hardened framework.
- There are no automated tests yet.
- There are no default rate limits or duration limits on high-volume modules.
- Safety checks are mostly documentation and menu flow, not enforced policy.
- `Menu` currently handles too many responsibilities: UI, configuration, module lookup, lifecycle, and logging.
- Module selection is based on display-name string matching.
- `Session` is a mutable state container with limited validation.
- System-state cleanup is best effort and not fully scoped.
- ARP blackhole mode changes the global `iptables` FORWARD policy.
- DNS parsing is simple and handles only straightforward query names.
- DNS domain matching uses substring matching.
- SYN packet construction is incomplete because TCP checksums are not calculated.
- The SYN target port is hardcoded to 80.
- The sniffer prints only shallow IPv4 protocol information.
- `make clean` removes the binary, `mischiever_history.db`, and the `sniffs/` directory.

## Repository Map

```text
src/main.cpp              Entry point and signal handler
src/menu.cpp              Interactive menu and orchestration
src/helperfuncs.cpp       Discovery, validation, and system helpers
src/database.cpp          SQLite attack history
src/sniffer.cpp           libpcap live capture and pcap writer
src/protocols/arp.cpp     ARP spoofing and blackhole modes
src/protocols/dhcp.cpp    DHCP starvation and release modes
src/protocols/dns.cpp     DNS response spoofing
src/protocols/icmp.cpp    ICMP Echo traffic generation
src/protocols/nat.cpp     Gateway NAT table pressure simulation
src/protocols/syn.cpp     TCP SYN traffic generation
src/headers/              Public headers for the above components
docs/ai/                  AI-oriented project context and roadmap
misc/                     Optional local image assets
sniffs/                   Runtime pcap output directory
```

## Future Work

See `docs/ai/PROJECT_CONTEXT.md`, `docs/ai/ARCHITECTURE.md`, `docs/ai/MODULE_REGISTRY.md`, `docs/ai/ROADMAP.md`, and `docs/ai/CODEX_NEXT_PROMPTS.md` for a deeper technical map and planned improvement path.
