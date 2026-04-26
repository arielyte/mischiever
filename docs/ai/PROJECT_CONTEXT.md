# Mischiever Project Context

## Project Summary

Mischiever is a Linux-only C++14 command-line networking tool for authorized LAN lab testing, packet capture, and educational attack simulation. The actual code is a menu-driven application built around a shared `Session` object, an `AttackModule` base interface, several raw-socket protocol modules, a `libpcap` sniffer, and a small SQLite attack-history database. The repository is compact and readable, but the current implementation is more of a working prototype than the polished "platform" described by the README: module boundaries exist, yet lifecycle, configuration, safety guardrails, testability, and system-state restoration are still fragile.

## Build And Runtime Assumptions

- Build command: `make`.
- Compiler settings from `Makefile`: `g++ -Wall -std=c++14 -pthread -I src`.
- Link libraries: `-lpcap -lsqlite3`.
- Expected OS: Linux. The code depends on Linux raw sockets, `/proc/net/arp`, `/proc/net/route`, `/proc/sys/net/ipv4/*`, `iptables`, `sysctl`, and optionally `nmcli`.
- Runtime privileges: root or equivalent capabilities are required for raw sockets, packet capture, and network stack changes.
- Runtime working directory matters. The SQLite file is opened as `mischiever_history.db`, sniffer output is written under `sniffs/`, and easter egg images are loaded from `misc/`.
- A syntax-only compile with the Makefile flags succeeded during this documentation pass. A full build was not run because this pass was requested as documentation-only.
- `make clean` is destructive for local runtime artifacts: it removes the binary, `mischiever_history.db`, and uses `sudo rm -rf sniffs`.

## External Dependencies

- C++ standard library with C++14 support.
- POSIX/Linux networking headers and APIs.
- `libpcap` development package.
- `sqlite3` development package.
- Shell commands used at runtime: `ping`, `nmcli`, `iptables`, `sysctl`, `mkdir`, `xdg-open`, and optionally `imv`.
- Kernel interfaces/files: `/proc/net/arp`, `/proc/net/route`, `/proc/sys/net/ipv4/ip_forward`.
- Environment variables used by sniffer ownership fix: `SUDO_UID`, `SUDO_GID`.

## Entry Point Flow From `main.cpp`

1. `main()` registers `handle_signal()` for `SIGINT`.
2. It constructs a stack-owned `Menu menu`.
3. It stores `&menu` in global `g_menu` so the signal handler can call `Menu::stop_all_attacks()`.
4. It calls `menu.run()`.
5. On Ctrl-C, `handle_signal()` prints a cleanup message, stops all attack modules, sleeps for one second, and exits.

Important caveat: signal handling calls C++ iostreams and application methods from inside the signal handler. That is not async-signal-safe. It is useful for a prototype, but fragile for a production-quality cleanup path.

## Menu And Control Flow

The `Menu` object owns the global `Session`, a vector of attack modules, and one `Sniffer`.

Startup flow inside `Menu::run()`:

1. Print ASCII logo.
2. Create all attack module instances:
   - `SYN(SYN::FLOOD)`
   - `ICMP(ICMP::FLOOD)`
   - `ARP(ARP::SPOOFING)`
   - `ARP(ARP::BLACKHOLE)`
   - `DHCP(DHCP::STARVATION)`
   - `DHCP(DHCP::RELEASE)`
   - `DNS(DNS::SPOOFING)`
   - `NAT(NAT::EXHAUSTION)`
3. Auto-detect the first active non-loopback IPv4 interface using `HelperFunctions::get_iface()`.
4. Enter a blocking text menu loop.

Main menu choices:

- `1` Attack Modules.
- `2` Traffic Sniffer.
- `3` Target Configuration.
- `4` Attack History.
- `5` Exit.
- `42` and `777` open local cat images through `HelperFunctions::displayImage()`.

Attack menu choices:

- Floods: SYN Flood, ICMP Ping Flood, NAT Exhaustion.
- MITM: ARP Spoofing toggle.
- DoS: DHCP Lease Breaker, DHCP Starvation toggle, ARP Blackhole, DNS Spoofing.

Module selection is string-based. The menu loops through `attack_modules` and compares `get_name()` results such as `"SYN Flood"` and `"ARP Spoof"`. This works, but it makes display labels part of internal control flow.

`Menu::run_selected_attack()` logs an attack, calls `attack->run(&session)`, waits for Enter, then calls `attack->stop()`. ARP spoofing and DHCP starvation are special-cased as background toggles and do not use this exact flow.

## Target Configuration Flow

`Menu::set_target_config()` interactively fills `Session` fields:

- `interface`
- `target_ip`
- `target_mac`
- `gateway_ip`
- `gateway_mac`
- `dhcp_server_ip`
- `dns_server_ip`

The wizard supports:

- Empty input to keep a current value.
- `q` to quit.
- `find` to scan local hosts, detect default gateway, resolve MACs through ARP cache, read DNS server from `/etc/resolv.conf`, or query DHCP server via `nmcli`.

The scanner assumes an IPv4 `/24` derived from the local interface IP. It runs a shell ping sweep and then reads `/proc/net/arp`.

## Sniffer Flow

`Sniffer::start(Session*)`:

1. Returns immediately if already running.
2. Creates `sniffs/` via `system("mkdir -p sniffs")`.
3. Builds a timestamped `.pcap` path.
4. Sets `running = true`.
5. Starts `capture_loop()` on a background thread.

`Sniffer::capture_loop()`:

1. Opens the configured interface with `pcap_open_live(interface, 65536, promiscuous=1, timeout=1000ms)`.
2. Opens a pcap dumper for the timestamped file.
3. If running under sudo, attempts to chown the pcap to `SUDO_UID:SUDO_GID`.
4. Loops with `pcap_next_ex()` while `running`.
5. Dumps every captured packet to file.
6. Prints only IPv4 packets in a small table.
7. Labels TCP, UDP, ICMP, or OTHER.
8. Highlights packets involving `session.target_ip`.
9. Closes the dumper and pcap handle after stop.

Known mismatch: `Sniffer::process_packet()` is declared in the header but not implemented or used.

## Attack Module Flow

All attack modules inherit from `AttackModule`:

```cpp
virtual void run(Session* session) = 0;
virtual void stop() = 0;
virtual std::string get_name() = 0;
```

The common pattern is:

1. Validate required `Session` fields.
2. Set an atomic stop/running flag.
3. Start one or more background threads.
4. Threads use raw sockets and loop until the flag changes.
5. `stop()` flips the flag and joins threads.

Important exceptions and issues:

- `SYN` and `ICMP` use one thread each and run unthrottled.
- `ARP`, `DHCP`, `DNS`, and `NAT` manage vectors of threads.
- DNS and ARP also modify host firewall/kernel network state.
- Some module state is not represented in `Session`, so the UI can become stale if a module exits early.
- There is no shared status/error model. A module can print an error and return, while the menu may still believe the action started.

## Database And Session Flow

`Session` is the shared mutable state container. It stores:

- Interface and local/target/gateway addressing fields.
- DHCP and DNS server fields.
- DNS spoofing config.
- UI-visible booleans for ARP spoofing and DHCP starvation.
- `std::unique_ptr<Database> db`.
- `std::unique_ptr<HelperFunctions> helper`.

`Database` opens `mischiever_history.db` in its constructor and creates an `ATTACKS` table if missing. `Menu` logs attacks through `session.db->log_attack(type, attacker_ip, victim_ip)`. History is printed with `sqlite3_exec()` and a callback.

Database limits:

- Only attack type/date/time/attacker/victim are stored.
- No session table exists despite README language about "session persistence".
- No structured module options, duration, result, error, interface, gateway, MACs, or pcap path are stored.
- `DATE('now')` and `TIME('now')` use SQLite UTC behavior, not local timezone display.

## Protocol Module Summaries

### ARP

Files: `src/headers/arp.h`, `src/protocols/arp.cpp`.

Modes:

- `SPOOFING`: sends forged ARP replies to both target and gateway, enables IP forwarding, disables ICMP redirects.
- `BLACKHOLE`: sends the same two-way poisoning pattern, sets `iptables -P FORWARD DROP`, and disables IP forwarding.

Inputs:

- `session.interface`
- `session.target_ip`
- `session.target_mac`
- `session.gateway_ip`
- `session.gateway_mac`

Behavior:

- Opens `AF_PACKET` raw ARP sockets.
- Builds Ethernet + ARP reply packets manually.
- Sends every two seconds from two threads.
- `stop()` joins threads and attempts to restore forwarding-related settings.

Fragile areas:

- Changes global iptables default FORWARD policy instead of adding/removing scoped rules.
- Does not restore ARP caches.
- Cleanup only partially restores system state.
- `session.arp_spoof_active` is maintained by `Menu`, not by the module.

### DHCP

Files: `src/headers/dhcp.h`, `src/protocols/dhcp.cpp`.

Modes:

- `STARVATION`: sends repeated DHCP Discover packets with randomized locally administered MAC addresses.
- `RELEASE`: sends repeated DHCP Release packets using the configured target IP/MAC toward the configured DHCP server.

Inputs:

- Starvation: `session.interface`.
- Release: `session.interface`, `session.target_ip`, `session.target_mac`, `session.dhcp_server_ip`, and usually `session.gateway_mac`.

Behavior:

- Uses `AF_PACKET` raw sockets.
- Crafts Ethernet, IPv4, UDP, BOOTP/DHCP headers, and DHCP options.
- Pads DHCP payload to at least 300 bytes.
- Starvation sleeps 10ms between discovers.
- Release sleeps 1 second between release packets.

Fragile areas:

- Packet checksums are partial: IPv4 checksum is set; UDP checksum is zero.
- `rand()` is used across the project without strong ownership or thread-local strategy.
- MAC parsing with `sscanf()` is unchecked in release mode.
- Header comment says release is "Coming soon", but implementation exists.

### DNS

Files: `src/headers/dns.h`, `src/protocols/dns.cpp`.

Mode:

- `SPOOFING`.

Inputs:

- `session.interface`
- `session.dns_target_domain`
- `session.dns_spoofed_ip`
- ARP spoofing must already be active according to the menu.

Behavior:

- Inserts an iptables rule to drop forwarded UDP destination port 53 traffic.
- Opens an `AF_PACKET` raw socket and reads packets.
- Filters IPv4 UDP packets whose destination port is 53.
- Parses the DNS query name.
- If the requested name contains the configured target domain as a substring, mutates the captured query buffer into a forged response and sends it back.
- Removes the DNS drop rule in `stop()`.

Fragile areas:

- Substring matching can match unintended domains.
- DNS parser handles only simple uncompressed query names.
- No BPF/libpcap filter; the raw socket receives a lot of unrelated traffic.
- UDP checksum helper exists but forged responses set UDP checksum to zero.
- Firewall cleanup assumes the exact inserted rule is still present and only one copy exists.

### ICMP

Files: `src/headers/icmp.h`, `src/protocols/icmp.cpp`.

Mode:

- `FLOOD`.

Inputs:

- `session.target_ip`.

Behavior:

- Opens an IPv4 raw socket for ICMP.
- Builds ICMP Echo Request packets with 64 bytes of `A` payload.
- Recomputes ICMP checksum each loop.
- Sends continuously until stopped.

Fragile areas:

- No rate limit.
- No packet count configuration exposed despite `packet_count` field.
- Minimal error handling and no statistics.

### NAT

Files: `src/headers/nat.h`, `src/protocols/nat.cpp`.

Mode:

- `EXHAUSTION`.

Inputs:

- `session.interface`
- `session.gateway_ip`
- Resolved gateway MAC from `HelperFunctions::get_mac_from_ip()`.
- Local interface IP from `HelperFunctions::get_local_ip()`.

Behavior:

- Uses four threads.
- Each thread opens an `AF_PACKET` raw socket.
- Builds Ethernet + IPv4 + UDP packets.
- Randomizes source MAC, spoofed local source IP within the local `/24`, destination public-looking IP, source port, and destination port.
- Sends continuously to the gateway MAC until stopped.

Fragile areas:

- Extremely high abuse and lab-disruption risk.
- No rate limit, duration, confirmation, or lab-scope guardrail.
- `generate_random_local_ip()` and `generate_random_public_ip()` are currently unused.
- In `Menu`, NAT is launched by temporarily overwriting `session.target_ip` with `session.gateway_ip` for logging/control flow.

### SYN

Files: `src/headers/syn.h`, `src/protocols/syn.cpp`.

Mode:

- `FLOOD`.

Inputs:

- `session.target_ip`.

Behavior:

- Opens an IPv4 raw TCP socket.
- Enables `IP_HDRINCL`.
- Crafts IP and TCP headers.
- Sends SYN packets to hardcoded target port `80`.
- Spoofs source IPs in the hardcoded `192.168.1.x` range.

Fragile areas:

- TCP checksum is not computed.
- IP checksum is not reset to zero before recalculation each loop.
- Source spoof range ignores the actual local subnet.
- Target port and packet count are private hardcoded values with no UI.
- No rate limit.

## Important Structs, Classes, And Functions

- `AttackModule`: common polymorphic interface for executable modules.
- `Session`: shared mutable state and service container.
- `Menu`: application orchestrator, UI, module registry, and control flow.
- `Sniffer`: background `libpcap` capture and pcap writer.
- `Database`: SQLite history writer/reader.
- `HelperFunctions`: interface detection, IP/MAC validation, local discovery, system network toggles, and image display.
- `ARP::spoof_loop()`: repeated forged ARP reply sender.
- `DHCP::send_dhcp_discover()`: DHCP Discover packet builder.
- `DHCP::send_dhcp_release()`: DHCP Release packet builder.
- `DNS::spoof_loop()` / `DNS::forge_response()`: DNS query watcher and forged response writer.
- `SYN::syn_flood_loop()`: raw TCP SYN packet sender.
- `ICMP::flood_loop()`: raw ICMP Echo sender.
- `NAT::exhaust_loop()`: raw Ethernet/IP/UDP sender for gateway NAT pressure.
- `Menu::run_selected_attack()`: generic foreground attack runner and logger.

## Module Dependencies

- `main.cpp` depends on `Menu`.
- `Menu` depends on `Session`, `Sniffer`, and every attack module header.
- Every attack module depends on `AttackModule`, which depends on `Session`.
- `Session` depends on `Database` and `HelperFunctions`.
- `Sniffer` depends on `Session` and `libpcap`.
- `ARP` and `DNS` depend on `HelperFunctions` for system network toggles.
- `NAT` creates a local `HelperFunctions` instance and also uses `session.helper`.
- `Database` depends on SQLite.
- Most protocol modules depend directly on Linux networking headers.

## Current Architectural Problems

- `Menu` is doing too much: UI rendering, configuration, module lookup, lifecycle, validation, logging, and special-case orchestration.
- Module lookup by display string is brittle.
- `Session` is a bag of mutable strings and booleans rather than a validated configuration model.
- Module status is split between module-local atomics and menu-maintained booleans.
- No common result/error type exists for `run()` or `stop()`.
- Long-running modules print directly to stdout/stderr, making structured logging and tests difficult.
- System mutations are not represented as scoped resources, so cleanup is best-effort.
- Packet builders are tightly coupled to send loops and sockets, making them hard to unit test.
- Safety policy is prose-only. There are no runtime guardrails for lab-only use.
- There is no test harness or simulated/dry-run mode.

## Current Code Quality Problems

- Several modules use raw `system()` or `popen()` calls with string-concatenated arguments.
- `rand()`/`srand()` are used globally and inconsistently, including in threaded paths.
- Headers include many implementation-heavy system headers, increasing coupling and build cost.
- Some functions are declared but unused or undefined, such as `Sniffer::process_packet()`.
- Some fields are unused or not externally configurable, such as `packet_count`, `target_port`, `Session::my_ip`, and `Session::my_mac`.
- Multiple checksum helpers exist with overlapping names and inconsistent behavior.
- Namespace pollution from free helper functions in protocol `.cpp` files could create future link conflicts.
- No RAII wrappers exist for sockets, pcap handles, iptables rules, or sysctl changes.
- Input validation is partial: IP/MAC regex exists, but interface names and shell command arguments are not consistently protected.
- README claims exceed verified code behavior.

## Safety, Legal, And Abuse-Risk Boundaries

- Intended scope should remain authorized lab networks, owned LANs, and educational packet analysis.
- The code includes disruptive functionality: ARP poisoning, DHCP starvation/release, DNS spoofing, ICMP flood, SYN flood, and NAT-table pressure.
- The current README uses terms like "C2", "kill chain", "stealth", and "bypass standard security filters". Those terms are risky, overstate the implementation, and conflict with a safety-forward educational positioning.
- Future work should add explicit lab-mode guardrails before expanding offensive capability:
  - Require confirmation of authorization.
  - Show configured interface, target, gateway, and local subnet before starting disruptive modules.
  - Prefer default packet-rate and duration limits.
  - Reject public-routable targets by default for flood modules.
  - Provide dry-run/packet-preview modes.
  - Log all runs with enough context for accountability.
- Do not add stealth, persistence, evasion, credential theft, botnet behavior, public-target automation, exploit delivery, or malware-like functionality.

## What Should Never Be Changed Casually

- Packet struct packing, field order, and network byte order conversions.
- Stop/join logic for background threads.
- Any code that changes `ip_forward`, `send_redirects`, or `iptables`.
- The SQLite schema if existing user history should remain readable.
- The meaning of `AttackModule::run()`, `stop()`, and `get_name()` without updating every module and the menu.
- The working-directory assumptions for `sniffs/`, `misc/`, and `mischiever_history.db`.
- The legal/safety positioning toward authorized local lab use only.

## Unfinished Or Fragile Areas

- README is aspirational and overclaims relative to the implementation.
- Makefile lacks dependency generation, debug/release modes, install targets, sanitizer targets, test targets, and safe clean behavior.
- `.gitignore` does not ignore the produced `mischiever` binary, `mischiever_history.db`, or generated `sniffs/*.pcap`.
- `.vscode/launch.json` is effectively empty.
- `Session::my_ip` and `Session::my_mac` are not populated.
- Sniffer has no filter selection, capture limit, load mode, or packet decoder beyond IPv4 protocol labels.
- DNS spoofing assumes simple A-query flows and minimal parsing.
- SYN/TCP packet construction is incomplete because TCP checksum is not built.
- ARP/DNS firewall/kernel changes need safer scoped rollback.
- NAT and flood modules need hard guardrails before feature expansion.
