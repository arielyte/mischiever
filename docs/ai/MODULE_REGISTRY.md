# Mischiever Module Registry

This registry summarizes every tracked source/build/config file that matters to future engineering work.

## `README.md`

- Purpose: User-facing project description, capabilities list, disclaimer, and install instructions.
- Public interface: Documentation only.
- Important content: Claims session state, polymorphic attack modules, dashboard, scanner, ARP/DNS/DHCP/flood/NAT/sniffer features.
- Inputs: None.
- Outputs: None.
- Side effects: Sets user expectations.
- Dependencies: Mentions Linux, root, `libpcap`, SQLite, raw sockets, `iptables`.
- Known issues: Overclaims maturity; uses risky language such as "C2", "kill chain", "stealth", and "bypass"; describes a broader framework than the code currently supports.
- Suggested improvements: Reframe as authorized lab tool, document exact current behavior, add safety guardrails, add build/test/dev notes.

## `Makefile`

- Purpose: Build and clean the application.
- Public interface: `make`, `make clean`.
- Important functions/classes: Not applicable.
- Inputs: Source list in `SRCS`.
- Outputs: `mischiever` binary; temporary `.o` files that are deleted after link.
- Side effects: `clean` removes `mischiever_history.db` and uses `sudo rm -rf sniffs`.
- Dependencies: `g++`, pthread, `libpcap`, SQLite.
- Known issues: No dependency generation, no debug/release modes, no sanitizer/test targets, deletes objects after every build, risky clean target, produced binary is not ignored by `.gitignore`.
- Suggested improvements: Add `build/` output directory, `.d` deps, `debug`, `release`, `sanitize`, `test`, and safer artifact cleanup.

## `.gitignore`

- Purpose: Ignore generic compiled artifacts.
- Public interface: Git ignore patterns.
- Important functions/classes: Not applicable.
- Inputs: Git path matching.
- Outputs: None.
- Side effects: Prevents some build artifacts from appearing as untracked.
- Dependencies: Git.
- Known issues: Does not ignore `mischiever`, `mischiever_history.db`, or generated `sniffs/*.pcap`.
- Suggested improvements: Add project-specific runtime artifacts.

## `.vscode/launch.json`

- Purpose: VS Code launch config placeholder.
- Public interface: Empty `configurations` array.
- Important functions/classes: Not applicable.
- Inputs: VS Code.
- Outputs: None.
- Side effects: None.
- Dependencies: VS Code.
- Known issues: No usable debugger config.
- Suggested improvements: Add optional root/debug launch instructions only if the repo wants editor configs tracked.

## `.vscode/settings.json`

- Purpose: VS Code C++ file associations.
- Public interface: Editor settings.
- Important functions/classes: Not applicable.
- Inputs: VS Code file association engine.
- Outputs: None.
- Side effects: Changes editor language mode.
- Dependencies: VS Code.
- Known issues: Large generic association list; not critical to project behavior.
- Suggested improvements: Consider removing from repo or replacing with focused workspace settings.

## `src/main.cpp`

- Purpose: Process entry point and Ctrl-C cleanup hook.
- Public interface: `main()`.
- Important functions/classes: `handle_signal(int)`, global `Menu* g_menu`.
- Inputs: SIGINT, process start.
- Outputs: Console messages.
- Side effects: Calls `Menu::stop_all_attacks()` and `exit(0)` from signal handler.
- Dependencies: `Menu`, iostream, signals, `sleep`.
- Known issues: Signal handler is not async-signal-safe and only stops attacks, not sniffer.
- Suggested improvements: Use atomic shutdown flag or `sigwait` pattern; let main loop perform cleanup.

## `src/headers/session.h`

- Purpose: Shared state and service container.
- Public interface: `struct Session` fields.
- Important functions/classes: `Session::Session()`.
- Inputs: None directly; mutated by `Menu` and helpers.
- Outputs: Shared config and services.
- Side effects: Constructs `Database`, which opens/creates SQLite DB.
- Dependencies: `Database`, `HelperFunctions`.
- Known issues: Mutable bag of strings; no validation invariants; `my_ip`/`my_mac` unused; state booleans can diverge from module reality.
- Suggested improvements: Split validated config, runtime status, and services; add typed addresses and module status model.

## `src/headers/attack_module.h`

- Purpose: Common interface for attack modules.
- Public interface: `run(Session*)`, `stop()`, `get_name()`.
- Important functions/classes: `class AttackModule`.
- Inputs: `Session*`.
- Outputs: Console/module side effects; no typed result.
- Side effects: Defined by implementations.
- Dependencies: `Session`.
- Known issues: `run()` cannot report failure except by printing; `get_name()` doubles as UI label and lookup key.
- Suggested improvements: Add stable module IDs, metadata, requirements, and typed start/stop results.

## `src/headers/menu.h` / `src/menu.cpp`

- Purpose: Text UI, application orchestration, module inventory, config wizard, attack history view.
- Public interface: `Menu::run()`, `Menu::stop_all_attacks()`.
- Important functions/classes: `Menu`, `run_selected_attack()`, `set_target_config()`, `show_*_menu()` methods.
- Inputs: `std::cin`, helper-discovered network info.
- Outputs: Console UI, database logs, module start/stop calls.
- Side effects: Owns modules, starts sniffer, mutates `Session`, opens images, logs attacks.
- Dependencies: All module headers, `Sniffer`, `Session`, `HelperFunctions`.
- Known issues: Large god object; string-based module lookup; NAT target-IP hack; mixed UI/validation/business logic; blocking input makes graceful shutdown difficult.
- Suggested improvements: Extract module registry, config service, UI renderer, and lifecycle manager.

## `src/headers/helperfuncs.h` / `src/helperfuncs.cpp`

- Purpose: Utility functions for screen control, image display, interface/IP/MAC discovery, validation, local scan, and privileged network toggles.
- Public interface: `clearScreen()`, `displayImage()`, `get_iface()`, `get_local_ip()`, `get_mac_from_ip()`, `is_valid_ip()`, `is_valid_mac()`, `scan_local_network()`, `get_default_gateway_ip()`, `get_dns_server_ip()`, `get_dhcp_server_ip()`, `toggle_ip_forwarding()`, `toggle_send_redirects()`, `toggle_dns_drop_rule()`.
- Important functions/classes: `class HelperFunctions`.
- Inputs: Interface names, IP strings, system files, shell command outputs.
- Outputs: Strings, console scan table.
- Side effects: Executes shell commands; changes kernel forwarding, redirects, and firewall rules.
- Dependencies: Linux networking APIs, `/proc`, `/etc/resolv.conf`, `ping`, `nmcli`, `iptables`, `sysctl`, `xdg-open`/`imv`.
- Known issues: Shell command construction; no interface-name validation; broad helper responsibilities; unscoped system changes.
- Suggested improvements: Split pure validation, discovery, command execution, and system-state management; add RAII rollback guards.

## `src/headers/database.h` / `src/database.cpp`

- Purpose: SQLite-backed attack history.
- Public interface: `Database()`, `~Database()`, `log_attack()`, `print_history()`.
- Important functions/classes: `class Database`, SQLite callback.
- Inputs: Attack type, attacker IP text, victim IP text.
- Outputs: Rows in `mischiever_history.db`, console history output.
- Side effects: Creates/opens database in current working directory.
- Dependencies: SQLite C API.
- Known issues: No error state exposed to caller; minimal schema; UTC SQLite date/time; print formatting tied to console colors.
- Suggested improvements: Add schema versioning, structured run records, query API, and export support.

## `src/headers/sniffer.h` / `src/sniffer.cpp`

- Purpose: Live packet capture and pcap dumping.
- Public interface: `start(Session*)`, `stop()`.
- Important functions/classes: `Sniffer`, `capture_loop()`, `get_current_datetime()`.
- Inputs: `session.interface`, `session.target_ip`.
- Outputs: `.pcap` files in `sniffs/`, console packet rows.
- Side effects: Creates `sniffs/`, opens promiscuous capture, optionally chowns output file.
- Dependencies: `libpcap`, Linux Ethernet/IP headers, `Session`.
- Known issues: Declares unused `process_packet()`; no BPF filters; only shallow IPv4 decoding; no load/read mode; no explicit sniffer stop on SIGINT.
- Suggested improvements: Add filter config, packet decoder abstraction, pcap load mode, capture limits, and structured capture metadata.

## `src/headers/arp.h` / `src/protocols/arp.cpp`

- Purpose: ARP spoofing and blackhole modes.
- Public interface: `ARP(Mode)`, `run()`, `stop()`, `get_name()`.
- Important functions/classes: `ARP::spoof_loop()`, `parse_mac()`, `get_my_mac()`, packed `arp_header`.
- Inputs: Interface, target IP/MAC, gateway IP/MAC.
- Outputs: Raw ARP replies.
- Side effects: Changes IP forwarding, send redirects, and FORWARD policy depending on mode.
- Dependencies: `AttackModule`, `HelperFunctions`, Linux raw packet sockets.
- Known issues: Global firewall policy changes; partial cleanup; no ARP cache restoration; no rate config.
- Suggested improvements: Scoped firewall/sysctl guard, module requirements metadata, safer rollback, and status reporting.

## `src/headers/dhcp.h` / `src/protocols/dhcp.cpp`

- Purpose: DHCP starvation and targeted DHCP release simulation.
- Public interface: `DHCP(Mode)`, `run()`, `stop()`, `get_name()`, `start_starvation_background()`, `stop_starvation()`.
- Important functions/classes: `dhcp_header`, `starvation_loop()`, `send_dhcp_discover()`, `release_loop()`, `send_dhcp_release()`.
- Inputs: Interface; for release, target IP/MAC and DHCP server IP.
- Outputs: Raw DHCP Discover or Release packets.
- Side effects: Consumes DHCP server attention/leases in lab; sends spoofed packets.
- Dependencies: Linux raw packet sockets, IP/UDP/Ethernet headers.
- Known issues: Unchecked MAC parsing; comments stale; UDP checksum disabled; global `rand()`.
- Suggested improvements: Packet-builder tests, explicit lease simulation guardrails, rate/duration controls.

## `src/headers/dns.h` / `src/protocols/dns.cpp`

- Purpose: DNS spoofing while ARP spoofing is active.
- Public interface: `DNS(Mode)`, `run()`, `stop()`, `get_name()`, `set_target_domain()`.
- Important functions/classes: `spoof_loop()`, `is_dns_query()`, `parse_dns_name()`, `forge_response()`, packed DNS structs.
- Inputs: Interface, target domain, spoofed IP.
- Outputs: Forged DNS responses.
- Side effects: Inserts/removes iptables DNS drop rule.
- Dependencies: `AttackModule`, `HelperFunctions`, raw packet sockets.
- Known issues: Simple parser only; substring domain match; no BPF filter; UDP checksum disabled; rule cleanup can be inaccurate.
- Suggested improvements: Exact domain matching, robust DNS parser, scoped firewall rule object, pcap-driven tests.

## `src/headers/icmp.h` / `src/protocols/icmp.cpp`

- Purpose: ICMP Echo flood simulation.
- Public interface: `ICMP(Mode)`, `run()`, `stop()`, `get_name()`.
- Important functions/classes: `flood_loop()`, `checksum()`.
- Inputs: Target IP.
- Outputs: ICMP Echo Request packets.
- Side effects: Generates high packet volume.
- Dependencies: raw ICMP sockets.
- Known issues: No rate/duration/packet count UI; no stats; unthrottled loop.
- Suggested improvements: Add bounded lab defaults, target validation, and metrics.

## `src/headers/syn.h` / `src/protocols/syn.cpp`

- Purpose: TCP SYN flood simulation.
- Public interface: `SYN(Mode)`, `run()`, `stop()`, `get_name()`.
- Important functions/classes: `syn_flood_loop()`, `checksum()`, unused `PseudoHeader`.
- Inputs: Target IP.
- Outputs: Raw TCP SYN packets to port 80.
- Side effects: Generates high packet volume.
- Dependencies: raw TCP sockets with `IP_HDRINCL`.
- Known issues: TCP checksum not calculated; source IP spoof range hardcoded; target port not configurable; no rate limit.
- Suggested improvements: Correct packet construction, expose safe config, add dry-run packet rendering, add tests.

## `src/headers/nat.h` / `src/protocols/nat.cpp`

- Purpose: Gateway NAT/PAT table pressure simulation via randomized UDP packets.
- Public interface: `NAT(AttackMode)`, `run()`, `stop()`, `get_name()`.
- Important functions/classes: `exhaust_loop()`, `parse_mac_address()`, `checksum()`.
- Inputs: Interface, gateway IP, gateway MAC, local IP.
- Outputs: Raw Ethernet/IP/UDP frames.
- Side effects: High-rate traffic toward gateway.
- Dependencies: raw packet sockets, helper discovery.
- Known issues: No guardrails; no rate limits; unused random-IP helper methods; temporary target-IP overwrite in menu for launch/logging.
- Suggested improvements: Add explicit lab confirmation, scope checks, rate/duration controls, and remove menu hack through module metadata.

## `misc/cat.jpg` / `misc/cat2.png`

- Purpose: Easter egg images opened by menu choices `42` and `777`.
- Public interface: Runtime paths used by `displayImage()`.
- Important functions/classes: Not applicable.
- Inputs: Menu choice.
- Outputs: External image viewer.
- Side effects: Spawns `imv` or `xdg-open`.
- Dependencies: Local files and installed viewer.
- Known issues: GUI behavior from a CLI/network tool is surprising; `displayImage()` builds shell commands from path strings.
- Suggested improvements: Keep as optional easter egg or remove from core CLI.
