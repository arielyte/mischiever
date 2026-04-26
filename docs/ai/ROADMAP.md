# Mischiever Improvement Roadmap

This roadmap is ordered for a documentation-first, safety-forward C++ networking lab tool. Priorities are relative: P0 means urgent foundation, P1 means high-value next work, P2 means useful but not blocking, P3 means later polish.

## Phase 0: Build Hygiene And Documentation

| Item | Priority | Impact | Risk | Difficulty | Files likely affected | Why it matters |
|---|---:|---:|---:|---:|---|---|
| Align README with actual behavior and authorized lab scope | P0 | High | Low | Low | `README.md` | Current README overclaims maturity and uses risky language. |
| Add project-specific `.gitignore` entries | P0 | Medium | Low | Low | `.gitignore` | Prevents committing binary, DB, and pcap artifacts. |
| Improve Makefile hygiene | P0 | High | Medium | Medium | `Makefile` | Safer builds and clean targets reduce accidental data loss. |
| Add docs index for `docs/ai` | P1 | Medium | Low | Low | `docs/ai/*`, maybe `README.md` | Makes AI handoff docs discoverable. |
| Document required Linux capabilities and runtime side effects | P0 | High | Low | Low | `README.md`, `docs/` | Users need to understand root, raw sockets, firewall/sysctl changes. |

## Phase 1: Stabilize Current Features

| Item | Priority | Impact | Risk | Difficulty | Files likely affected | Why it matters |
|---|---:|---:|---:|---:|---|---|
| Add lab-mode confirmation before disruptive modules | P0 | High | Low | Medium | `menu.cpp`, `session.h` | Reduces accidental misuse and reinforces authorized-scope intent. |
| Add rate and duration limits to flood modules | P0 | High | Medium | Medium | `syn.*`, `icmp.*`, `nat.*`, `dhcp.*`, `menu.cpp` | Prevents unbounded packet loops by default. |
| Fix SYN packet construction | P1 | High | Medium | Medium | `syn.cpp`, `syn.h` | TCP checksum and source selection are currently incomplete. |
| Scope and restore firewall/sysctl changes safely | P0 | High | High | Medium | `helperfuncs.*`, `arp.cpp`, `dns.cpp` | Global host state changes are the highest operational risk. |
| Improve sniffer lifecycle and errors | P1 | Medium | Low | Medium | `sniffer.*`, `main.cpp`, `menu.cpp` | Capture failures should not leave stale running state or orphaned behavior. |
| Replace broad `iptables -P FORWARD` policy changes | P0 | High | High | Medium | `arp.cpp`, `helperfuncs.*` | Changing default firewall policy is too blunt and can break the host. |
| Remove stale/unused declarations and comments | P2 | Medium | Low | Low | `sniffer.h`, `dhcp.h`, `syn.h`, `session.h` | Reduces confusion for future contributors and AI sessions. |

## Phase 2: Refactor Architecture

| Item | Priority | Impact | Risk | Difficulty | Files likely affected | Why it matters |
|---|---:|---:|---:|---:|---|---|
| Add stable module IDs and metadata | P0 | High | Medium | Medium | `attack_module.h`, all modules, `menu.cpp` | Avoids brittle lookup by display strings. |
| Split `Menu` into UI, config, registry, and lifecycle services | P1 | High | High | High | `menu.*`, new `src/*` files | Makes the project easier to extend horizontally. |
| Replace raw `Session` string bag with validated config types | P1 | High | Medium | High | `session.h`, `helperfuncs.*`, modules | Reduces repeated validation and bad states. |
| Add typed start/stop result model | P1 | High | Medium | Medium | `attack_module.h`, modules, `menu.cpp` | Lets modules report failures without relying on console prints. |
| Create packet builder classes/functions separate from send loops | P1 | High | Medium | High | protocol modules | Enables unit tests and safer packet correctness work. |
| Introduce RAII wrappers for sockets and pcap handles | P2 | Medium | Medium | Medium | modules, `sniffer.*` | Reduces leaks and simplifies cleanup paths. |

## Phase 3: Add Tests

| Item | Priority | Impact | Risk | Difficulty | Files likely affected | Why it matters |
|---|---:|---:|---:|---:|---|---|
| Add a C++ test framework | P0 | High | Low | Medium | `Makefile`, `tests/` | The project currently has no automated tests. |
| Unit-test IP/MAC validation and route parsing | P0 | Medium | Low | Low | `helperfuncs.*`, `tests/` | Low-risk first tests with high regression value. |
| Unit-test packet builders with golden bytes | P1 | High | Medium | High | `syn.*`, `icmp.*`, `dhcp.*`, `dns.*`, `arp.*` | Packet code is brittle and needs byte-level verification. |
| Add fake command/system adapters | P1 | High | Medium | Medium | `helperfuncs.*`, new abstractions | Enables testing without changing host firewall or sysctl. |
| Add pcap fixture tests for sniffer/DNS parsing | P2 | Medium | Low | Medium | `sniffer.*`, `dns.*`, `tests/fixtures` | Validates packet decoding without live traffic. |

## Phase 4: Add New Protocols And Features

| Item | Priority | Impact | Risk | Difficulty | Files likely affected | Why it matters |
|---|---:|---:|---:|---:|---|---|
| Add pcap save/load analysis mode | P1 | High | Low | Medium | `sniffer.*`, `menu.cpp`, new analysis files | Expands defensive/educational value without adding attack surface. |
| Add ARP table viewer and passive host discovery | P1 | Medium | Low | Medium | `helperfuncs.*`, `menu.cpp` | Useful horizontal feature that is safer than active attacks. |
| Add module dry-run packet preview | P1 | High | Low | High | all protocol modules | Lets users learn packet structure without sending traffic. |
| Add scoped DNS analysis tools before more spoofing features | P2 | Medium | Low | Medium | `dns.*`, sniffer analysis | Improves educational value safely. |
| Add new modules only after metadata/lifecycle refactor | P2 | High | Medium | Medium | `attack_module.h`, new modules | Avoids making `Menu` more tangled. |

## Phase 5: UX, CLI, Reporting Improvements

| Item | Priority | Impact | Risk | Difficulty | Files likely affected | Why it matters |
|---|---:|---:|---:|---:|---|---|
| Add non-interactive CLI flags | P1 | High | Medium | High | `main.cpp`, new CLI parser, `menu.cpp` | Enables repeatable lab runs and testing. |
| Add structured logging | P1 | High | Low | Medium | new logger, modules, `menu.cpp` | Makes behavior auditable and easier to debug. |
| Improve SQLite schema and add exports | P1 | Medium | Medium | Medium | `database.*`, `menu.cpp` | History should include module config, duration, result, and artifacts. |
| Add report generation for sniffer sessions | P2 | Medium | Low | Medium | `sniffer.*`, `database.*`, new report files | Turns packet capture into useful learning output. |
| Add clearer status dashboard | P2 | Medium | Low | Medium | `menu.cpp`, maybe new UI files | Current dashboard shows config but not robust module status. |
| Add safer error messages and recovery prompts | P2 | Medium | Low | Low | `menu.cpp`, modules | Helps users fix missing interface/MAC/root/dependency issues. |
