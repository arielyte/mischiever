# Codex Next Prompts

These prompts are designed for future vertical and horizontal improvement sessions. Paste one prompt at a time so Codex can stay focused and avoid rewriting the project all at once.

## 1. Improve README Accuracy And Safety Positioning

Read `docs/ai/PROJECT_CONTEXT.md` and the current `README.md`. Rewrite the README so it accurately describes the current code, keeps the authorized LAN lab scope, removes overclaims and risky "C2/stealth/kill chain/bypass" language, and adds clear build/runtime/safety notes. Do not change source code.

## 2. Improve Makefile And Gitignore Hygiene

Read `docs/ai/PROJECT_CONTEXT.md` and `docs/ai/ROADMAP.md`. Update the Makefile to use a build directory, keep object files there, add dependency generation, add debug/release/sanitize targets, and make clean safer. Update `.gitignore` for `mischiever`, database files, build output, and generated pcap captures. Do not alter application behavior.

## 3. Add Lab-Mode Guardrails

Add a conservative lab-mode confirmation layer before disruptive modules start. It should show interface, target IP/MAC, gateway IP/MAC, module name, and expected side effects, then require explicit confirmation. Reject public-routable flood targets by default unless a clearly named override is enabled. Keep behavior otherwise unchanged.

## 4. Refactor Attack Modules Behind Stable Metadata

Refactor `AttackModule` so each module exposes a stable ID, display name, category, required session fields, and risk level. Update `Menu` to select modules by ID/metadata instead of string-matching `get_name()`. Keep the existing user-visible menu behavior as close as possible.

## 5. Add Module-Level Error Handling

Replace `void run(Session*)` with a minimally invasive result/status model, or add a new compatible start method if changing the interface all at once is too risky. Modules should report missing config, socket errors, and system command failures back to the menu instead of only printing to stderr.

## 6. Stabilize Firewall And Sysctl Cleanup

Audit ARP and DNS side effects. Replace broad `iptables -P FORWARD DROP/ACCEPT` and untracked sysctl toggles with scoped, reversible guard objects that record previous state and restore it reliably. Add clear warnings and avoid changing unrelated host firewall policy.

## 7. Add Unit Tests For Helper Functions

Introduce a lightweight C++ test target and add unit tests for IP validation, MAC validation, gateway route parsing, DNS server parsing, and DHCP server parsing. Refactor helper parsing into pure functions where needed so tests do not depend on the real host files.

## 8. Extract Packet Builders For Testability

Refactor one module at a time, starting with ICMP or SYN, so packet construction is separate from socket send loops. Add golden-byte or field-level tests for generated headers and checksums. Keep runtime behavior unchanged except for obvious packet correctness fixes covered by tests.

## 9. Add Pcap Save/Load Analysis Mode

Extend the sniffer into a safer analysis tool: keep live capture, but add a mode to load an existing `.pcap` file, summarize protocols, endpoints, packet counts, and target-related traffic. Prefer `libpcap` offline APIs and update the menu without changing attack modules.

## 10. Add Structured Logging And Better History

Improve `Database` and logging so each run records module ID, display name, interface, target, gateway, start/end time, duration, result, error text, and pcap path if relevant. Add schema versioning or migration so existing `ATTACKS` rows do not break.

## 11. Remove Menu God Object Responsibilities

Refactor `Menu` gradually. Extract a module registry, a target configuration service, and a lifecycle runner. Keep the same CLI menu text for now, but reduce `menu.cpp` size and remove special-case hacks such as temporarily overwriting `session.target_ip` for NAT.

## 12. Add Safer Defaults To Flood Modules

Add configurable packet rate, duration, and packet count limits to SYN, ICMP, DHCP starvation, and NAT modules. Default to bounded lab-safe values. Show a clear summary before launch and record the selected limits in attack history.
