# Mischiever Architecture

This document diagrams the architecture verified from the current source code. The design is small and centered on `Menu` plus shared `Session`; the protocol modules are plugged in through `AttackModule`, but the menu still has substantial module-specific knowledge.

## High-Level Module Graph

```mermaid
flowchart TD
    Main["src/main.cpp<br/>main(), SIGINT handler"] --> Menu["Menu<br/>src/menu.cpp"]
    Menu --> Session["Session<br/>shared mutable state"]
    Menu --> Sniffer["Sniffer<br/>libpcap capture"]
    Menu --> AttackModule["AttackModule<br/>abstract interface"]

    AttackModule --> SYN["SYN<br/>raw TCP"]
    AttackModule --> ICMP["ICMP<br/>raw ICMP"]
    AttackModule --> ARP["ARP<br/>raw Ethernet/ARP"]
    AttackModule --> DHCP["DHCP<br/>raw Ethernet/IP/UDP/DHCP"]
    AttackModule --> DNS["DNS<br/>raw packet DNS response"]
    AttackModule --> NAT["NAT<br/>raw Ethernet/IP/UDP"]

    Session --> Database["Database<br/>SQLite history"]
    Session --> Helper["HelperFunctions<br/>discovery, validation, system toggles"]

    Sniffer --> Pcap["libpcap<br/>pcap_open_live, pcap_dump"]
    Database --> SQLite["sqlite3"]
    Helper --> LinuxFiles["/proc, /etc/resolv.conf"]
    Helper --> ShellTools["ping, nmcli, iptables, sysctl, xdg-open/imv"]

    ARP --> Helper
    DNS --> Helper
    NAT --> Helper
```

Notes:

- `Menu` is the application hub and owns almost every top-level object.
- `Session` carries both configuration data and shared service objects.
- `AttackModule` gives the modules a common shape, but the menu still selects modules by matching `get_name()` strings.
- `HelperFunctions` is a mix of pure-ish validators, system discovery, shell command execution, and privileged network toggles.

## Runtime Flow Graph

```mermaid
flowchart TD
    Start["Process start"] --> RegisterSignal["Register SIGINT handler"]
    RegisterSignal --> ConstructMenu["Construct Menu"]
    ConstructMenu --> InitSession["Session constructs Database and HelperFunctions"]
    InitSession --> MenuRun["Menu::run()"]
    MenuRun --> Logo["Print logo"]
    Logo --> LoadModules["Create attack module inventory"]
    LoadModules --> DetectIface["Auto-detect default interface"]
    DetectIface --> MainLoop["Main menu loop"]

    MainLoop --> AttackMenu["Attack modules menu"]
    MainLoop --> SnifferStart["Start sniffer"]
    MainLoop --> ConfigMenu["Target configuration"]
    MainLoop --> History["Print SQLite history"]
    MainLoop --> Exit["Exit"]

    ConfigMenu --> Helpers["Helper discovery:<br/>scan /24, ARP cache, gateway, DNS, DHCP"]
    Helpers --> SessionUpdate["Update Session fields"]
    SessionUpdate --> MainLoop

    AttackMenu --> SelectModule["Find module by display name"]
    SelectModule --> ValidateConfig["Validate required Session fields"]
    ValidateConfig --> LogAttack["Database::log_attack()"]
    LogAttack --> RunModule["module.run(&Session)"]
    RunModule --> WaitEnter["Foreground modules wait for Enter<br/>or background modules toggle"]
    WaitEnter --> StopModule["module.stop()"]
    StopModule --> MainLoop

    SnifferStart --> CaptureThread["capture_loop thread"]
    CaptureThread --> PcapOpen["pcap_open_live + pcap_dump_open"]
    PcapOpen --> CapturePackets["Dump packets and print IPv4 rows"]
    CapturePackets --> StopSniffer["Enter stops sniffer"]
    StopSniffer --> MainLoop

    RegisterSignal --> Sigint["Ctrl-C"]
    Sigint --> StopAll["Menu::stop_all_attacks()"]
    StopAll --> ProcessExit["exit(0)"]
```

Notes:

- Most user interactions are blocking `std::cin` reads.
- Foreground attack modules run until the user presses Enter.
- ARP spoofing and DHCP starvation are toggled in the menu and can keep running in the background.
- SIGINT cleanup only stops attack modules; it does not explicitly stop the sniffer.

## Data Flow Graph

```mermaid
flowchart LR
    User["User input"] --> Menu["Menu"]
    Menu --> Session["Session config fields"]
    Session --> Modules["Attack modules"]
    Session --> Sniffer["Sniffer"]
    Session --> DB["Database"]

    Helper["HelperFunctions"] --> Session
    Proc["/proc/net/arp<br/>/proc/net/route"] --> Helper
    Resolv["/etc/resolv.conf"] --> Helper
    Nmcli["nmcli"] --> Helper
    Ping["ping sweep"] --> Helper

    Modules --> RawSockets["Raw sockets<br/>AF_PACKET / AF_INET"]
    RawSockets --> Network["LAN traffic / host network stack"]

    Sniffer --> PcapLive["libpcap live capture"]
    PcapLive --> Console["Console packet rows"]
    PcapLive --> PcapFiles["sniffs/timestamp.pcap"]

    DB --> SqliteFile["mischiever_history.db"]
    Modules --> Console
    Helper --> SysState["ip_forward<br/>send_redirects<br/>iptables"]
```

Notes:

- `Session` is the only real shared application state model.
- Packet-generation modules mostly read from `Session` at start, then copy strings into worker threads.
- The database records only a small slice of runtime context.
- System state changes are side effects of helper methods and module stop methods, not first-class tracked resources.

## Control-Flow Hotspots

- `Menu::show_floods_menu()` has a NAT-specific hack that temporarily sets `session.target_ip = session.gateway_ip`.
- `Menu::show_mitm_menu()` manually maintains `session.arp_spoof_active`.
- `Menu::show_dos_menu()` manually maintains `session.dhcp_starvation_active` and gates DNS spoofing on ARP spoofing.
- `Menu::set_target_config()` contains discovery, validation, prompting, and state mutation in one long method.
- `Menu::run_selected_attack()` assumes an attack can be started, then stopped by pressing Enter. Background/toggle modules bypass parts of this generic lifecycle.

## System-State Side Effects

```mermaid
flowchart TD
    ARPSpoof["ARP Spoof mode"] --> EnableForward["ip_forward = 1"]
    ARPSpoof --> DisableRedirects["send_redirects = 0"]
    ARPStop["ARP stop"] --> DisableForward["ip_forward = 0"]
    ARPStop --> EnableRedirects["send_redirects = 1"]

    ARPBlackhole["ARP Blackhole mode"] --> ForwardDrop["iptables -P FORWARD DROP"]
    BlackholeStop["Blackhole stop"] --> ForwardAccept["iptables -P FORWARD ACCEPT"]

    DNSSpoof["DNS Spoofing start"] --> DropDNS["iptables -I FORWARD -p udp --dport 53 -j DROP"]
    DNSStop["DNS stop"] --> RemoveDropDNS["iptables -D matching DROP rule"]

    SnifferStart["Sniffer start"] --> SniffsDir["mkdir -p sniffs"]
    SnifferCapture["Sniffer capture"] --> ChownPcap["optional chown to SUDO_UID/SUDO_GID"]
```

Notes:

- These side effects are global to the host, not scoped to Mischiever's process.
- The most dangerous design issue is changing default firewall policy (`iptables -P FORWARD DROP/ACCEPT`) rather than installing scoped, reversible rules.
- Future refactors should wrap these mutations in explicit guard/restore objects and record the previous state before changing it.
