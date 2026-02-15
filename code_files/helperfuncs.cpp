#include "headers/helperfuncs.h"

// OPTIMIZATION: Use ANSI Escape codes instead of system("clear")
// This avoids spawning a shell process, eliminating flicker and lag.
void HelperFunctions::clearScreen() {
    std::cout << "\033[2J\033[1;1H";
}

void HelperFunctions::displayImage(const char* filename) {
    std::string command;
    // Helper function to detect Wayland vs X11
    if (std::getenv("WAYLAND_DISPLAY")) {
        command = "imv " + std::string(filename) + " &";
    } else {
        command = "xdg-open " + std::string(filename);
    }
    system(command.c_str());
}

std::string HelperFunctions::get_iface() {
    struct ifaddrs *ifaddr, *ifa;
    std::string iface_name = ""; // Default empty

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return "";
    }

    // Iterate linked list
    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && (ifa->ifa_flags & IFF_UP) && !(ifa->ifa_flags & IFF_LOOPBACK)) {
            if (ifa->ifa_addr->sa_family == AF_INET) { // Ensure it has an IPv4 address
                iface_name = ifa->ifa_name; // Copy string safely
                break;
            }
        }
    }

    freeifaddrs(ifaddr); // Now it's safe to free
    return iface_name;
}

std::string HelperFunctions::get_local_ip(const char* iface) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);

    std::string ip_str = "";

    if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
        struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
        ip_str = inet_ntoa(ipaddr->sin_addr);
    } 

    close(fd);
    return ip_str;
}

std::string HelperFunctions::get_mac_from_ip(const std::string& ip_addr) {
    // 1. Silent ping
    // We redirect stderr to /dev/null as well (2>&1)
    std::string cmd = "ping -c 1 -W 1 " + ip_addr + " > /dev/null 2>&1";
    system(cmd.c_str());

    // 2. Read ARP Cache
    std::ifstream arp_file("/proc/net/arp");
    if (!arp_file.is_open()) return "";

    std::string line;
    std::getline(arp_file, line); // Skip header

    while (std::getline(arp_file, line)) {
        std::stringstream ss(line);
        std::string ip, hw_type, flags, mac, mask, dev;
        ss >> ip >> hw_type >> flags >> mac >> mask >> dev;

        if (ip == ip_addr) {
            if (mac == "00:00:00:00:00:00") return "";
            return mac;
        }
    }
    return "";
}

bool HelperFunctions::is_valid_ip(const std::string& ip) {
    // OPTIMIZATION: 'static' prevents recompiling the regex on every call
    static const std::regex pattern("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");
    return std::regex_match(ip, pattern);
}

bool HelperFunctions::is_valid_mac(const std::string& mac) {
    // OPTIMIZATION: 'static' prevents recompiling the regex on every call
    static const std::regex pattern("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$");
    return std::regex_match(mac, pattern);
}

void HelperFunctions::scan_local_network(const char* interface) {
    std::string local_ip = get_local_ip(interface);
    if (local_ip.empty()) {
        std::cerr << C_RED << "Error: Interface " << interface << " has no IP." << C_RESET << std::endl;
        return;
    }

    std::string subnet = local_ip.substr(0, local_ip.find_last_of('.') + 1);

    std::cout << "\n" << C_YELLOW << "[*] Scanning " << subnet << "0/24 (approx 2s)..." << C_RESET << std::endl;

    // The Ping Sweep Command
    std::string cmd = "for i in $(seq 1 254); do ping -c 1 -W 1 " + subnet + "$i > /dev/null & done; wait";
    system(cmd.c_str());

    std::ifstream arp_file("/proc/net/arp");
    std::string line;
    
    std::cout << C_BLUE << "==========================================" << C_RESET << std::endl;
    std::cout << C_BOLD << " IP ADDRESS      MAC ADDRESS" << C_RESET << std::endl;
    std::cout << C_BLUE << "==========================================" << C_RESET << std::endl;

    std::getline(arp_file, line); // Skip header

    bool found = false;
    while(std::getline(arp_file, line)) {
        std::stringstream ss(line);
        std::string ip, hw_type, flags, mac, mask, dev;
        ss >> ip >> hw_type >> flags >> mac >> mask >> dev;

        // Filter: Must match interface AND have a valid MAC (flag 0x2 usually means complete)
        // 0x0 is incomplete, 0x2 is complete. We just check != 0x0 to be safe.
        if (dev == interface && flags != "0x0") {
            std::cout << " " << C_GREEN << std::left << std::setw(15) << ip << C_RESET << " " << mac << std::endl;
            found = true;
        }
    }
    
    if (!found) {
        std::cout << C_YELLOW << " No active hosts found." << C_RESET << std::endl;
    }
    std::cout << C_BLUE << "==========================================" << C_RESET << "\n" << std::endl;
}

std::string HelperFunctions::get_default_gateway_ip() {
    std::ifstream route_file("/proc/net/route");
    std::string line;
    
    if (!std::getline(route_file, line)) return ""; 

    while (std::getline(route_file, line)) {
        std::stringstream ss(line);
        std::string iface, dest, gateway_hex;
        
        ss >> iface >> dest >> gateway_hex;

        if (dest == "00000000") {
            unsigned int ip_val;
            std::stringstream ss_hex;
            ss_hex << std::hex << gateway_hex;
            ss_hex >> ip_val;
            
            struct in_addr ip_addr;
            ip_addr.s_addr = ip_val;
            return inet_ntoa(ip_addr);
        }
    }
    return "";
}

std::string HelperFunctions::get_dns_server_ip() {
    std::ifstream file("/etc/resolv.conf");
    std::string line;
    if (!file.is_open()) return "";

    while (std::getline(file, line)) {
        // Look for line starting with "nameserver"
        if (line.find("nameserver") == 0) {
            std::stringstream ss(line);
            std::string label, ip;
            ss >> label >> ip;
            // Skip localhost DNS entries
            if (is_valid_ip(ip) && ip != "127.0.0.53") return ip;
        }
    }
    return "";
}

std::string HelperFunctions::get_dhcp_server_ip() {
    // FIX: Dynamically get the interface instead of hardcoding eth0
    std::string iface = get_iface();
    if (iface.empty()) {
        // Fallback if no active interface found
        return get_default_gateway_ip(); 
    }

    // Strategy: Ask NetworkManager CLI directly
    std::string cmd = "nmcli -f IP4.DHCP-SERVER dev show " + iface + " 2>/dev/null";
    
    std::array<char, 128> buffer;
    std::string result;
    
    // Run the command and capture output
    std::shared_ptr<FILE> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) return get_default_gateway_ip(); // Fallback if popen fails

    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }

    // Output format is usually: "IP4.DHCP-SERVER:            192.168.174.254"
    std::stringstream ss(result);
    std::string segment;
    while (ss >> segment) {
        // Return the first valid IP we find in the output
        if (is_valid_ip(segment)) {
            return segment; 
        }
    }

    // Final Fallback: If nmcli failed or returned nothing, guess the Gateway
    return get_default_gateway_ip();
}

void HelperFunctions::toggle_ip_forwarding(bool enable) {
    if (enable) {
        system("echo 1 > /proc/sys/net/ipv4/ip_forward");
    } else {
        system("echo 0 > /proc/sys/net/ipv4/ip_forward");
    }
}

void HelperFunctions::toggle_send_redirects(bool enable) {
    // 0 = Disable redirects (Stealth Mode / "Don't tell victim to bypass me")
    // 1 = Enable redirects (Default Linux behavior)
    if (enable) {
        system("sysctl -w net.ipv4.conf.all.send_redirects=1 > /dev/null");
    } else {
        system("sysctl -w net.ipv4.conf.all.send_redirects=0 > /dev/null");
    }
}

void HelperFunctions::toggle_dns_drop_rule(bool enable) {
    // We use -I (Insert at top) to enable, and -D (Delete) to disable
    if (enable) {
        // Drop UDP packets on port 53 passing THROUGH the machine (FORWARD chain)
        // We suppress output with > /dev/null 2>&1 just to keep the console clean
        system("iptables -I FORWARD -p udp --dport 53 -j DROP > /dev/null 2>&1");
    } else {
        // Remove the rule
        system("iptables -D FORWARD -p udp --dport 53 -j DROP > /dev/null 2>&1");
    }
}
