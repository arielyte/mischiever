#ifndef HELPERFUNCS_H
#define HELPERFUNCS_H

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <regex>
#include <iomanip>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#define C_RESET       "\033[0m"
#define C_GREEN       "\033[1;32m"
#define C_YELLOW      "\033[1;33m"
#define C_BLUE        "\033[1;34m"
#define C_BOLD        "\033[1m"
#define C_RED         "\033[1;31m"

class HelperFunctions {
    public:
    void clearScreen();
    void displayImage(const char* filename);
    
    // Returns std::string to avoid dangling pointer issues
    std::string get_iface(); 
    
    // get_local_ip returns a string instead of char* to avoid memory management issues (caller doesn't have to free it)
    std::string get_local_ip(const char* iface);
    
    // Pass string by const reference (&) to avoid copying
    std::string get_mac_from_ip(const std::string& ip_addr);

    // Input validation
    bool is_valid_ip(const std::string& ip);
    bool is_valid_mac(const std::string& mac);

    // Scanner functions
    void scan_local_network(const char* interface);
    std::string get_default_gateway_ip();
    std::string get_dns_server_ip();
    std::string get_dhcp_server_ip();
};

#endif // HELPERFUNCS_H