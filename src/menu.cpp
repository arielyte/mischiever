#include <iostream>
#include <limits>
#include <unistd.h> // for sleep()
#include <cstdlib>  // for srand(), time()
#include <ctime>    // for time()
#include <iomanip> // For std::setw

#include "headers/menu.h"
#include "headers/sniffer.h"
#include "headers/syn.h"
#include "headers/arp.h"
#include "headers/icmp.h"
#include "headers/dhcp.h"
#include "headers/dns.h"

// --- Constructor & Destructor ---
Menu::Menu() {
    // Seed random number generator
    srand(time(0));
    sniffer_tool = std::unique_ptr<Sniffer>(new Sniffer()); // Initialize sniffer tool
}

Menu::~Menu() {}

// --- Main Application Logic ---
void Menu::run() {
    print_logo();

    // [PLATFORM ARCHITECTURE]
    // Instead of creating tools on demand, we load them all into an "Inventory" (vector) at startup.
    // This allows us to add 50 new attacks without changing the main loop logic.
    // We use unique_ptr to handle memory automatically (no more manual 'delete').
    attack_modules.push_back(std::unique_ptr<SYN>(new SYN(SYN::FLOOD)));
    attack_modules.push_back(std::unique_ptr<ICMP>(new ICMP(ICMP::FLOOD)));
    attack_modules.push_back(std::unique_ptr<ARP>(new ARP(ARP::SPOOFING)));
    attack_modules.push_back(std::unique_ptr<ARP>(new ARP(ARP::BLACKHOLE)));
    attack_modules.push_back(std::unique_ptr<DHCP>(new DHCP(DHCP::STARVATION))); // DHCP with Starvation mode
    attack_modules.push_back(std::unique_ptr<DHCP>(new DHCP(DHCP::RELEASE))); // DHCP with Targeted Release mode
    attack_modules.push_back(std::unique_ptr<DNS>(new DNS(DNS::SPOOFING)));

    // Set default interface automatically if possible
    std::string default_iface = session.helper->get_iface();
    if (!default_iface.empty()) {
        session.interface = default_iface;
    } else {
        std::cout << C_RED << "Could not detect default interface. Please set one in Target Configuration." << C_RESET << std::endl;
        sleep(2);
    }
    
    int choice = -1;
    while (choice != 5) {
        display_main_menu();
        
        std::cin >> choice;
        // Handle invalid input
        if (std::cin.fail()) {
            choice = -1; // Invalid input
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        }

        switch (choice) {
            case 1: show_attack_modules_menu(); break;
            case 2: // sniffer
            if (session.interface.empty()) {
                std::cout << C_RED << "Interface not set! Please configure it first." << C_RESET << std::endl;
                sleep(2);
            } else {
                sniffer_tool->start(&session);
                // Wait for Enter to stop
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                std::cin.get();
                sniffer_tool->stop();
                sleep(2);
            }
            break;
            case 3: show_target_config_menu(); break;
            case 4: show_attack_history(); break;
            // Easter Eggs
            case 42: session.helper->displayImage("misc/cat.jpg"); break; // Easter egg
            case 777: session.helper->displayImage("misc/cat2.png"); break; // Easter egg
            case 5: break; // Exit
            default:
                std::cout << C_RED << "Invalid choice. Please try again." << C_RESET << std::endl;
                sleep(1);
                break;
        }
    }

    std::cout << C_YELLOW << "Exiting Mischiever." << C_RESET << std::endl;
}

void Menu::stop_all_attacks() {
    for (const auto& mod : attack_modules) {
        if (mod) {
            mod->stop();
        }
    }
}


// --- Menu Display Functions ---

void Menu::print_logo() {
    session.helper->clearScreen();
    std::cout << C_MAGENTA << R"(
    __  ____       __    _                     
   /  |/  (_)_____/ /_  (_)__ _   _____  _____
  / /|_/ / / ___/ __ \/ / _ \ | / / _ \/ ___/
 / /  / / (__  ) /_/ / /  __/ |/ /  __/ /    
/_/  /_/_/____/_.___/_/\___/|___/\___/_/     
                                             
    )" << C_RESET << std::endl;
    std::cout << C_CYAN << "      The Network Swiss Army Knife" << C_RESET << "\n" << std::endl;
    sleep(1);
}

void Menu::display_main_menu_header() {
    // Clear the screen first
    session.helper->clearScreen();
    
    // A nice wide separator
    std::cout << C_BLUE << "================================================================================" << C_RESET << std::endl;

    // Helper lambda to handle "None" vs "Value" coloring cleanly
    auto colorize = [](const std::string& val) {
        // If empty -> Yellow "None", If set -> Green Value
        return val.empty() ? (std::string(C_YELLOW) + "None" + C_RESET) : (std::string(C_GREEN) + val + C_RESET);
    };

    // The Single Line Dashboard
    // Uses Blue Pipes " | " to visually separate the sections
    std::cout << C_BOLD << " Interface: " << C_RESET << colorize(session.interface) 
              << C_BLUE << "  |  " << C_RESET 
              << C_BOLD << "Target IP: " << C_RESET << colorize(session.target_ip)
              << C_BLUE << "  |  " << C_RESET 
              << C_BOLD << "Gateway IP: " << C_RESET << colorize(session.gateway_ip) 
              << std::endl;

    std::cout << C_BLUE << "================================================================================" << C_RESET << std::endl;
}

void Menu::display_main_menu() {
    display_main_menu_header();
    std::cout << C_BOLD << "            MAIN MENU                   " << C_RESET << std::endl;
    std::cout << C_BLUE << "========================================" << C_RESET << std::endl;
    std::cout << C_GREEN << "[1]" << C_RESET << " Attack Modules" << std::endl;
    std::cout << C_GREEN << "[2]" << C_RESET << " Traffic Sniffer" << std::endl;
    std::cout << C_GREEN << "[3]" << C_RESET << " Target Configuration" << std::endl;
    std::cout << C_GREEN << "[4]" << C_RESET << " Attack History" << std::endl;
    std::cout << C_GREEN << "[5]" << C_RESET << " Exit" << std::endl;
    std::cout << std::endl << C_BOLD << "mischiever > " << C_RESET;
}

void Menu::show_attack_modules_menu() {
    int choice = -1;
    while (choice != 4) {
        display_main_menu_header();
        std::cout << C_BOLD << "           ATTACK MODULES               " << C_RESET << std::endl;
        std::cout << C_BLUE << "========================================" << C_RESET << std::endl;
        std::cout << C_GREEN << "[1]" << C_RESET << " Floods" << std::endl;
        std::cout << C_GREEN << "[2]" << C_RESET << " Man In The Middle" << std::endl;
        std::cout << C_GREEN << "[3]" << C_RESET << " Denial of Service" << std::endl;
        std::cout << C_GREEN << "[4]" << C_RESET << " Back" << std::endl;
        std::cout << std::endl << C_BOLD << "mischiever/modules > " << C_RESET;

        std::cin >> choice;
        if (std::cin.fail()) {
            choice = -1;
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        }

        switch (choice) {
            case 1: show_floods_menu(); break;
            case 2: show_mitm_menu(); break;
            case 3: show_dos_menu(); break;
            case 4: return;
            default:
                std::cout << C_RED << "Invalid choice." << C_RESET << std::endl;
                sleep(1);
                break;
        }
    }
}

void Menu::show_floods_menu() {
    int choice = -1;
    while (choice != 3) {
        display_main_menu_header();
        std::cout << C_BOLD << "           FLOOD ATTACKS                " << C_RESET << std::endl;
        std::cout << C_BLUE << "========================================" << C_RESET << std::endl;
        std::cout << C_GREEN << "[1]" << C_RESET << " SYN Flood" << std::endl;
        std::cout << C_GREEN << "[2]" << C_RESET << " ICMP Ping Flood" << std::endl;
        std::cout << C_GREEN << "[3]" << C_RESET << " Back" << std::endl;
        std::cout << std::endl << C_BOLD << "mischiever/modules/floods > " << C_RESET;
        
        std::cin >> choice;
        if (std::cin.fail()) {
            choice = -1;
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        }

        AttackModule* selected_attack = nullptr;
        switch (choice) {
            case 1: // SYN
                for (const auto& mod : attack_modules) {
                    if (mod->get_name() == "SYN Flood") selected_attack = mod.get();
                }
                break;
            case 2: // ICMP
                for (const auto& mod : attack_modules) {
                    if (mod->get_name() == "ICMP Flood") selected_attack = mod.get();
                }
                break;
            case 3: return;
            default:
                std::cout << C_RED << "Invalid choice." << C_RESET << std::endl;
                sleep(1);
                continue;
        }
        
        // Smoother now
        if (selected_attack) {
            // Only ask for config if we genuinely don't have a target yet
            if(session.target_ip.empty()) {
                std::cout << C_YELLOW << "[!] Target not set. Redirecting to configuration..." << C_RESET << std::endl;
                set_target_config();
            }
            std::cout << C_GREEN << selected_attack->get_name() << " attack started." << C_RESET << std::endl;
            run_selected_attack(selected_attack);
        }
    }
}

void Menu::show_mitm_menu() {
    int choice = -1;
    while (choice != 2) {
        display_main_menu_header();
        std::cout << C_BOLD << "              MITM ATTACKS              " << C_RESET << std::endl;
        std::cout << C_BLUE << "========================================" << C_RESET << std::endl;
        std::cout << C_YELLOW << "[!] Some attacks can be toggled ON/OFF to run in the background." << C_RESET << std::endl;
        std::cout << C_GREEN << "[1]" << C_RESET << " ARP Spoofing "
                  << (session.arp_spoof_active ? C_GREEN "[ON]" C_RESET : C_RED "[OFF]" C_RESET)
                  << std::endl;
        std::cout << C_GREEN << "[2]" << C_RESET << " Back" << std::endl;
        std::cout << std::endl << C_BOLD << "mischiever/modules/mitm > " << C_RESET;

        std::cin >> choice;
        if (std::cin.fail()) {
            choice = -1;
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        }

        if (choice == 1) {
            AttackModule* arp_attack = nullptr;
            for (const auto& mod : attack_modules) {
                if (mod->get_name() == "ARP Spoof") {
                    arp_attack = mod.get();
                    break;
                }
            }

            if (arp_attack) {
                if (session.arp_spoof_active) {
                    // If it's on, turn it off
                    arp_attack->stop();
                    session.arp_spoof_active = false;
                    std::cout << C_GREEN << "ARP Spoof attack stopped." << C_RESET << std::endl;
                    sleep(1);
                } else {
                    // If it's off, turn it on
                    if (session.target_ip.empty() || session.gateway_ip.empty()) {
                         std::cout << C_YELLOW << "[!] Target and Gateway IPs must be set for this attack." << C_RESET << std::endl;
                         sleep(1);
                         set_target_config();
                    }
                    
                    // Re-check after config
                    if (!session.target_ip.empty() && !session.gateway_ip.empty()) {
                        // Log before running
                        std::string my_ip = session.helper->get_local_ip(session.interface.c_str());
                        std::string source_log = my_ip.empty() ? "Unknown (You)" : my_ip + " (You)";
                        session.db->log_attack(arp_attack->get_name(), source_log, session.target_ip);
                        
                        arp_attack->run(&session); // This runs in the background
                        session.arp_spoof_active = true;
                        std::cout << C_GREEN << "ARP Spoof attack started in the background." << C_RESET << std::endl;
                        sleep(2);
                    } else {
                        std::cout << C_RED << "Configuration incomplete. Attack not started." << C_RESET << std::endl;
                        sleep(1);
                    }
                }
            }
        } else if (choice != 2) {
             std::cout << C_RED << "Invalid choice." << C_RESET << std::endl;
             sleep(1);
        }
    }
}

void Menu::show_dos_menu() {
    int choice = -1;
    while (choice != 5) {
        display_main_menu_header();

        // 1. Prepare Status Strings (Logic first)
        std::string starvation_status = session.dhcp_starvation_active 
                                        ? C_GREEN "[ON]" 
                                        : C_RED "[OFF]";

        std::string dns_status = session.arp_spoof_active 
                                 ? C_GREEN "[READY]" 
                                 : C_RED "[ARP SPOOFING REQUIRED]";

        // 2. Print Menu (View second)
        // \t tabs are cleaner than typing 10 spaces
        std::cout << C_BOLD << "\t\tDoS ATTACKS" << C_RESET << std::endl; 
        std::cout << C_BLUE << "========================================" << C_RESET << std::endl;
        
        std::cout << C_GREEN << "[1]" << C_RESET << " DHCP Lease Breaker" << std::endl;
        std::cout << C_GREEN << "[2]" << C_RESET << " DHCP Starvation " << starvation_status << C_RESET << std::endl;
        std::cout << C_GREEN << "[3]" << C_RESET << " ARP Blackhole" << std::endl;
        std::cout << C_GREEN << "[4]" << C_RESET << " DNS Spoofing    " << dns_status << C_RESET << std::endl;
        std::cout << C_GREEN << "[5]" << C_RESET << " Back" << std::endl;

        // 3. Prompt & Input
        std::cout << "\n" << C_BOLD << "mischiever/modules/dos > " << C_RESET;

        std::cin >> choice;
        // Input validation to prevent infinite loops on bad input
        if (std::cin.fail()) {
            choice = -1;
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        }

        if (choice == 1) { // DHCP Lease Breaker
            AttackModule* selected_attack = nullptr;
            for (const auto& mod : attack_modules) {
                if (mod->get_name() == "DHCP Release") selected_attack = mod.get();
            }

            if (selected_attack) {
                // This attack needs Target IP, Target MAC, and the DHCP Server IP
                if (session.target_ip.empty() || session.target_mac.empty() || session.dhcp_server_ip.empty()) {
                    std::cout << C_YELLOW << "[!] Target IP/MAC & DHCP Server IP must be set. Redirecting..." << C_RESET << std::endl;
                    sleep(1);
                    set_target_config();
                }
                
                // Re-check after config
                if (!session.target_ip.empty() && !session.target_mac.empty() && !session.dhcp_server_ip.empty()) {
                    std::cout << C_GREEN << "DHCP Release attack started." << C_RESET << std::endl;
                    run_selected_attack(selected_attack);
                } else {
                    std::cout << C_RED << "Configuration incomplete. Attack not started." << C_RESET << std::endl;
                    sleep(1);
                }
            } else {
                std::cout << C_RED << "Error: DHCP Release module not found!" << C_RESET << std::endl;
                sleep(2);
            }
        }
        else if (choice == 2) { // DHCP Starvation (Toggle)
            DHCP* dhcp_starve_attack = nullptr;
            for (const auto& mod : attack_modules) {
                if (mod->get_name() == "DHCP Starvation") {
                    dhcp_starve_attack = static_cast<DHCP*>(mod.get());
                    break;
                }
            }

            if (dhcp_starve_attack) {
                if (session.dhcp_starvation_active) {
                    // It's ON -> Turn it OFF
                    dhcp_starve_attack->stop_starvation();
                    session.dhcp_starvation_active = false;
                    std::cout << C_GREEN << "DHCP Starvation stopped." << C_RESET << std::endl;
                    sleep(1);
                } else {
                    // It's OFF -> Turn it ON
                    if (session.interface.empty()) {
                        std::cout << C_YELLOW << "[!] Interface not set. Redirecting..." << C_RESET << std::endl;
                        sleep(1);
                        set_target_config();
                    }
                    
                    if (!session.interface.empty()) {
                        std::string my_ip = session.helper->get_local_ip(session.interface.c_str());
                        std::string source_log = my_ip.empty() ? "Unknown (You)" : my_ip + " (You)";
                        session.db->log_attack(dhcp_starve_attack->get_name(), source_log, "Network Pool");

                        dhcp_starve_attack->start_starvation_background(&session);
                        session.dhcp_starvation_active = true;
                        std::cout << C_GREEN << "DHCP Starvation started in the background." << C_RESET << std::endl;
                        sleep(2);
                    } else {
                        std::cout << C_RED << "Interface not set. Attack not started." << C_RESET << std::endl;
                        sleep(1);
                    }
                }
            } else {
                std::cout << C_RED << "Error: DHCP Starvation module not found!" << C_RESET << std::endl;
                sleep(2);
            }
        }
        else if (choice == 3) { // ARP Blackhole
            AttackModule* selected_attack = nullptr;
            for (const auto& mod : attack_modules) {
                if (mod->get_name() == "ARP Blackhole") {
                    selected_attack = mod.get();
                    break;
                }
            }

            if (selected_attack) {
                if (session.target_ip.empty() || session.gateway_ip.empty()) {
                     std::cout << C_YELLOW << "[!] Target and Gateway IPs must be set for this attack." << C_RESET << std::endl;
                     sleep(1);
                     set_target_config();
                }
                
                // Re-check after config
                if (!session.target_ip.empty() && !session.gateway_ip.empty()) {
                    std::cout << C_GREEN << "ARP Blackhole attack started." << C_RESET << std::endl;
                    run_selected_attack(selected_attack);
                }
            } else {
                std::cout << C_RED << "Error: ARP Blackhole module not found!" << C_RESET << std::endl;
                sleep(2);
            }
        } else if (choice == 4) {
            set_dns_config();
            AttackModule* dns_attack = nullptr;
            for (const auto& mod : attack_modules) {
                if (mod->get_name() == "DNS Spoofing") {
                    dns_attack = mod.get();
                    break;
                }
            }
            if (dns_attack) {
                run_selected_attack(dns_attack);
            }
        }
        else if (choice != 5) {
             std::cout << C_RED << "Invalid choice." << C_RESET << std::endl;
             sleep(1);
        }
    }
}
    
void Menu::show_attack_history() {
    display_main_menu_header();
    std::cout << C_BOLD << "                            ATTACK HISTORY               " << C_RESET << std::endl;
    std::cout << C_BLUE << "===========================================================================================================================" << C_RESET << std::endl;
    session.db->print_history();
    std::cout << C_BLUE << "===========================================================================================================================" << C_RESET << std::endl;
    std::cout << "\nPress Enter to return..." << std::endl;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::cin.get();
}

// Target Configuration Sub-Menu
void Menu::show_target_config_menu() {
    int choice = -1;
    while (choice != 4) {
        display_main_menu_header();
        std::cout << C_BOLD << "         TARGET CONFIGURATION           " << C_RESET << std::endl;
        std::cout << C_BLUE << "========================================" << C_RESET << std::endl;
        std::cout << C_GREEN << "[1]" << C_RESET << " View current configuration" << std::endl;
        std::cout << C_GREEN << "[2]" << C_RESET << " Set target configuration" << std::endl;
        std::cout << C_GREEN << "[3]" << C_RESET << " Delete target configuration" << std::endl;
        std::cout << C_GREEN << "[4]" << C_RESET << " Back" << std::endl;
        std::cout << std::endl << C_BOLD << "mischiever/config > " << C_RESET;

        std::cin >> choice;
        if (std::cin.fail()) {
            choice = -1;
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        }

        switch (choice) {
            case 1: 
                view_target_config(); 
                break;
            case 2: 
                // This calls the "Wizard" function
                set_target_config(); 
                break;
            case 3: 
                delete_target_config(); 
                break;
            case 4: 
                return; // Go back to Main Menu
            default:
                std::cout << C_RED << "Invalid choice." << C_RESET << std::endl;
                sleep(1);
                break;
        }
    }
}

void Menu::view_target_config() {
    display_main_menu_header();
    std::cout << C_BOLD << "        CURRENT CONFIGURATION           " << C_RESET << std::endl;
    std::cout << C_BLUE << "========================================" << C_RESET << std::endl;
    
    // Helper lambda for consistent spacing
    auto print_param = [](std::string label, std::string value) {
        std::cout << std::left << std::setw(15) << label << ": ";
        if (value.empty()) std::cout << C_YELLOW << "Not Set" << C_RESET << std::endl;
        else std::cout << C_GREEN << value << C_RESET << std::endl;
    };

    print_param("Interface", session.interface);
    print_param("Target IP", session.target_ip);
    print_param("Target MAC", session.target_mac);
    print_param("Gateway IP", session.gateway_ip);
    print_param("Gateway MAC", session.gateway_mac);
    print_param("DHCP Server IP", session.dhcp_server_ip);
    print_param("DNS Server IP", session.dns_server_ip);

    std::cout << C_BLUE << "========================================" << C_RESET << std::endl;
    std::cout << "\nPress Enter to return..." << std::endl;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::cin.get();
}

// Target configuration menu with input validation and auto-find features
void Menu::set_target_config() {
    display_main_menu_header();
    std::cout << C_BOLD << "         TARGET CONFIGURATION           " << C_RESET << std::endl;
    std::cout << C_BLUE << "========================================" << C_RESET << std::endl;
    std::cout << C_YELLOW << "[!] Press Enter to keep current value." << C_RESET << std::endl;
    std::cout << C_YELLOW << "[!] Type 'find' to auto-detect IPs or MACs." << C_RESET << std::endl;
    std::cout << C_YELLOW << "[!] Type 'q' to quit.\n" << C_RESET << std::endl;
    
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    std::string temp;
    bool valid_input;

    auto check_exit = [&](const std::string& input) -> bool {
        if (input == "q") {
            std::cout << C_GREEN << "Exiting configuration..." << C_RESET << std::endl;
            sleep(1);
            return true; 
        }
        return false;
    };

    // 0. Interface (Only ask if NOT set)
    if (session.interface.empty()) {
        do {
            valid_input = true;
            std::cout << C_CYAN << "Interface [None]: " << C_RESET;
            std::getline(std::cin, temp);

            if (check_exit(temp)) return;

            if (!temp.empty()) {
                session.interface = temp;
                std::cout << C_GREEN << "Interface set to: " << session.interface << C_RESET << std::endl;
            } else {
                std::cout << C_RED << "Interface is required to proceed." << C_RESET << std::endl;
                valid_input = false;
            }
        } while (!valid_input);
    }

    // 1. Target IP (we keep this looped - User must choose from list)
    do {
        valid_input = true;
        std::cout << C_CYAN << "Target IP [" << (session.target_ip.empty() ? "None" : session.target_ip) << "]: " << C_RESET;
        std::getline(std::cin, temp);
        if (check_exit(temp)) return;

        if (temp == "find") {
            session.helper->scan_local_network(session.interface.c_str());
            valid_input = false; // STAY IN LOOP so user can type the IP they just saw
            continue;
        }

        if (!temp.empty()) {
            if (session.helper->is_valid_ip(temp)) session.target_ip = temp;
            else { std::cout << C_RED << "Invalid IP." << C_RESET << std::endl; valid_input = false; }
        }
    } while (!valid_input);

    // 2. Target MAC (AUTO-ADVANCE)
    do {
        valid_input = true;
        std::cout << C_CYAN << "Target MAC [" << (session.target_mac.empty() ? "None" : session.target_mac) << "]: " << C_RESET;
        std::getline(std::cin, temp);
        if (check_exit(temp)) return;

        if (!temp.empty()) {
            if (temp == "find") {
                if (session.target_ip.empty()) {
                    std::cout << C_RED << "Set Target IP first." << C_RESET << std::endl; valid_input = false;
                } else {
                    std::cout << C_YELLOW << "[*] Finding Target MAC... " << C_RESET;
                    std::string mac = session.helper->get_mac_from_ip(session.target_ip);
                    if (!mac.empty()) { 
                        session.target_mac = mac; 
                        std::cout << C_GREEN << mac << " (Found & Set)" << C_RESET << std::endl; 
                        valid_input = true; // BREAK LOOP - Auto-advance
                    } else { 
                        std::cout << C_RED << "Failed." << C_RESET << std::endl; 
                        valid_input = false; 
                    }
                }
            } else if (session.helper->is_valid_mac(temp)) {
                session.target_mac = temp;
            } else { 
                std::cout << C_RED << "Invalid MAC." << C_RESET << std::endl; 
                valid_input = false; 
            }
        }
    } while (!valid_input);

    // 3. Gateway IP (AUTO-ADVANCE)
    do {
        valid_input = true;
        std::cout << C_CYAN << "Gateway IP [" << (session.gateway_ip.empty() ? "None" : session.gateway_ip) << "]: " << C_RESET;
        std::getline(std::cin, temp);
        if (check_exit(temp)) return;

        if (temp == "find") {
            std::cout << C_YELLOW << "[*] Detecting Default Gateway... " << C_RESET;
            std::string gw = session.helper->get_default_gateway_ip();
            if (!gw.empty()) { 
                session.gateway_ip = gw; 
                std::cout << C_GREEN << gw << " (Found & Set)" << C_RESET << std::endl; 
                valid_input = true; // BREAK LOOP
            } else { 
                std::cout << C_RED << "Failed." << C_RESET << std::endl; 
                valid_input = false; 
            }
            continue;
        }

        if (!temp.empty()) {
            if (session.helper->is_valid_ip(temp)) session.gateway_ip = temp;
            else { std::cout << C_RED << "Invalid IP." << C_RESET << std::endl; valid_input = false; }
        }
    } while (!valid_input);

    // 4. Gateway MAC (AUTO-ADVANCE)
    do {
        valid_input = true;
        std::cout << C_CYAN << "Gateway MAC [" << (session.gateway_mac.empty() ? "None" : session.gateway_mac) << "]: " << C_RESET;
        std::getline(std::cin, temp);
        if (check_exit(temp)) return;

        if (!temp.empty()) {
            if (temp == "find") {
                if (session.gateway_ip.empty()) {
                    std::cout << C_RED << "Set Gateway IP first." << C_RESET << std::endl; valid_input = false;
                } else {
                    std::cout << C_YELLOW << "[*] Finding Gateway MAC... " << C_RESET;
                    std::string mac = session.helper->get_mac_from_ip(session.gateway_ip);
                    if (!mac.empty()) { 
                        session.gateway_mac = mac; 
                        std::cout << C_GREEN << mac << " (Found & Set)" << C_RESET << std::endl; 
                        valid_input = true; // BREAK LOOP
                    } else { 
                        std::cout << C_RED << "Failed." << C_RESET << std::endl; 
                        valid_input = false; 
                    }
                }
            } else if (session.helper->is_valid_mac(temp)) {
                session.gateway_mac = temp;
            } else { 
                std::cout << C_RED << "Invalid MAC." << C_RESET << std::endl; 
                valid_input = false; 
            }
        }
    } while (!valid_input);

    // 5. DHCP Server IP (AUTO-ADVANCE)
    do {
        valid_input = true;
        std::cout << C_CYAN << "DHCP Server IP [" << (session.dhcp_server_ip.empty() ? "None" : session.dhcp_server_ip) << "]: " << C_RESET;
        std::getline(std::cin, temp);
        if (check_exit(temp)) return;

        if (temp == "find") {
            std::cout << C_YELLOW << "[*] Detecting DHCP... " << C_RESET;
            std::string dhcp = session.helper->get_dhcp_server_ip();
            if (!dhcp.empty()) { 
                session.dhcp_server_ip = dhcp; 
                std::cout << C_GREEN << dhcp << " (Found & Set)" << C_RESET << std::endl; 
                valid_input = true; // BREAK LOOP
            } else { 
                std::cout << C_RED << "Failed." << C_RESET << std::endl; 
                valid_input = false; 
            }
            continue;
        }

        if (!temp.empty()) {
            if (session.helper->is_valid_ip(temp)) session.dhcp_server_ip = temp;
            else { std::cout << C_RED << "Invalid IP." << C_RESET << std::endl; valid_input = false; }
        }
    } while (!valid_input);

    // 6. DNS Server IP (AUTO-ADVANCE)
    do {
        valid_input = true;
        std::cout << C_CYAN << "DNS Server IP [" << (session.dns_server_ip.empty() ? "None" : session.dns_server_ip) << "]: " << C_RESET;
        std::getline(std::cin, temp);
        if (check_exit(temp)) return;

        if (temp == "find") {
            std::cout << C_YELLOW << "[*] Detecting DNS... " << C_RESET;
            std::string dns = session.helper->get_dns_server_ip();
            if (!dns.empty()) { 
                session.dns_server_ip = dns; 
                std::cout << C_GREEN << dns << " (Found & Set)" << C_RESET << std::endl; 
                valid_input = true; // BREAK LOOP
            } else { 
                std::cout << C_RED << "Failed." << C_RESET << std::endl; 
                valid_input = false; 
            }
            continue;
        }

        if (!temp.empty()) {
            if (session.helper->is_valid_ip(temp)) session.dns_server_ip = temp;
            else { std::cout << C_RED << "Invalid IP." << C_RESET << std::endl; valid_input = false; }
        }
    } while (!valid_input);

    std::cout << C_GREEN << "\nConfiguration updated.\n" << C_RESET << std::endl;
    sleep(1);
}

void Menu::delete_target_config() {
    char confirm;
    std::cout << C_YELLOW << "\n[!] Are you sure you want to delete all configuration? (y/n): " << C_RESET;
    std::cin >> confirm;

    if (confirm == 'y' || confirm == 'Y') {
        // Clear all session variables except Interface (we prefer to keep that)
        session.target_ip.clear();
        session.target_mac.clear();
        session.gateway_ip.clear();
        session.gateway_mac.clear();
        session.dhcp_server_ip.clear();
        session.dns_server_ip.clear();
        
        std::cout << C_RED << "Configuration wiped." << C_RESET << std::endl;
    } else {
        std::cout << C_GREEN << "Operation cancelled." << C_RESET << std::endl;
    }
    sleep(1);
}

void Menu::set_dns_config() {
    std::cout << "\n" << C_BLUE << "======== DNS SPOOF CONFIG ========" << C_RESET << std::endl;
    
    std::cout << "Target Domain (e.g. " << C_YELLOW << "neverssl.com" << C_RESET << "): ";
    std::cin >> session.dns_target_domain;

    // INPUT VALIDATION LOOP
    while (true) {
        std::cout << "Spoof IP (Redirect to): ";
        std::string input_ip;
        std::cin >> input_ip;

        if (HelperFunctions::is_valid_ip(input_ip)) {
            session.dns_spoofed_ip = input_ip;
            break; // Valid IP, exit loop
        } else {
            std::cout << C_RED << "[!] Invalid IP address. Format: x.x.x.x" << C_RESET << std::endl;
        }
    }
}

// Dynamic attack runner that takes any AttackModule and runs it using shared Session state
void Menu::run_selected_attack(AttackModule* attack) {
    if (!attack) return;
    // Edge case: Ensure target IP is set
    if (session.target_ip.empty()) {
        std::cerr << C_RED << "Target IP is not set! Please configure it first." << C_RESET << std::endl;
        sleep(2);
        return;
    }

    // Log the attack before running
    // Get local IP for logging by querying the interface with the helper functions we declared inside session
    std::string my_ip = session.helper->get_local_ip(session.interface.c_str());
    // For source_log, if my_ip is empty, use "Unknown (You)" to indicate the attack is from us - otherwise use the actual IP
    std::string source_log = my_ip.empty() ? "Unknown (You)" : my_ip + " (You)";
    // Log the attack with database service inside session, we get the info from here and the session 
    session.db->log_attack(attack->get_name(), source_log, session.target_ip);
    
    // Use the run attack inside the module's class, passing the shared session state
    attack->run(&session);
    
    std::cout << C_YELLOW << "\nAttack is running. Press [Enter] to stop it." << C_RESET << std::endl;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::cin.get(); 

    attack->stop();
    std::cout << C_GREEN << "Attack stopped." << C_RESET << std::endl;
    sleep(1);
}
