#include "headers/menu.h"
#include <iostream>
#include <csignal>
#include <unistd.h>

// Global pointer to the Menu object for the signal handler
Menu* g_menu = nullptr;

// Signal handler function
void handle_signal(int signum) {
    if (signum == SIGINT) {
        std::cout << "\n\n" << C_RED << "[!] SIGINT received." << C_RESET << " " << C_YELLOW << "Cleaning up and shutting down..." << C_RESET << std::endl;
        
        // Stop all attack modules
        if (g_menu) {
            g_menu->stop_all_attacks();
        }
        
        // Give a moment for cleanup to finish
        sleep(1);

        // Exit cleanly
        exit(0);
    }
}

int main() {
    // Register the signal handler for SIGINT
    signal(SIGINT, handle_signal);
    
    // Create the Menu object
    Menu menu;
    g_menu = &menu;

    // Run the main application loop
    menu.run();

    return 0;
}