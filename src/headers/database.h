#ifndef DATABASE_H
#define DATABASE_H

#include <sqlite3.h>
#include <string>

class Database {
private:
    sqlite3* db;
    
public:
    // Constructor opens DB and creates table
    Database();
    
    // Destructor closes DB
    ~Database();

    // Logs a new attack
    void log_attack(const std::string& type, const std::string& attacker_ip, const std::string& victim_ip);

    // Prints all history
    void print_history();
};

#endif