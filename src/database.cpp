#include "headers/database.h"
#include <ctime>
#include <iostream>

// ANSI Colors are now included via headers that need them, e.g. menu.cpp

// Callback function used by sqlite3_exec to print results
static int callback(void* NotUsed, int argc, char** argv, char** azColName) {
    for (int i = 0; i < argc; i++) {
        // Assuming colors are available from session.h which is included by higher-level files
        std::cout << "\033[1;36m" << azColName[i] << ": " << "\033[0m" 
                  << "\033[1;33m" << (argv[i] ? argv[i] : "NULL") << "\033[0m";
        if (i < argc - 1) std::cout << "\033[1;35m" << " | " << "\033[0m";
    }
    std::cout << std::endl;
    return 0;
}

Database::Database() {
    int rc = sqlite3_open("mischiever_history.db", &db);
    
    if (rc) {
        std::cerr << "[-] Can't open database: " << sqlite3_errmsg(db) << std::endl;
    } else {
        // Create Table if not exists
        const char* sql = "CREATE TABLE IF NOT EXISTS ATTACKS(" \
                          "ID INTEGER PRIMARY KEY AUTOINCREMENT," \
                          "TYPE           TEXT    NOT NULL," \
                          "DATE           TEXT    DEFAULT (DATE('now'))," \
                          "TIME           TEXT    DEFAULT (TIME('now'))," \
                          "ATTACKER_IP    TEXT    NOT NULL," \
                          "VICTIM_IP      TEXT    NOT NULL);";
        
        char* zErrMsg = 0;
        rc = sqlite3_exec(db, sql, 0, 0, &zErrMsg);
        
        if (rc != SQLITE_OK) {
            std::cerr << "SQL error: " << zErrMsg << std::endl;
            sqlite3_free(zErrMsg);
        }
    }
}

Database::~Database() {
    sqlite3_close(db);
}

void Database::log_attack(const std::string& type, const std::string& attacker_ip, const std::string& victim_ip) {
    const char* sql = "INSERT INTO ATTACKS (TYPE, ATTACKER_IP, VICTIM_IP) VALUES (?, ?, ?);";
    sqlite3_stmt* stmt;

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL prepare error: " << sqlite3_errmsg(db) << std::endl;
        return;
    }

    // Bind parameters
    sqlite3_bind_text(stmt, 1, type.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, attacker_ip.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, victim_ip.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "SQL insert step error: " << sqlite3_errmsg(db) << std::endl;
    }

    sqlite3_finalize(stmt);
}

void Database::print_history() {
    const char* sql = "SELECT * from ATTACKS";
    char* zErrMsg = 0;
    int rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
    
    if (rc != SQLITE_OK) {
        std::cerr << "\033[1;31m" << "SQL error: " << zErrMsg << "\033[0m" << std::endl;
        sqlite3_free(zErrMsg);
    }
}