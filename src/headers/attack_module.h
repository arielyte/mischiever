#ifndef ATTACK_MODULE_H
#define ATTACK_MODULE_H

#include <string>
#include "session.h"

// Abstract base class for all attack modules.
class AttackModule {
public:
    virtual ~AttackModule() {}

    // Pure virtual function to run the attack logic.
    // Takes a Session object to access shared state and services.
    virtual void run(Session* session) = 0;

    // Pure virtual function to stop the attack (e.g., kill the thread).
    virtual void stop() = 0;

    // Pure virtual function to get the display name of the module.
    virtual std::string get_name() = 0;
};

#endif // ATTACK_MODULE_H
