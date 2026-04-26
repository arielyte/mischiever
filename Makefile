# ==========================================
#  MISCHIEVER BUILD SYSTEM
# ==========================================

# Compiler Settings
CXX           = g++
CONFIG       ?= default
BUILD_DIR     = build/$(CONFIG)
CXXFLAGS_BASE = -Wall -std=c++14 -pthread -I src
CXXFLAGS     ?= $(CXXFLAGS_BASE)
CPPFLAGS     += -MMD -MP
LDFLAGS      += -lpcap -lsqlite3

# Target Binary Name
TARGET   = mischiever

# Source Files
SRCS = src/main.cpp \
       src/helperfuncs.cpp \
       src/menu.cpp \
       src/database.cpp \
       src/sniffer.cpp \
       src/protocols/syn.cpp \
       src/protocols/arp.cpp \
       src/protocols/icmp.cpp \
       src/protocols/dhcp.cpp \
       src/protocols/dns.cpp \
       src/protocols/nat.cpp

# Generate build artifact names under build/<config>/
OBJS = $(patsubst %.cpp,$(BUILD_DIR)/%.o,$(SRCS))
DEPS = $(OBJS:.o=.d)

# ------------------------------------------
#  Rules
# ------------------------------------------

.PHONY: all debug release sanitize clean distclean

# Default Rule: Build the target
all: $(TARGET)

# Link Step (The Final Binary)
$(TARGET): $(OBJS)
	@echo "[*] Linking objects..."
	@$(CXX) -o $(TARGET) $(OBJS) $(LDFLAGS)
	@echo "[+] Build Success: ./$(TARGET)"

# Compile Step (Source -> Object)
$(BUILD_DIR)/%.o: %.cpp
	@echo "    Compiling $<..."
	@mkdir -p $(@D)
	@$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

# Debug build: symbols, no optimization
debug:
	@$(MAKE) CONFIG=debug CXXFLAGS="$(CXXFLAGS_BASE) -O0 -g -DDEBUG" all

# Release build: optimized binary
release:
	@$(MAKE) CONFIG=release CXXFLAGS="$(CXXFLAGS_BASE) -O2 -DNDEBUG" all

# Sanitizer build: address and undefined behavior checks
sanitize:
	@$(MAKE) CONFIG=sanitize CXXFLAGS="$(CXXFLAGS_BASE) -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer" LDFLAGS="$(LDFLAGS) -fsanitize=address,undefined" all

# Clean generated build products only
clean:
	@echo "[*] Removing binary..."
	@rm -f $(TARGET)
	@echo "[*] Removing build artifacts..."
	@rm -rf build

# Full clean including generated runtime artifacts
distclean: clean
	@echo "[*] Removing session history..."
	@rm -f mischiever_history.db
	@echo "[*] Removing captured packet files..."
	@rm -f sniffs/*.pcap

-include $(DEPS)
