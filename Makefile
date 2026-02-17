# ==========================================
#  MISCHIEVER BUILD SYSTEM
# ==========================================

# Compiler Settings
CXX      = g++
CXXFLAGS = -Wall -std=c++14 -pthread -I src
LDFLAGS  = -lpcap -lsqlite3

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
       src/protocols/dns.cpp

# Generate Object Names (.cpp -> .o)
OBJS = $(SRCS:.cpp=.o)

# ------------------------------------------
#  Rules
# ------------------------------------------

# Default Rule: Build the target
all: $(TARGET)

# Link Step (The Final Binary)
$(TARGET): $(OBJS)
	@echo "[*] Linking objects..."
	@$(CXX) -o $(TARGET) $(OBJS) $(LDFLAGS)
	@echo "[+] Build Success: ./$(TARGET)"
	@echo "[*] Cleaning up intermediate object files..."
	@rm -f $(OBJS)

# Compile Step (Source -> Object)
%.o: %.cpp
	@echo "    Compiling $<..."
	@$(CXX) $(CXXFLAGS) -c $< -o $@

# Full Clean (Binary + Database + Sniffs)
clean:
	@echo "[*] Removing binary..."
	@rm -f $(TARGET)
	@echo "[*] Removing session history..."
	@rm -f mischiever_history.db
	@echo "[*] Removing captured packets (sniffs/)..."
	@sudo rm -rf sniffs