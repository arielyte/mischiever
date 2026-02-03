# Compiler and Flags
CXX = g++
CXXFLAGS = -Wall -std=c++14 -pthread -lpcap -lsqlite3

# Target Executable
TARGET = mischiever

# Source Files
SRCS = main.cpp \
       code_files/helperfuncs.cpp \
       code_files/menu.cpp \
       code_files/database.cpp \
       code_files/sniffer.cpp \
       code_files/protocols/syn.cpp \
       code_files/protocols/arp.cpp \
       code_files/protocols/icmp.cpp

# Object Files
OBJS = $(SRCS:.cpp=.o)

# Default Rule
all: $(TARGET)

# Link Step (MUST START WITH TAB)
$(TARGET): $(OBJS)
	$(CXX) -o $(TARGET) $(OBJS) $(CXXFLAGS)
	rm -f $(OBJS)

# Compile Step (MUST START WITH TAB)
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean Command (MUST START WITH TAB)
clean:
	rm -f $(TARGET)