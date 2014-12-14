# Makefile for Multi-Threaded DNS64s
CXX=g++
TARGET=mtd64
CXXFLAGS=-Wall -std=c++0x -O2 -pthread
RM=rm -f

# Check whether GCC version is above 4.7, if yes, this vaule will be one
GCC_VERSION := $(shell echo `gcc -dumpversion | cut -f1-2 -d.` \>= 4.7 | sed -e 's/\./*100+/g' | bc )

# If GCC version is above 4.7 compiler supports c++11
ifeq ($(GCC_VERSION),1)
CXXFLAGS=-Wall -std=c++11 -O2 -pthread
endif


all: $(TARGET)

$(TARGET): dns64server.cpp config_load.cpp config_module.cpp header.h
	$(CXX) $(CXXFLAGS) -o $(TARGET) dns64server.cpp config_load.cpp config_module.cpp

distclean: clean

clean:
	$(RM) $(TARGET)

