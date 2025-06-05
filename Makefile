# Makefile for UDP Docker Bug Reproduction Test

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -g
LDFLAGS = -pthread

PROGRAM = bin/minimal_udp_bug_repro
SOURCE = minimal_udp_bug_repro.cpp

all: $(PROGRAM)

bin:
	mkdir -p bin

$(PROGRAM): $(SOURCE) | bin
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -rf bin

.PHONY: all clean 