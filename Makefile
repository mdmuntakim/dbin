CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2 -flto -ffunction-sections -fdata-sections -Wall -Wextra
LDFLAGS ?= -flto -Wl,--gc-sections -s
SRCS := src/main.cpp src/elf.cpp src/x86.cpp src/a64.cpp src/arm.cpp src/emit.cpp src/util.cpp
OBJS := $(SRCS:.cpp=.o)

dbin: $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS) $(LDFLAGS)

static: $(OBJS)
	$(CXX) $(CXXFLAGS) -static -o dbin $(OBJS) $(LDFLAGS)

%.o: %.cpp src/dbin.hpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f dbin $(OBJS)

.PHONY: clean static
