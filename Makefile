CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2 -flto -ffunction-sections -fdata-sections -Wall -Wextra
LDFLAGS ?= -flto -Wl,--gc-sections -s
SRCS := src/main.cpp src/elf.cpp src/x86.cpp src/a64.cpp src/arm.cpp src/emit.cpp src/util.cpp

# Objects live in a per-target directory: a cross build must never reuse a
# host object, a host .o linked into an Android binary is garbage machine code.
BUILD ?= build
OUT ?= dbin
OBJS := $(SRCS:src/%.cpp=$(BUILD)/%.o)

# Android/Termux releases are built against bionic (the NDK), fully static.
# A glibc static binary is *not* usable there: glibc calls rseq(2) while the
# C runtime starts, and the Android seccomp filter traps that syscall, so the
# process dies from SIGSYS (signal 31) before main() runs.
NDK ?= $(if $(ANDROID_NDK_HOME),$(ANDROID_NDK_HOME),$(if $(ANDROID_NDK_ROOT),$(ANDROID_NDK_ROOT),$(lastword $(wildcard /usr/local/lib/android/sdk/ndk/* $(ANDROID_HOME)/ndk/* $(ANDROID_SDK_ROOT)/ndk/*))))
NDK_HOST_TAG ?= linux-x86_64
ANDROID_API ?= 24
NDK_BIN := $(NDK)/toolchains/llvm/prebuilt/$(NDK_HOST_TAG)/bin
ANDROID_ARM64_CXX ?= $(NDK_BIN)/aarch64-linux-android$(ANDROID_API)-clang++
ANDROID_ARM_CXX ?= $(NDK_BIN)/armv7a-linux-androideabi$(ANDROID_API)-clang++
ANDROID_X64_CXX ?= $(NDK_BIN)/x86_64-linux-android$(ANDROID_API)-clang++
ANDROID_LDFLAGS ?= -static -static-libstdc++ -flto -Wl,--gc-sections -s

# Generic Linux aarch64 (glibc).  This is *not* the Termux binary.
LINUX_ARM64_CXX ?= aarch64-linux-gnu-g++
LINUX_ARM64_LDFLAGS ?= -static -flto -Wl,--gc-sections -s

$(BUILD)/%.o: src/%.cpp src/dbin.hpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

all: dbin

dbin: $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS) $(LDFLAGS)

static: $(OBJS)
	$(CXX) $(CXXFLAGS) -static -o dbin $(OBJS) $(LDFLAGS)

# Recursive helpers: each Android ABI gets its own object directory and output.
link: $(OBJS)
	@test -n "$(NDK)" || { echo "error: set ANDROID_NDK_HOME (or NDK=...) to build Android targets" >&2; exit 1; }
	$(CXX) $(CXXFLAGS) -o $(OUT) $(OBJS) $(LDFLAGS)

android-aarch64:
	$(MAKE) BUILD=build/android-aarch64 OUT=dbin-android-aarch64 \
		CXX='$(ANDROID_ARM64_CXX)' LDFLAGS='$(ANDROID_LDFLAGS)' link

android-armv7a:
	$(MAKE) BUILD=build/android-armv7a OUT=dbin-android-armv7a \
		CXX='$(ANDROID_ARM_CXX)' LDFLAGS='$(ANDROID_LDFLAGS)' link

android-x86_64:
	$(MAKE) BUILD=build/android-x86_64 OUT=dbin-android-x86_64 \
		CXX='$(ANDROID_X64_CXX)' LDFLAGS='$(ANDROID_LDFLAGS)' link

android: android-aarch64 android-armv7a android-x86_64

linux-aarch64:
	$(MAKE) BUILD=build/linux-aarch64 OUT=dbin-linux-aarch64 \
		CXX='$(LINUX_ARM64_CXX)' LDFLAGS='$(LINUX_ARM64_LDFLAGS)' link

# Everything a release publishes, built in one go.
release:
	$(MAKE) static
	$(MAKE) android
	$(MAKE) linux-aarch64

clean:
	rm -rf build dbin dbin-android-aarch64 dbin-android-armv7a dbin-android-x86_64 dbin-linux-aarch64

.PHONY: all clean static android android-aarch64 android-armv7a android-x86_64 linux-aarch64 release link
