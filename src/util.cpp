// name helpers
// SPDX-License-Identifier: MIT
#include "dbin.hpp"

std::string archName(uint16_t machine) {
    switch (machine) {
        case 3: return "i386";
        case 8: return "mips";
        case 20: return "powerpc";
        case 21: return "powerpc64";
        case 40: return "arm";
        case 50: return "ia64";
        case 62: return "x86-64";
        case 183: return "aarch64";
        case 243: return "riscv";
        case 244: return "bpf";
        default: { char b[32]; snprintf((char*)b, sizeof b, "machine %u", machine); return b; }
    }
}

std::string elfTypeName(uint16_t t) {
    switch (t) {
        case 0: return "none";
        case 1: return "relocatable";
        case 2: return "executable";
        case 3: return "shared";
        case 4: return "core";
        default: return "etype " + std::to_string(t);
    }
}
