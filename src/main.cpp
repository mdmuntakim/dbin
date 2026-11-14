// dbin: binary inventory + reassemblable assembly dumper.
// SPDX-License-Identifier: MIT
#include "dbin.hpp"
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <chrono>
#include <set>

static std::string basenameOf(const std::string& p) {
    size_t k = p.find_last_of('/');
    return k == std::string::npos ? p : p.substr(k + 1);
}

static std::string outNameFor(const std::string& input, const std::string& member, bool fromArchive) {
    std::string base = basenameOf(input);
    size_t dot = base.find_last_of('.');
    std::string stem = (dot != std::string::npos && dot > 0) ? base.substr(0, dot) : base;
    if (fromArchive) {
        std::string m = member;
        size_t md = m.find_last_of('.');
        std::string ms = (md != std::string::npos && md > 0) ? m.substr(0, md) : m;
        return stem + "-" + ms + ".s";
    }
    return stem + ".s";
}

struct Module {
    std::string name;      // display name
    uint64_t off = 0, size = 0;
    bool fromArchive = false;
};

struct Result {
    std::string name, outFile, kind;
    uint64_t size = 0;
    int sections = 0;
    bool ok = false;
    std::string error;
    std::string stats;
};

static std::string jsonEsc(const std::string& s) {
    std::string o;
    for (char ch : s) {
        if (ch == '"' || ch == '\\') { o += '\\'; o += ch; }
        else if (ch < 0x20) { char b[8]; snprintf(b, sizeof b, "\\u%04x", ch); o += b; }
        else o += ch;
    }
    return o;
}

static void printUsage() {
    fprintf(stderr,
        "usage: dbin [--json] [--outdir DIR] [--no-disasm] <file>\n"
        "  inventory a binary (ELF 32/64 both endians, .a archives) and emit one\n"
        "  reassemblable .s per object module into DIR (default dbin_out).\n");
}

int main(int argc, char** argv) {
    std::string input, outdir = "dbin_out";
    bool json = false, noDisasm = false;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--json") json = true;
        else if (a == "--outdir" && i + 1 < argc) outdir = argv[++i];
        else if (a == "--no-disasm") noDisasm = true;
        else if (a == "-h" || a == "--help") { printUsage(); return 0; }
        else if (!a.empty() && a[0] == '-' && a != "-") { fprintf(stderr, "dbin: unknown option %s\n", a.c_str()); printUsage(); return 2; }
        else { if (!input.empty()) { fprintf(stderr, "dbin: multiple inputs\n"); return 2; } input = a; }
    }
    if (input.empty()) { printUsage(); return 2; }

    auto t0 = std::chrono::steady_clock::now();

    // ensure outdir exists
    mkdir(outdir.c_str(), 0777);

    int fd = open(input.c_str(), O_RDONLY);
    if (fd < 0) {
        std::string msg = "cannot open " + input + ": " + strerror(errno);
        if (json) printf("{\"error\":\"%s\",\"ok\":false}\n", jsonEsc(msg).c_str());
        else fprintf(stderr, "dbin: %s\n", msg.c_str());
        return 1;
    }
    struct stat st{};
    if (fstat(fd, &st) != 0 || st.st_size <= 0) {
        if (json) printf("{\"error\":\"empty or unreadable file\",\"ok\":false}\n");
        else fprintf(stderr, "dbin: empty or unreadable file\n");
        close(fd);
        return 1;
    }
    uint64_t fsize = (uint64_t)st.st_size;
    const uint8_t* base = (const uint8_t*)mmap(nullptr, fsize, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (base == MAP_FAILED) {
        if (json) printf("{\"error\":\"mmap failed\",\"ok\":false}\n");
        else fprintf(stderr, "dbin: mmap failed\n");
        return 1;
    }

    // module discovery
    std::vector<Module> modules;
    std::string topErr;
    bool isArchive = fsize >= 8 && memcmp(base, "!<arch>\n", 8) == 0;
    bool isElf = fsize >= 4 && memcmp(base, "\x7f" "ELF", 4) == 0;

    if (isArchive) {
        std::vector<ArchiveMember> members;
        std::string err;
        if (!parseArchive(base, fsize, members, err)) {
            topErr = "archive parse failed: " + err;
        } else if (members.empty()) {
            topErr = "archive has no data members";
        } else {
            for (auto& m : members) {
                if (m.size < 4 || memcmp(base + m.offset, "\x7f" "ELF", 4) != 0) {
                    topErr = "archive member \"" + m.name + "\" is not an ELF object (unsupported member format)";
                    modules.clear();
                    break;
                }
                modules.push_back({m.name, m.offset, m.size, true});
            }
        }
    } else if (isElf) {
        modules.push_back({basenameOf(input), 0, fsize, false});
    } else {
        topErr = "unsupported format: not ELF and not an ar archive (magic not recognized)";
    }

    std::vector<Result> results;
    bool anyModule = false;
    int totalSections = 0;
    std::string fmtDesc, archDesc, endianDesc;
    int bits = 0;

    if (topErr.empty()) {
        anyModule = true;
        std::set<std::string> outs;
        for (auto& m : modules) {
            Result r; r.name = m.name; r.size = m.size; r.outFile = "";
            ElfImage e;
            if (!parseElfInto(e, base + m.off, m.size)) {
                r.error = e.error;
                results.push_back(std::move(r));
                continue;
            }
            r.kind = elfTypeName(e.etype);
            r.sections = (int)e.sections.size();
            totalSections += r.sections;
            if (bits == 0) {
                bits = e.bits;
                endianDesc = e.be ? "big" : "little";
                archDesc = archName(e.machine);
                fmtDesc = "ELF" + std::to_string(e.bits) + " " + (e.be ? "MSB" : "LSB") + " " + elfTypeName(e.etype);
            }
            if (noDisasm) { r.ok = true; results.push_back(std::move(r)); continue; }
            std::string outName = outNameFor(input, m.name, m.fromArchive);
            // avoid collisions
            while (!outs.insert(outName).second) outName = "x_" + outName;
            std::string path = outdir + "/" + outName;
            std::string err, stats;
            if (emitModuleS(e, m.name, path, err, stats)) {
                r.ok = true; r.outFile = path; r.stats = stats;
            } else {
                r.error = err;
            }
            results.push_back(std::move(r));
        }
    }

    auto t1 = std::chrono::steady_clock::now();
    double secs = std::chrono::duration<double>(t1 - t0).count();

    int rc = 0;
    if (!topErr.empty()) rc = 1;
    for (auto& r : results) if (!r.ok) rc = 1;

    if (json) {
        printf("{\n");
        printf("  \"file\": \"%s\",\n", jsonEsc(basenameOf(input)).c_str());
        printf("  \"format\": \"%s\",\n", jsonEsc(topErr.empty() ? fmtDesc : "unknown").c_str());
        printf("  \"architecture\": \"%s\",\n", jsonEsc(archDesc).c_str());
        printf("  \"bits\": %d,\n", bits);
        printf("  \"endian\": \"%s\",\n", jsonEsc(endianDesc).c_str());
        printf("  \"sections\": %d,\n", totalSections);
        printf("  \"modules\": %zu,\n", modules.size());
        printf("  \"errors\": [%s],\n", (topErr.empty() ? std::string() : "\"" + jsonEsc(topErr) + "\"").c_str());
        printf("  \"outputs\": [\n");
        bool first = true;
        for (auto& r : results) {
            if (r.outFile.empty()) continue;
            if (!first) printf(",\n");
            first = false;
            printf("    {\"module\": \"%s\", \"file\": \"%s\", \"stats\": \"%s\"}",
                   jsonEsc(r.name).c_str(), jsonEsc(r.outFile).c_str(), jsonEsc(r.stats).c_str());
        }
        printf("\n  ],\n");
        printf("  \"time_seconds\": %.3f,\n", secs);
        printf("  \"ok\": %s\n", rc == 0 ? "true" : "false");
        printf("}\n");
    } else {
        printf("dbin: %s\n", basenameOf(input).c_str());
        if (!topErr.empty()) {
            printf("  ERROR: %s\n", topErr.c_str());
        } else {
            printf("  format: %s, %s\n", fmtDesc.c_str(), archDesc.c_str());
            printf("  sections: %d\n", totalSections);
            printf("  modules: %zu\n", modules.size());
            for (size_t i = 0; i < modules.size() && i < results.size(); i++) {
                auto& m = modules[i]; auto& r = results[i];
                printf("    [%zu] %-28s size=%-10llu type=%-12s", i, m.name.c_str(),
                       (unsigned long long)m.size, r.kind.c_str());
                if (r.ok) {
                    if (!r.outFile.empty()) printf(" -> %s", r.outFile.c_str());
                    printf("\n");
                    if (!r.stats.empty()) printf("        %s\n", r.stats.c_str());
                } else {
                    printf(" ERROR: %s\n", r.error.c_str());
                }
            }
            printf("  time: %.2fs\n", secs);
        }
    }

    munmap((void*)base, fsize);
    return rc;
}
