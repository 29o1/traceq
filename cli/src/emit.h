#pragma once
// Internal dual-mode (text / JSON Lines) output plumbing for the gt CLI.
//
// The consumer of `gt` is an agent with a bounded context window, so every
// bounded output ends in a machine-parseable trailer: JSON mode gets a
// {"meta":{...}} line as the last line, text mode keeps the
// "... [N more rows truncated]" marker plus "next:" (copy-executable
// continuation) and "# suggest:" lines.
//
// Value convention for JSON Lines: u64 values ride in hex strings
// ("val":"0x1ff") so they survive double precision loss; indices and counts
// (ev, total, shown, ...) stay decimal numbers.
//
// This header deliberately lives in src/, not include/: it is CLI glue, not
// part of the reusable libtraceq API.
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace gt {
namespace emit {

// --json mode flag, set by the command dispatcher after argv parsing. The
// default finish() overload reads it; query entry points take an explicit
// bool instead so in-process tests (bench selftest) can pick the mode per
// call.
inline bool json_mode = false;

// JSON string escaping (RFC 8259): quotes, backslash, control characters.
inline void esc_append(std::string& out, const char* s) {
    out.push_back('"');
    for (const char* p = s; *p; p++) {
        unsigned char c = (unsigned char)*p;
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (c < 0x20) {
                char b[8];
                snprintf(b, sizeof b, "\\u%04x", c);
                out += b;
            } else {
                out.push_back(char(c));
            }
        }
    }
    out.push_back('"');
}

inline std::string hex64(uint64_t v) {
    char b[24];
    snprintf(b, sizeof b, "0x%llx", (unsigned long long)v);
    return b;
}

// key/value joiners: append "\"key\":value" (no leading comma) to a JSON
// object body being assembled in `out`.
inline void kv_hex(std::string& out, const char* key, uint64_t v) {
    char b[64];
    snprintf(b, sizeof b, "\"%s\":\"0x%llx\"", key, (unsigned long long)v);
    out += b;
}
inline void kv_u64(std::string& out, const char* key, uint64_t v) {
    char b[64];
    snprintf(b, sizeof b, "\"%s\":%llu", key, (unsigned long long)v);
    out += b;
}
inline void kv_bool(std::string& out, const char* key, bool v) {
    out.push_back('"');
    out += key;
    out += "\":";
    out += v ? "true" : "false";
}
inline void kv_str(std::string& out, const char* key, const std::string& v) {
    out.push_back('"');
    out += key;
    out += "\":";
    esc_append(out, v.c_str());
}

// ["0x1","0x2"] / [] — array of hex-string values.
inline std::string hex_array(const std::vector<uint64_t>& vs) {
    std::string s = "[";
    for (size_t i = 0; i < vs.size(); i++) {
        if (i) s += ',';
        s += hex64(vs[i]);
    }
    s += ']';
    return s;
}

// ["a","b"] / [] — array of escaped strings.
inline std::string str_array(const std::vector<std::string>& vs) {
    std::string s = "[";
    for (size_t i = 0; i < vs.size(); i++) {
        if (i) s += ',';
        esc_append(s, vs[i].c_str());
    }
    s += ']';
    return s;
}

struct Meta {
    bool truncated = false;
    uint64_t total = 0;              // rows existing in the answer
    uint64_t shown = 0;              // rows actually emitted
    std::string next;                // full continuation command ("" = none)
    std::vector<std::string> suggest; // filled-in next-step commands
};

// Trailing footer. JSON mode: the {"meta":{...}} line. Text mode: the
// print_truncated marker ("... [N more rows truncated]") when rows were cut,
// plus "next: <cmd>" and "# suggest: <cmd>" lines when present.
inline void finish(const Meta& m, bool json, FILE* out) {    if (json) {
        std::string s = "{\"meta\":{\"truncated\":";
        s += m.truncated ? "true" : "false";
        char b[96];
        snprintf(b, sizeof b, ",\"total\":%llu,\"shown\":%llu,\"next\":",
                 (unsigned long long)m.total, (unsigned long long)m.shown);
        s += b;
        if (m.next.empty()) s += "null";
        else esc_append(s, m.next.c_str());
        s += ",\"suggest\":[";
        for (size_t i = 0; i < m.suggest.size(); i++) {
            if (i) s += ',';
            esc_append(s, m.suggest[i].c_str());
        }
        s += "]}}\n";
        fwrite(s.data(), 1, s.size(), out);
        return;
    }
    if (m.total > m.shown)
        fprintf(out, "... [%llu more rows truncated]\n",
                (unsigned long long)(m.total - m.shown));
    if (!m.next.empty()) fprintf(out, "next: %s\n", m.next.c_str());
    for (const auto& s : m.suggest) fprintf(out, "# suggest: %s\n", s.c_str());
}

inline void finish(const Meta& m, bool json) { finish(m, json, stdout); }
inline void finish(const Meta& m, FILE* out) { finish(m, json_mode, out); }

} // namespace emit
} // namespace gt
