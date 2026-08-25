#pragma once
// Internal dual-mode (text / JSON) output plumbing for the gt CLI.
//
// The consumer of `gt` is an agent with a bounded context window, so every
// bounded query returns one standard JSON document with `data` and `meta`;
// text mode keeps the
// "... [N more rows truncated]" marker plus "next:" (copy-executable
// continuation).
//
// Value convention for JSON: integer values (including u128 SIMD memory
// values) ride in hex strings ("val":"0x1ff") so they survive precision loss;
// indices and counts
// (ev, total, shown, ...) stay decimal numbers.
//
// This header deliberately lives in src/, not include/: it is CLI glue, not
// part of the reusable libtraceq API.
#include <cstdint>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

namespace gt {
namespace emit {

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

inline std::string hex128(unsigned __int128 v) {
    static const char digits[] = "0123456789abcdef";
    char b[34];
    char* p = b + sizeof b;
    do {
        *--p = digits[uint8_t(v & 0xf)];
        v >>= 4;
    } while (v);
    *--p = 'x';
    *--p = '0';
    return std::string(p, b + sizeof b);
}

// key/value joiners: append "\"key\":value" (no leading comma) to a JSON
// object body being assembled in `out`.
inline void kv_hex(std::string& out, const char* key, uint64_t v) {
    char b[64];
    snprintf(b, sizeof b, "\"%s\":\"0x%llx\"", key, (unsigned long long)v);
    out += b;
}
inline void kv_hex128(std::string& out, const char* key, unsigned __int128 v) {
    out.push_back('"');
    out += key;
    out += "\":\"";
    out += hex128(v);
    out.push_back('"');
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
    uint64_t total = 0;              // primary result items in the answer
    uint64_t shown = 0;              // primary result items represented
    std::string next;                // full continuation command ("" = none)
};

inline void meta_append(std::string& s, const Meta& m) {
    s += "{\"truncated\":";
    s += m.truncated ? "true" : "false";
    char b[96];
    snprintf(b, sizeof b, ",\"total\":%llu,\"shown\":%llu,\"next\":",
             (unsigned long long)m.total, (unsigned long long)m.shown);
    s += b;
    if (m.next.empty()) s += "null";
    else esc_append(s, m.next.c_str());
    s += '}';
}

// Query JSON is buffered until finish() so a validation/scan failure never
// leaves a syntactically incomplete document on stdout. List results are
// bounded by command limits; snapshot and aggregate sizes come from their
// explicit selectors or command-specific controls. Large unbounded streams use
// export --format jsonl instead.
class QueryWriter {
public:
    explicit QueryWriter(bool json, FILE* out = stdout) : json_(json), out_(out) {}

    bool json() const { return json_; }

    void row(std::string row) {
        if (json_) rows_.push_back(std::move(row));
    }

    void finish(const Meta& m) {
        if (!json_) {
            if (m.total > m.shown)
                fprintf(out_, "... [%llu more rows truncated]\n",
                        (unsigned long long)(m.total - m.shown));
            if (!m.next.empty()) fprintf(out_, "next: %s\n", m.next.c_str());
            return;
        }
        fputs("{\"data\":[", out_);
        for (size_t i = 0; i < rows_.size(); i++) {
            if (i) fputc(',', out_);
            fwrite(rows_[i].data(), 1, rows_[i].size(), out_);
        }
        std::string tail = "],\"meta\":";
        meta_append(tail, m);
        tail += "}\n";
        fwrite(tail.data(), 1, tail.size(), out_);
    }

private:
    bool json_;
    FILE* out_;
    std::vector<std::string> rows_;
};

// Trailing footer for JSONL export. Query commands use QueryWriter instead.
// Text mode: the
// print_truncated marker ("... [N more rows truncated]") when rows were cut,
// plus "next: <cmd>" when present.
inline void finish(const Meta& m, bool json, FILE* out) {
    if (json) {
        std::string s = "{\"meta\":";
        meta_append(s, m);
        s += "}\n";
        fwrite(s.data(), 1, s.size(), out);
        return;
    }
    if (m.total > m.shown)
        fprintf(out, "... [%llu more rows truncated]\n",
                (unsigned long long)(m.total - m.shown));
    if (!m.next.empty()) fprintf(out, "next: %s\n", m.next.c_str());
}

inline void finish(const Meta& m, bool json) { finish(m, json, stdout); }

} // namespace emit
} // namespace gt
