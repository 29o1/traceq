#pragma once

#include <traceq/ingest.h>
#include <cstdint>
#include <cstdio>
#include <string>

inline std::string shell_arg(const std::string& value) {
    if (!value.empty() && value.find_first_not_of(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./:-") ==
            std::string::npos)
        return value;
    std::string quoted = "'";
    for (char c : value) {
        if (c == '\'') quoted += "'\\''";
        else quoted += c;
    }
    return quoted + '\'';
}

inline int scan_error(const std::string& path,
                      const char* reason = "corrupt EVENTS payload") {
    fprintf(stderr, "scan failed: %s: %s\n", path.c_str(), reason);
    return 1;
}

// Load with a path-qualified diagnostic: "load failed: <path>: <reason>".
// Agents wasted multiple retries on the old bare "load failed" when the real
// cause was a cwd-relative path or a non-GTB2 file.
inline bool load_query_file(gt::GtbFile& file, const std::string& path) {
    std::string reason;
    if (file.load(path, &reason)) return true;
    fprintf(stderr, "load failed: %s: %s\n", path.c_str(), reason.c_str());
    return false;
}

inline std::string query_at(const gt::GtbFile& file, uint32_t site_id) {
    if (site_id == UINT32_MAX) return "<event>";
    const gt::Site& site = file.arena.get(site_id);
    char location[320];
    if (site.module_id < file.arena.modules().size())
        snprintf(location, sizeof location, "%s!0x%llx",
                 file.arena.modules()[site.module_id].c_str(),
                 (unsigned long long)(site.addr -
                                      file.arena.module_base(site.module_id)));
    else
        snprintf(location, sizeof location, "0x%llx",
                 (unsigned long long)site.addr);
    return location;
}
