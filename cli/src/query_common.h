#pragma once

#include <traceq/ingest.h>
#include <cstdint>
#include <cstdio>
#include <string>

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
