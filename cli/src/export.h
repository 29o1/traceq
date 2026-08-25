#pragma once

#include <traceq/ingest.h>
#include <cstdint>
#include <cstdio>

namespace gt {

uint64_t export_upstream(const GtbFile& file, FILE* out,
                         uint64_t from_idx = 0,
                         uint64_t to_idx = UINT64_MAX,
                         uint64_t max_lines = 0,
                         uint64_t* stop_event = nullptr);

uint64_t export_compact(const GtbFile& file, FILE* out,
                        uint64_t from_idx = 0,
                        uint64_t to_idx = UINT64_MAX,
                        uint64_t max_lines = 0,
                        uint64_t* stop_event = nullptr);

uint64_t export_jsonl(const GtbFile& file, FILE* out,
                      uint64_t from_idx = 0,
                      uint64_t to_idx = UINT64_MAX,
                      uint64_t max_lines = 0,
                      uint64_t* stop_event = nullptr,
                      uint64_t* total_selected = nullptr);

} // namespace gt
