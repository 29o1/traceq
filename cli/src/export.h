#pragma once

#include <traceq/ingest.h>
#include <cstdint>
#include <cstdio>

namespace gt {

// Exporters return UINT64_MAX on a decode failure; streamed output may contain
// a prefix, which the caller must not present as a successful complete export.
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
                      uint64_t* stop_event = nullptr);

// --context support for hit queries: the bounded instruction window
// [ev - span, ev + span] rendered through the export path (compact text rows
// with module headers, or a JSON array of jsonl row objects). Returns false
// on stream creation or decode failure. No meta trailer or continuation cursor.
bool render_context(const GtbFile& file, uint64_t ev, uint64_t span,
                    bool json, std::string& out);

} // namespace gt
