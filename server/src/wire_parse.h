#ifndef WIRE_PARSE_H
#define WIRE_PARSE_H

// =============================================================================
// SecureSeaHorse SIEM -- Phase 27: safe wire-field parsing
// =============================================================================
// The text report deserializers (process / connection / session / software)
// parse pipe-delimited fields that arrive from a connected agent. A single
// non-numeric field used to reach std::stoi/stoul/stoll/stoull directly, which
// throws std::invalid_argument / std::out_of_range on malformed input. Because
// nothing on the ingest path caught it (dispatcher -> thread-pool task), one
// malformed packet terminated the whole server (std::terminate). See the
// 2026-09-18 review, finding 4.1.
//
// These helpers are the FIM deserializer's discipline (which already used
// try/catch) generalised: never throw, fall back to a caller-supplied default.
// A malformed device_id therefore becomes 0, which every report handler already
// treats as "invalid, skip" -- so a bad report is dropped, not fatal.
// =============================================================================

#include <cstdint>
#include <string>

namespace seahorse {
namespace wire {

inline int32_t to_i32(const std::string& s, int32_t def = 0) noexcept {
    try { return static_cast<int32_t>(std::stol(s)); } catch (...) { return def; }
}

inline int64_t to_i64(const std::string& s, int64_t def = 0) noexcept {
    try { return static_cast<int64_t>(std::stoll(s)); } catch (...) { return def; }
}

inline uint32_t to_u32(const std::string& s, uint32_t def = 0) noexcept {
    try { return static_cast<uint32_t>(std::stoul(s)); } catch (...) { return def; }
}

inline uint64_t to_u64(const std::string& s, uint64_t def = 0) noexcept {
    try { return static_cast<uint64_t>(std::stoull(s)); } catch (...) { return def; }
}

} // namespace wire
} // namespace seahorse

#endif // WIRE_PARSE_H
