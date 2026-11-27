#ifndef SEAHORSE_RATE_LIMITER_H
#define SEAHORSE_RATE_LIMITER_H
// =============================================================================
// FailureThrottle -- failed-attempt counter with temporary lockout.
//
// Used to stop online password guessing against /api/auth/login (and to stop a
// single peer from burning server CPU on PBKDF2). Keyed by an arbitrary string
// (peer IP, normalised username). Header-only, no dependencies, and the clock
// is injected (now_ms is a parameter) so the behaviour is unit-testable
// without sleeping. Thread-safe.
//
// Semantics:
//   * record_failure(): N failures inside `window_ms` => key locked for
//     `lockout_ms`. Failures while locked do not extend the lock.
//   * retry_after_ms(): 0 = attempt allowed; >0 = ms until the lock expires.
//     Callers MUST check this BEFORE doing expensive work (password hashing).
//   * record_success(): clears the key's failure history.
//   * max_failures == 0 disables the throttle (always allowed).
//   * Memory is bounded by max_keys: expired entries are swept first, then the
//     least-recently-seen entry is evicted.
// =============================================================================
#include <cstdint>
#include <cstddef>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>

class FailureThrottle {
public:
    struct Config {
        size_t  max_failures = 5;          // failures within window that trigger a lock (0 = disabled)
        int64_t window_ms    = 300000;     // 5 min
        int64_t lockout_ms   = 300000;     // 5 min
        size_t  max_keys     = 10000;      // memory bound
    };

    FailureThrottle() = default;
    explicit FailureThrottle(const Config& c) : cfg_(c) {}

    // 0 => allowed. >0 => locked; value is ms remaining.
    int64_t retry_after_ms(const std::string& key, int64_t now_ms) {
        if (cfg_.max_failures == 0) return 0;
        std::lock_guard<std::mutex> g(m_);
        auto it = map_.find(key);
        if (it == map_.end()) return 0;
        if (it->second.locked_until > now_ms) return it->second.locked_until - now_ms;
        return 0;
    }

    void record_failure(const std::string& key, int64_t now_ms) {
        if (cfg_.max_failures == 0) return;
        std::lock_guard<std::mutex> g(m_);
        auto it = map_.find(key);
        if (it == map_.end()) {
            if (map_.size() >= cfg_.max_keys) make_room_locked(now_ms);
            it = map_.emplace(key, Entry{}).first;
        }
        Entry& e = it->second;
        e.last_seen = now_ms;
        if (e.locked_until > now_ms) return;          // already locked: do not extend
        while (!e.fails.empty() && now_ms - e.fails.front() >= cfg_.window_ms)
            e.fails.pop_front();
        e.fails.push_back(now_ms);
        if (e.fails.size() >= cfg_.max_failures) {
            e.locked_until = now_ms + cfg_.lockout_ms;
            e.fails.clear();
        }
    }

    void record_success(const std::string& key) {
        std::lock_guard<std::mutex> g(m_);
        map_.erase(key);
    }

    size_t tracked_keys() const {
        std::lock_guard<std::mutex> g(m_);
        return map_.size();
    }

    // Normalise a user-supplied identifier into a bounded, case-insensitive key.
    static std::string normalize_key(const std::string& s) {
        std::string k = s.substr(0, 128);
        for (auto& c : k) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        return k;
    }

private:
    struct Entry {
        std::deque<int64_t> fails;
        int64_t locked_until = 0;
        int64_t last_seen    = 0;
    };

    bool is_dead(const Entry& e, int64_t now_ms) const {
        if (e.locked_until > now_ms) return false;
        return e.fails.empty() || now_ms - e.fails.back() >= cfg_.window_ms;
    }

    void make_room_locked(int64_t now_ms) {
        for (auto it = map_.begin(); it != map_.end();) {
            if (is_dead(it->second, now_ms)) it = map_.erase(it); else ++it;
        }
        if (map_.size() < cfg_.max_keys) return;
        auto oldest = map_.begin();
        for (auto it = map_.begin(); it != map_.end(); ++it)
            if (it->second.last_seen < oldest->second.last_seen) oldest = it;
        if (oldest != map_.end()) map_.erase(oldest);
    }

    Config cfg_;
    mutable std::mutex m_;
    std::unordered_map<std::string, Entry> map_;
};

#endif
