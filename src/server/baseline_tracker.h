#ifndef BASELINE_TRACKER_H
#define BASELINE_TRACKER_H

// =============================================================================
// SecureSeaHorse SIEM — Phase 4: Adaptive Baseline Tracker
// =============================================================================
// Provides:
//   - Exponentially Weighted Moving Average (EWMA) per metric per device
//   - Running standard deviation estimate
//   - Z-score anomaly scoring
//   - Configurable learning rate (alpha) and anomaly threshold (z)
//   - Warm-up period to avoid false positives on cold start
// =============================================================================

#include <cmath>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

// =============================================================================
// EWMA METRIC — Tracks a single scalar metric
// =============================================================================
struct EwmaMetric {
    double mean     = 0.0;      // Exponentially weighted mean
    double variance = 0.0;      // Exponentially weighted variance
    double alpha    = 0.05;     // Learning rate (0.01 = slow adapt, 0.1 = fast)
    int    samples  = 0;        // Total observations seen
    int    warmup   = 20;       // Minimum samples before baselines are trusted
    double last_value = 0.0;    // Most recent raw observation

    EwmaMetric() = default;
    EwmaMetric(double a, int w) : alpha(a), warmup(w) {}

    /// Feed a new observation. Updates mean and variance.
    void update(double value) {
        last_value = value;
        samples++;

        if (samples == 1) {
            // First sample — initialize
            mean     = value;
            variance = 0.0;
            return;
        }

        double diff    = value - mean;
        double incr    = alpha * diff;
        mean          += incr;
        variance       = (1.0 - alpha) * (variance + alpha * diff * diff);
    }

    /// Standard deviation (sqrt of EWMA variance)
    double stddev() const {
        return std::sqrt(std::max(variance, 0.0));
    }

    /// Z-score: how many standard deviations the last value is from mean.
    /// Returns 0.0 during warmup period.
    double z_score() const {
        if (samples < warmup) return 0.0;
        double sd = stddev();
        if (sd < 1e-9) return 0.0;  // Avoid division by zero
        return (last_value - mean) / sd;
    }

    /// Z-score for an arbitrary value (not the last observation)
    double z_score_of(double value) const {
        if (samples < warmup) return 0.0;
        double sd = stddev();
        if (sd < 1e-9) return 0.0;
        return (value - mean) / sd;
    }

    /// Is baseline warmed up and trustworthy?
    bool is_ready() const { return samples >= warmup; }
};

// =============================================================================
// DEVICE BASELINE — All tracked metrics for a single device
// =============================================================================
struct DeviceBaseline {
    // --- Network metrics (deltas per reporting interval) ---
    EwmaMetric net_bytes_in_rate;    // Bytes/interval inbound
    EwmaMetric net_bytes_out_rate;   // Bytes/interval outbound
    EwmaMetric net_in_out_ratio;     // in/out ratio (exfil detection)

    // --- System metrics ---
    EwmaMetric cpu_usage;            // CPU percent
    EwmaMetric ram_usage_pct;        // RAM used percent

    // --- Security event rates ---
    EwmaMetric auth_failure_rate;    // Auth failures per interval
    EwmaMetric total_event_rate;     // Total security events per interval

    // --- Timing ---
    EwmaMetric report_interval_ms;   // Time between consecutive reports (beaconing)

    // --- Previous raw values for delta computation ---
    uint64_t prev_net_bytes_in  = 0;
    uint64_t prev_net_bytes_out = 0;
    int64_t  prev_timestamp_ms  = 0;
    bool     has_prev           = false;

    // Initialize all metrics with the same alpha and warmup
    void init(double alpha, int warmup) {
        net_bytes_in_rate  = EwmaMetric(alpha, warmup);
        net_bytes_out_rate = EwmaMetric(alpha, warmup);
        net_in_out_ratio   = EwmaMetric(alpha, warmup);
        cpu_usage          = EwmaMetric(alpha, warmup);
        ram_usage_pct      = EwmaMetric(alpha, warmup);
        auth_failure_rate  = EwmaMetric(alpha, warmup);
        total_event_rate   = EwmaMetric(alpha, warmup);
        report_interval_ms = EwmaMetric(alpha, warmup);
    }
};

// =============================================================================
// BASELINE TRACKER — Manages baselines for all devices
// =============================================================================
class BaselineTracker {
public:
    struct Config {
        double alpha  = 0.05;   // EWMA learning rate
        int    warmup = 20;     // Samples before baselines are trusted

        // Anomaly z-score thresholds (how many stddevs = anomaly)
        double z_high     = 3.0;   // High confidence anomaly
        double z_medium   = 2.5;   // Medium confidence
        double z_low      = 2.0;   // Low confidence (informational)
    };

    explicit BaselineTracker(const Config& cfg = {}) : config_(cfg) {}

    // -------------------------------------------------------------------------
    // UPDATE: Feed a new telemetry report and compute deltas
    // Returns the DeviceBaseline (after update) for the classifier to inspect
    // -------------------------------------------------------------------------
    DeviceBaseline& update(int32_t device_id,
                           int64_t timestamp_ms,
                           uint64_t net_bytes_in,
                           uint64_t net_bytes_out,
                           double cpu_pct,
                           double ram_pct,
                           int auth_failures,
                           int total_events)
    {
        std::lock_guard<std::mutex> lock(mutex_);

        auto& bl = baselines_[device_id];

        // First-time init
        if (!bl.has_prev) {
            bl.init(config_.alpha, config_.warmup);
            bl.prev_net_bytes_in  = net_bytes_in;
            bl.prev_net_bytes_out = net_bytes_out;
            bl.prev_timestamp_ms  = timestamp_ms;
            bl.has_prev = true;

            // Feed initial system metrics
            bl.cpu_usage.update(cpu_pct);
            bl.ram_usage_pct.update(ram_pct);
            return bl;
        }

        // --- Compute deltas ---
        // Network deltas (handle counter wraps gracefully)
        double delta_in  = 0.0;
        double delta_out = 0.0;
        if (net_bytes_in >= bl.prev_net_bytes_in)
            delta_in = static_cast<double>(net_bytes_in - bl.prev_net_bytes_in);
        if (net_bytes_out >= bl.prev_net_bytes_out)
            delta_out = static_cast<double>(net_bytes_out - bl.prev_net_bytes_out);

        // Time delta
        double dt_ms = static_cast<double>(timestamp_ms - bl.prev_timestamp_ms);
        if (dt_ms < 1.0) dt_ms = 1.0;  // Prevent division by zero

        // Update baselines
        bl.net_bytes_in_rate.update(delta_in);
        bl.net_bytes_out_rate.update(delta_out);

        // In/out ratio (protect against zero outbound)
        double ratio = (delta_out > 1.0) ? (delta_in / delta_out) : 0.0;
        bl.net_in_out_ratio.update(ratio);

        bl.cpu_usage.update(cpu_pct);
        bl.ram_usage_pct.update(ram_pct);
        bl.auth_failure_rate.update(static_cast<double>(auth_failures));
        bl.total_event_rate.update(static_cast<double>(total_events));
        bl.report_interval_ms.update(dt_ms);

        // Store current as previous for next delta
        bl.prev_net_bytes_in  = net_bytes_in;
        bl.prev_net_bytes_out = net_bytes_out;
        bl.prev_timestamp_ms  = timestamp_ms;

        return bl;
    }

    // -------------------------------------------------------------------------
    // QUERY: Get baseline for a specific device (read-only copy)
    // -------------------------------------------------------------------------
    bool get_baseline(int32_t device_id, DeviceBaseline& out) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = baselines_.find(device_id);
        if (it == baselines_.end()) return false;
        out = it->second;
        return true;
    }

    // -------------------------------------------------------------------------
    // CLASSIFY Z-SCORE into severity tier
    // -------------------------------------------------------------------------
    std::string z_to_severity(double z) const {
        double abs_z = std::abs(z);
        if (abs_z >= config_.z_high)   return "critical";
        if (abs_z >= config_.z_medium) return "high";
        if (abs_z >= config_.z_low)    return "medium";
        return "";  // Below threshold — not anomalous
    }

    // -------------------------------------------------------------------------
    // COMPUTE CONFIDENCE from z-score (0.0 to 1.0 scale)
    // -------------------------------------------------------------------------
    double z_to_confidence(double z) const {
        double abs_z = std::abs(z);
        if (abs_z < config_.z_low) return 0.0;
        // Linear scale: z_low=0.3, z_high=0.9, beyond=0.95
        double conf = 0.3 + (abs_z - config_.z_low) / (config_.z_high - config_.z_low) * 0.6;
        return std::min(conf, 0.95);
    }

    const Config& config() const { return config_; }

    size_t device_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return baselines_.size();
    }

private:
    Config config_;
    mutable std::mutex mutex_;
    std::map<int32_t, DeviceBaseline> baselines_;
};

#endif
