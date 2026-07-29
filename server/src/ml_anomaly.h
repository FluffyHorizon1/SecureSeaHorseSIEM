// =============================================================================
// ml_anomaly.h -- Phase 24 (v4.5.0)
// -----------------------------------------------------------------------------
// Pure-C++ anomaly detectors. Two orthogonal techniques — isolation forest
// for per-device numeric-feature anomalies (CPU, RAM, network, disk IOPS)
// and a periodogram-based beaconing scorer that flags regular C2 heartbeats
// hidden in connection timing.
//
// No Python, no ONNX, no external ML runtimes. Both models are small enough
// to train in-process on a rolling 7-day window and re-score incoming events
// at ingestion latency.
// =============================================================================
#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <unordered_map>
#include <vector>

namespace seahorse::ml {

// ------------------ Isolation Forest (per-device telemetry) ------------------

struct FeatureVector {
    int    device_id = 0;
    std::chrono::system_clock::time_point ts;
    double cpu_pct = 0.0;
    double ram_pct = 0.0;
    double disk_iops = 0.0;
    double net_in_bytes = 0.0;
    double net_out_bytes = 0.0;
    double event_rate = 0.0;        // security events / minute
    double failed_login_rate = 0.0;
};

class IsolationTree;   // impl detail

class IsolationForest {
public:
    IsolationForest(int num_trees = 100, int subsample_size = 256, int max_depth = 12);

    // Incremental training. Adds `v` to a ring buffer; re-fit fires whenever
    // the buffer crosses a re-fit threshold (every 500 samples, configurable).
    void observe(const FeatureVector& v);

    // Returns anomaly score in [0, 1]. >= 0.6 is interesting, >= 0.75 fires
    // an alert in the default server.conf.
    double score(const FeatureVector& v) const;

    // Called by Phase 18 report generator to summarize the week.
    struct ModelSnapshot {
        int    num_trees = 0;
        int    samples_observed = 0;
        double mean_score = 0.0;
        std::chrono::system_clock::time_point last_fit;
    };
    ModelSnapshot snapshot() const;

private:
    int num_trees_;
    int subsample_;
    int max_depth_;
    std::vector<std::shared_ptr<IsolationTree>> trees_;
    std::deque<FeatureVector> buffer_;
    mutable std::mutex        mtx_;
    std::mt19937              rng_;
    int                       observed_since_fit_ = 0;

    void fit_locked();
};

// --------------------- Beaconing Detector (periodogram) ---------------------

struct BeaconCandidate {
    int         device_id = 0;
    std::string remote_ip;
    int         remote_port = 0;
    double      period_seconds = 0.0;       // best-guess interval
    double      confidence = 0.0;           // 0..1, signal strength
    int         observation_count = 0;
    std::chrono::system_clock::time_point first_seen;
    std::chrono::system_clock::time_point last_seen;
};

class BeaconingDetector {
public:
    // Connection timestamps are appended per (device, remote) flow. We keep
    // the last 512 timestamps per flow; a sparse periodogram is computed over
    // the inter-arrival series whenever a flow has ≥ 16 observations.
    void observe(int device_id,
                 const std::string& remote_ip, int remote_port,
                 std::chrono::system_clock::time_point ts);

    // Periodic scan — invoked by a scheduler thread every 5 minutes.
    std::vector<BeaconCandidate> scan();

private:
    struct FlowSeries {
        std::deque<std::chrono::system_clock::time_point> ts;
        std::chrono::system_clock::time_point             first_seen;
    };
    std::unordered_map<std::string, FlowSeries> flows_;
    mutable std::mutex mtx_;

    static std::pair<double,double> best_period(const std::deque<std::chrono::system_clock::time_point>& ts);
};

} // namespace seahorse::ml
