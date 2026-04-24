#ifndef ML_ANOMALY_H
#define ML_ANOMALY_H

#ifndef NOMINMAX
#define NOMINMAX
#endif

// =============================================================================
// SecureSeaHorse SIEM -- Phase 24: ML Anomaly Detection (Server-Side)
// =============================================================================
// Provides:
//   - Isolation Forest for multi-dimensional outlier detection on per-device
//     telemetry vectors (CPU, RAM, net_in, net_out, event_rate, auth_fail_rate)
//   - Beaconing scorer: Fourier / autocorrelation-lite pass over outbound
//     connection intervals to flag periodic C2 communication
//   - Pure C++17, no external ML dependencies -- every algorithm is implemented
//     inline so the server continues to have only OpenSSL + libpq as link deps
//   - Per-device rolling windows with thread-safe ingestion
//   - Emits AnomalyFinding objects that the main pipeline converts into
//     ThreatDetection rows and feeds to the correlation + IR engines
//
// Design notes:
//   - The isolation forest uses extended isolation (random hyperplanes rather
//     than axis-aligned splits) because standard iForest biases toward axis
//     boundaries and produces brittle scores on correlated dimensions like
//     (net_in, net_out). Extended iForest handles correlation much better
//     with only a small implementation cost.
//   - Forest retraining happens lazily: every retrain_interval_s, a background
//     tick rebuilds the forest from the rolling window. Training is O(N log N)
//     per tree and typically sub-second for the default window size.
//   - Scoring is always cheap: O(trees * depth).
//
// Mapped to MITRE ATT&CK:
//   - Outlier telemetry -> T1078 (Valid Accounts misuse), T1041 (Exfiltration),
//     or T1496 (Resource Hijacking) depending on which dimension dominates
//   - Beaconing -> T1071 (Application Layer Protocol)
// =============================================================================

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <deque>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <vector>

// =============================================================================
// FEATURE VECTOR -- One sample fed into the forest per telemetry report
// =============================================================================
struct AnomalyFeatures {
    double cpu_pct        = 0.0;   // 0..100
    double ram_pct        = 0.0;   // 0..100
    double net_in_rate    = 0.0;   // bytes / interval
    double net_out_rate   = 0.0;   // bytes / interval
    double event_rate     = 0.0;   // security_events / interval
    double auth_fail_rate = 0.0;   // auth_failures / interval
    double interval_ms    = 0.0;   // time since previous report

    static constexpr int DIM = 7;

    // Pack into fixed-size vector for the forest
    std::vector<double> to_vector() const {
        return {cpu_pct, ram_pct, net_in_rate, net_out_rate,
                event_rate, auth_fail_rate, interval_ms};
    }
};

// =============================================================================
// ANOMALY FINDING -- Output from the detector
// =============================================================================
struct AnomalyFinding {
    int32_t     device_id       = 0;
    int64_t     timestamp_ms    = 0;
    std::string machine_ip;
    std::string detector;        // "iforest" | "beaconing"
    std::string severity;        // "low" | "medium" | "high" | "critical"
    double      score           = 0.0;   // 0..1, higher = more anomalous
    double      confidence      = 0.0;   // 0..1
    std::string mitre_id;
    std::string mitre_tactic;
    std::string description;
    std::string evidence;        // Feature snapshot or interval stats

    // Beaconing-specific (unused for iforest findings)
    double      beacon_period_s = 0.0;
    double      beacon_jitter   = 0.0;
};

// =============================================================================
// EXTENDED ISOLATION TREE
// =============================================================================
// A single tree in the ensemble. Each split is defined by a random hyperplane
// (normal vector + intercept) rather than a single feature/threshold pair.
// This is "Extended Isolation Forest" (Hariri et al., 2018).
// =============================================================================
class IsolationTree {
public:
    struct Node {
        bool   is_leaf = false;
        size_t size    = 0;           // # samples reaching this node (leaves)
        std::vector<double> normal;    // Hyperplane normal (splits only)
        double intercept = 0.0;         // Hyperplane intercept
        std::unique_ptr<Node> left;
        std::unique_ptr<Node> right;
    };

    IsolationTree(int max_depth, int dim, std::mt19937& rng)
        : max_depth_(max_depth), dim_(dim), rng_(rng) {}

    void build(std::vector<std::vector<double>>& samples) {
        root_ = build_node(samples, 0);
    }

    // Path length to isolation -- shorter means more anomalous
    double path_length(const std::vector<double>& x) const {
        return descend(root_.get(), x, 0);
    }

private:
    int max_depth_;
    int dim_;
    std::mt19937& rng_;
    std::unique_ptr<Node> root_;

    std::unique_ptr<Node> build_node(std::vector<std::vector<double>>& samples, int depth) {
        auto node = std::make_unique<Node>();
        if (samples.size() <= 1 || depth >= max_depth_) {
            node->is_leaf = true;
            node->size    = samples.size();
            return node;
        }

        // Pick a random normal vector (Gaussian components, then normalize)
        std::normal_distribution<double> gauss(0.0, 1.0);
        node->normal.resize(dim_);
        double norm = 0.0;
        for (int i = 0; i < dim_; i++) {
            node->normal[i] = gauss(rng_);
            norm += node->normal[i] * node->normal[i];
        }
        norm = std::sqrt(std::max(norm, 1e-12));
        for (int i = 0; i < dim_; i++) node->normal[i] /= norm;

        // Projection range to pick intercept uniformly within bounds
        double min_proj = std::numeric_limits<double>::infinity();
        double max_proj = -std::numeric_limits<double>::infinity();
        for (const auto& s : samples) {
            double p = dot(node->normal, s);
            if (p < min_proj) min_proj = p;
            if (p > max_proj) max_proj = p;
        }

        if (max_proj - min_proj < 1e-9) {
            // All samples collapse to the same point along this normal
            node->is_leaf = true;
            node->size    = samples.size();
            node->normal.clear();
            return node;
        }

        std::uniform_real_distribution<double> U(min_proj, max_proj);
        node->intercept = U(rng_);

        std::vector<std::vector<double>> left, right;
        left.reserve(samples.size() / 2);
        right.reserve(samples.size() / 2);
        for (auto& s : samples) {
            double p = dot(node->normal, s);
            if (p < node->intercept) left.push_back(std::move(s));
            else                     right.push_back(std::move(s));
        }

        if (left.empty() || right.empty()) {
            // Degenerate split -- treat as leaf
            node->is_leaf = true;
            node->size    = samples.size();
            node->normal.clear();
            return node;
        }

        node->left  = build_node(left,  depth + 1);
        node->right = build_node(right, depth + 1);
        return node;
    }

    double descend(const Node* n, const std::vector<double>& x, int depth) const {
        if (!n) return static_cast<double>(depth);
        if (n->is_leaf) {
            return static_cast<double>(depth) + c_factor(n->size);
        }
        double p = dot(n->normal, x);
        return descend((p < n->intercept ? n->left.get() : n->right.get()), x, depth + 1);
    }

    static double dot(const std::vector<double>& a, const std::vector<double>& b) {
        double s = 0.0;
        const size_t n = std::min(a.size(), b.size());
        for (size_t i = 0; i < n; i++) s += a[i] * b[i];
        return s;
    }

    // Average BST path length approximation -- the "c(n)" correction from
    // the original iForest paper so that leaves of a partial tree contribute
    // an unbiased path length estimate.
    static double c_factor(size_t n) {
        if (n <= 1) return 0.0;
        double H = std::log(static_cast<double>(n) - 1.0) + 0.5772156649;  // Harmonic
        return 2.0 * H - (2.0 * (n - 1)) / static_cast<double>(n);
    }
};

// =============================================================================
// ISOLATION FOREST
// =============================================================================
class IsolationForest {
public:
    struct Config {
        int    num_trees     = 64;
        int    subsample     = 256;    // Samples per tree
        int    dim           = AnomalyFeatures::DIM;
        double contamination = 0.01;   // Expected anomaly fraction
        uint32_t seed        = 0;      // 0 = random seed
    };

    explicit IsolationForest(const Config& cfg = {}) : config_(cfg) {
        uint32_t s = config_.seed ? config_.seed
            : static_cast<uint32_t>(std::random_device{}());
        rng_.seed(s);
        max_depth_ = static_cast<int>(std::ceil(std::log2(
            std::max(2, config_.subsample))));
    }

    // Train on a pool of samples. Safe to call repeatedly (replaces the forest).
    void train(const std::vector<std::vector<double>>& pool) {
        if (pool.size() < 2) {
            std::lock_guard<std::mutex> lock(forest_mutex_);
            trees_.clear();
            trained_ = false;
            return;
        }

        std::vector<std::unique_ptr<IsolationTree>> new_trees;
        new_trees.reserve(config_.num_trees);

        std::uniform_int_distribution<size_t> pick(0, pool.size() - 1);
        for (int t = 0; t < config_.num_trees; t++) {
            size_t n = std::min<size_t>(config_.subsample, pool.size());
            std::vector<std::vector<double>> sample;
            sample.reserve(n);
            for (size_t i = 0; i < n; i++) sample.push_back(pool[pick(rng_)]);

            auto tree = std::make_unique<IsolationTree>(max_depth_, config_.dim, rng_);
            tree->build(sample);
            new_trees.push_back(std::move(tree));
        }

        // Swap in new forest atomically
        {
            std::lock_guard<std::mutex> lock(forest_mutex_);
            trees_ = std::move(new_trees);
            trained_ = true;
            training_pool_size_ = pool.size();
        }
    }

    // Score a single feature vector. Returns a value in [0, 1] where 1 = very
    // anomalous and values near 0.5 are average. Score < 0.5 is "normal".
    double score(const std::vector<double>& x) const {
        std::lock_guard<std::mutex> lock(forest_mutex_);
        if (!trained_ || trees_.empty()) return 0.0;

        double sum_path = 0.0;
        for (const auto& tree : trees_) {
            sum_path += tree->path_length(x);
        }
        double avg_path = sum_path / trees_.size();
        double c = IsolationTree_c_factor(config_.subsample);
        if (c < 1e-12) return 0.0;
        return std::pow(2.0, -avg_path / c);
    }

    bool   is_trained() const      { std::lock_guard<std::mutex> lock(forest_mutex_); return trained_; }
    size_t tree_count() const      { std::lock_guard<std::mutex> lock(forest_mutex_); return trees_.size(); }
    size_t training_size() const   { std::lock_guard<std::mutex> lock(forest_mutex_); return training_pool_size_; }
    const Config& config() const   { return config_; }

private:
    Config config_;
    int max_depth_ = 8;
    mutable std::mutex forest_mutex_;
    std::vector<std::unique_ptr<IsolationTree>> trees_;
    bool   trained_ = false;
    size_t training_pool_size_ = 0;
    mutable std::mt19937 rng_;

    // Exposed copy of the IsolationTree c_factor for score normalisation
    static double IsolationTree_c_factor(size_t n) {
        if (n <= 1) return 0.0;
        double H = std::log(static_cast<double>(n) - 1.0) + 0.5772156649;
        return 2.0 * H - (2.0 * (n - 1)) / static_cast<double>(n);
    }
};

// =============================================================================
// BEACONING SCORER
// =============================================================================
// Given a rolling series of report intervals (or outbound-burst timestamps),
// detect periodic patterns indicative of C2 beaconing.
// Uses a lightweight combination of:
//   - Coefficient of variation (CoV) -- low CoV = regular heartbeat
//   - Autocorrelation at the mean lag -- positive = truly periodic rather
//     than coincidentally low-variance
// =============================================================================
class BeaconingScorer {
public:
    struct Config {
        int    min_samples   = 12;    // Require at least this many intervals
        double max_jitter    = 0.15;  // Max CoV to classify as beacon
        double min_autocorr  = 0.35;  // Min lag-1 autocorrelation to confirm
        size_t window_size   = 64;    // Rolling window of intervals to keep
    };

    explicit BeaconingScorer(const Config& cfg = {}) : config_(cfg) {}

    void ingest(int32_t device_id, double interval_ms) {
        if (interval_ms <= 0.0) return;
        std::lock_guard<std::mutex> lock(mutex_);
        auto& buf = windows_[device_id];
        buf.push_back(interval_ms);
        while (buf.size() > config_.window_size) buf.pop_front();
    }

    // Returns a finding if this device is currently beaconing. The description
    // and evidence fields are populated; caller sets device_id/machine_ip/
    // timestamp_ms fields that are out of scope for this class.
    bool score(int32_t device_id, AnomalyFinding& out) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = windows_.find(device_id);
        if (it == windows_.end()) return false;
        const auto& buf = it->second;
        if (static_cast<int>(buf.size()) < config_.min_samples) return false;

        // Compute mean and stddev
        double mean = 0.0;
        for (double v : buf) mean += v;
        mean /= buf.size();
        if (mean < 1.0) return false;

        double var = 0.0;
        for (double v : buf) { double d = v - mean; var += d * d; }
        var /= buf.size();
        double sd  = std::sqrt(var);
        double cov = sd / mean;

        if (cov >= config_.max_jitter) return false;  // Too jittery

        // Lag-1 autocorrelation
        double num = 0.0, den = 0.0;
        for (size_t i = 1; i < buf.size(); i++) {
            num += (buf[i] - mean) * (buf[i - 1] - mean);
        }
        for (double v : buf) den += (v - mean) * (v - mean);
        double autocorr = (den > 1e-9) ? num / den : 0.0;
        if (autocorr < config_.min_autocorr) return false;

        // Confirmed beacon
        double confidence = std::min(1.0,
            (config_.max_jitter - cov) / config_.max_jitter * 0.5
            + autocorr * 0.5);

        out.detector        = "beaconing";
        out.score           = 1.0 - cov;
        out.confidence      = confidence;
        out.severity        = (confidence >= 0.75 ? "high" : "medium");
        out.mitre_id        = "T1071";
        out.mitre_tactic    = "Command and Control";
        out.beacon_period_s = mean / 1000.0;
        out.beacon_jitter   = cov;

        std::ostringstream desc;
        desc << "Periodic communication pattern detected -- possible C2 beacon "
             << "(period=" << static_cast<int>(mean / 1000.0) << "s, "
             << "CoV=" << cov << ", autocorr=" << autocorr << ")";
        out.description = desc.str();

        std::ostringstream ev;
        ev << "samples=" << buf.size()
           << " mean_ms=" << mean
           << " stddev_ms=" << sd
           << " cov=" << cov
           << " autocorr_lag1=" << autocorr;
        out.evidence = ev.str();

        return true;
    }

    size_t tracked_devices() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return windows_.size();
    }

private:
    Config config_;
    mutable std::mutex mutex_;
    std::map<int32_t, std::deque<double>> windows_;
};

// =============================================================================
// ML ANOMALY DETECTOR -- Orchestrator combining both detectors
// =============================================================================
class MlAnomalyDetector {
public:
    struct Config {
        bool                    enabled           = true;
        size_t                  window_size       = 2048;  // Rolling training pool
        int                     warmup_samples    = 128;   // Before scoring
        int                     retrain_interval_s = 300;  // Retrain cadence
        double                  score_threshold   = 0.65;  // Score above -> finding
        double                  critical_threshold = 0.85;
        IsolationForest::Config forest_config;
        BeaconingScorer::Config beacon_config;
    };

    explicit MlAnomalyDetector(const Config& cfg = {})
        : config_(cfg), forest_(cfg.forest_config), beaconing_(cfg.beacon_config)
    {
        last_retrain_ = std::chrono::steady_clock::now();
    }

    // Returns all findings generated by this observation. The detector
    // maintains one rolling window of feature vectors shared across all
    // devices (the forest is population-level, not per-device) because that's
    // how "what does normal look like" for the fleet as a whole is defined.
    std::vector<AnomalyFinding> observe(int32_t device_id,
                                         int64_t timestamp_ms,
                                         const std::string& machine_ip,
                                         const AnomalyFeatures& feat)
    {
        std::vector<AnomalyFinding> findings;
        if (!config_.enabled) return findings;

        auto vec = feat.to_vector();

        {
            std::lock_guard<std::mutex> lock(pool_mutex_);
            training_pool_.push_back(vec);
            while (training_pool_.size() > config_.window_size) {
                training_pool_.pop_front();
            }
            total_observed_++;
        }

        maybe_retrain();

        // iForest scoring
        if (forest_.is_trained()) {
            double s = forest_.score(vec);
            if (s >= config_.score_threshold) {
                AnomalyFinding f;
                f.device_id    = device_id;
                f.timestamp_ms = timestamp_ms;
                f.machine_ip   = machine_ip;
                f.detector     = "iforest";
                f.score        = s;
                f.confidence   = std::min(1.0, (s - 0.5) * 2.0);
                f.severity     = (s >= config_.critical_threshold) ? "critical"
                               : (s >= 0.75)                         ? "high"
                               : "medium";
                assign_iforest_mitre(f, feat);
                std::ostringstream desc;
                desc << "ML outlier detected -- isolation forest score "
                     << std::fixed << s << " (threshold " << config_.score_threshold << ")";
                f.description = desc.str();

                std::ostringstream ev;
                ev << "cpu=" << feat.cpu_pct << "% ram=" << feat.ram_pct << "% "
                   << "net_in=" << feat.net_in_rate << "B "
                   << "net_out=" << feat.net_out_rate << "B "
                   << "events=" << feat.event_rate << " "
                   << "auth_fail=" << feat.auth_fail_rate;
                f.evidence = ev.str();
                findings.push_back(std::move(f));
                total_findings_++;
            }
        }

        // Beaconing scoring (fed by inter-report intervals)
        if (feat.interval_ms > 0.0) {
            beaconing_.ingest(device_id, feat.interval_ms);
            AnomalyFinding bf;
            if (beaconing_.score(device_id, bf)) {
                bf.device_id    = device_id;
                bf.timestamp_ms = timestamp_ms;
                bf.machine_ip   = machine_ip;
                findings.push_back(std::move(bf));
                total_findings_++;
            }
        }

        return findings;
    }

    // --- Diagnostics ---
    size_t total_observed() const { return total_observed_.load(); }
    size_t total_findings() const { return total_findings_.load(); }
    size_t pool_size() const {
        std::lock_guard<std::mutex> lock(pool_mutex_);
        return training_pool_.size();
    }
    bool is_trained() const { return forest_.is_trained(); }
    const Config& config() const { return config_; }

private:
    Config config_;
    IsolationForest forest_;
    BeaconingScorer beaconing_;

    mutable std::mutex pool_mutex_;
    std::deque<std::vector<double>> training_pool_;
    std::chrono::steady_clock::time_point last_retrain_;

    std::atomic<size_t> total_observed_{0};
    std::atomic<size_t> total_findings_{0};

    void maybe_retrain() {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - last_retrain_).count();

        std::vector<std::vector<double>> snapshot;
        bool should_train = false;
        {
            std::lock_guard<std::mutex> lock(pool_mutex_);
            if (static_cast<int>(training_pool_.size()) < config_.warmup_samples)
                return;
            if (!forest_.is_trained()) {
                should_train = true;  // First time as soon as warmed
            } else if (elapsed >= config_.retrain_interval_s) {
                should_train = true;
            }
            if (should_train) {
                snapshot.assign(training_pool_.begin(), training_pool_.end());
            }
        }

        if (should_train) {
            forest_.train(snapshot);
            last_retrain_ = now;
        }
    }

    // Heuristic: pick the most MITRE-meaningful technique based on which
    // feature(s) dominate the outlier. We avoid claiming T1071 here because
    // beaconing gets its own dedicated detector.
    static void assign_iforest_mitre(AnomalyFinding& f, const AnomalyFeatures& feat) {
        // Priority order: exfil signal > resource hijack > auth misuse > generic
        if (feat.net_out_rate > feat.net_in_rate * 2.0 && feat.net_out_rate > 1e6) {
            f.mitre_id = "T1041";
            f.mitre_tactic = "Exfiltration";
        } else if (feat.cpu_pct > 80.0 && feat.ram_pct > 70.0) {
            f.mitre_id = "T1496";
            f.mitre_tactic = "Impact";
        } else if (feat.auth_fail_rate > 3.0) {
            f.mitre_id = "T1110";
            f.mitre_tactic = "Credential Access";
        } else {
            f.mitre_id = "T1078";
            f.mitre_tactic = "Defense Evasion";
        }
    }
};

#endif
