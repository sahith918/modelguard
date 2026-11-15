#pragma once
#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

#include "modelguard/core/finding.hpp"

namespace modelguard::monitor {

struct Query {
    std::string client;
    double timestamp = 0.0;  // seconds
    std::vector<double> features;
};

// Per-feature statistics of known-benign traffic (or training features).
struct Reference {
    std::vector<double> mean;
    std::vector<double> sd;
};

struct MonitorOptions {
    double window_seconds = 60.0;
    std::size_t rate_threshold = 100;   // queries per window before a warning
    double mean_shift_threshold = 0.5;  // in reference standard deviations
    double std_log_threshold = 0.4;     // average |log(client sd / reference sd)|
    std::size_t min_queries_for_drift = 30;
    std::vector<std::string> allowlist; // client ids to skip
};

// CSV lines: client,timestamp_seconds,f1,f2,...   ('#' comments and blank lines ignored)
std::vector<Query> load_query_log(const std::filesystem::path& path);

// CSV lines: f1,f2,...
std::vector<std::vector<double>> load_feature_rows(const std::filesystem::path& path);

Reference make_reference(const std::vector<std::vector<double>>& rows);

// Two detectors per client:
//   rate_limit         - too many queries inside a sliding window
//   distribution_drift - queries look unlike the reference data (synthetic/probing inputs)
// `reference` may be null, which disables the drift detector.
std::vector<Finding> analyze(const std::vector<Query>& queries, const Reference* reference,
                             const MonitorOptions& options);

}  // namespace modelguard::monitor
