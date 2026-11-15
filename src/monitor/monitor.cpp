#include "modelguard/monitor/monitor.hpp"

#include <algorithm>
#include <cmath>
#include <fstream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace modelguard::monitor {

namespace {

std::string trim(const std::string& s) {
    const auto b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return "";
    const auto e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

std::vector<std::string> split_csv(const std::string& line) {
    std::vector<std::string> out;
    std::string cur;
    std::stringstream ss(line);
    while (std::getline(ss, cur, ',')) out.push_back(trim(cur));
    return out;
}

double parse_number(const std::string& text, std::size_t line_no) {
    try {
        std::size_t used = 0;
        const double v = std::stod(text, &used);
        if (used != text.size()) throw std::invalid_argument("trailing characters");
        return v;
    } catch (const std::exception&) {
        throw std::runtime_error("line " + std::to_string(line_no) + ": '" + text +
                                 "' is not a number");
    }
}

template <typename Fn>
void for_each_line(const std::filesystem::path& path, Fn&& fn) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("cannot open file: " + path.string());
    std::string line;
    std::size_t n = 0;
    while (std::getline(in, line)) {
        ++n;
        const std::string t = trim(line);
        if (t.empty() || t[0] == '#') continue;
        fn(t, n);
    }
}

Finding make_finding(const std::string& subject, Severity severity, const std::string& detector,
                     double score, nlohmann::json evidence) {
    Finding f;
    f.module = "monitor";
    f.detector = detector;
    f.severity = severity;
    f.score = score;
    f.subject = subject;
    f.evidence = std::move(evidence);
    return f;
}

}  // namespace

std::vector<Query> load_query_log(const std::filesystem::path& path) {
    std::vector<Query> out;
    std::size_t dim = 0;
    for_each_line(path, [&](const std::string& line, std::size_t n) {
        const auto f = split_csv(line);
        if (f.size() < 3) {
            throw std::runtime_error("line " + std::to_string(n) +
                                     ": expected client,timestamp,feature1,...");
        }
        Query q;
        q.client = f[0];
        q.timestamp = parse_number(f[1], n);
        for (std::size_t i = 2; i < f.size(); ++i) q.features.push_back(parse_number(f[i], n));
        if (out.empty()) {
            dim = q.features.size();
        } else if (q.features.size() != dim) {
            throw std::runtime_error("line " + std::to_string(n) + ": expected " +
                                     std::to_string(dim) + " features");
        }
        out.push_back(std::move(q));
    });
    return out;
}

std::vector<std::vector<double>> load_feature_rows(const std::filesystem::path& path) {
    std::vector<std::vector<double>> rows;
    for_each_line(path, [&](const std::string& line, std::size_t n) {
        std::vector<double> row;
        for (const auto& field : split_csv(line)) row.push_back(parse_number(field, n));
        if (!rows.empty() && row.size() != rows[0].size()) {
            throw std::runtime_error("line " + std::to_string(n) + ": inconsistent column count");
        }
        rows.push_back(std::move(row));
    });
    return rows;
}

Reference make_reference(const std::vector<std::vector<double>>& rows) {
    if (rows.empty()) throw std::invalid_argument("reference data is empty");
    const std::size_t d = rows[0].size();
    const double n = static_cast<double>(rows.size());
    Reference ref;
    ref.mean.assign(d, 0.0);
    ref.sd.assign(d, 0.0);
    for (const auto& r : rows)
        for (std::size_t j = 0; j < d; ++j) ref.mean[j] += r[j];
    for (std::size_t j = 0; j < d; ++j) ref.mean[j] /= n;
    for (const auto& r : rows)
        for (std::size_t j = 0; j < d; ++j) {
            const double diff = r[j] - ref.mean[j];
            ref.sd[j] += diff * diff;
        }
    for (std::size_t j = 0; j < d; ++j) ref.sd[j] = std::max(std::sqrt(ref.sd[j] / n), 1e-9);
    return ref;
}

std::vector<Finding> analyze(const std::vector<Query>& queries, const Reference* reference,
                             const MonitorOptions& opt) {
    if (reference != nullptr && !queries.empty() &&
        queries[0].features.size() != reference->mean.size()) {
        throw std::invalid_argument("query log and reference data have different feature counts");
    }

    std::map<std::string, std::vector<const Query*>> by_client;
    for (const auto& q : queries) by_client[q.client].push_back(&q);

    std::vector<Finding> out;
    for (auto& entry : by_client) {
        const std::string& client = entry.first;
        std::vector<const Query*>& qs = entry.second;
        if (std::find(opt.allowlist.begin(), opt.allowlist.end(), client) != opt.allowlist.end()) {
            continue;
        }
        std::sort(qs.begin(), qs.end(),
                  [](const Query* a, const Query* b) { return a->timestamp < b->timestamp; });

        // --- rate detector: most queries inside any window of window_seconds ---
        std::size_t best = 0, lo = 0;
        for (std::size_t hi = 0; hi < qs.size(); ++hi) {
            while (qs[hi]->timestamp - qs[lo]->timestamp > opt.window_seconds) ++lo;
            best = std::max(best, hi - lo + 1);
        }
        if (best > opt.rate_threshold) {
            nlohmann::json ev;
            ev["max_queries_in_window"] = best;
            ev["window_seconds"] = opt.window_seconds;
            ev["total_queries"] = qs.size();
            const Severity sev = best > 3 * opt.rate_threshold ? Severity::Critical : Severity::Warning;
            const double score =
                std::min(1.0, static_cast<double>(best) / (3.0 * static_cast<double>(opt.rate_threshold)));
            out.push_back(make_finding(client, sev, "rate_limit", score, ev));
        }

        // --- drift detector: do this client's queries look like real data? ---
        if (reference != nullptr && qs.size() >= opt.min_queries_for_drift) {
            const std::size_t d = reference->mean.size();
            const double n = static_cast<double>(qs.size());
            std::vector<double> cm(d, 0.0), cs(d, 0.0);
            for (const Query* q : qs)
                for (std::size_t j = 0; j < d; ++j) cm[j] += q->features[j];
            for (std::size_t j = 0; j < d; ++j) cm[j] /= n;
            for (const Query* q : qs)
                for (std::size_t j = 0; j < d; ++j) {
                    const double diff = q->features[j] - cm[j];
                    cs[j] += diff * diff;
                }
            double shift = 0.0, slog = 0.0;
            for (std::size_t j = 0; j < d; ++j) {
                const double sd_c = std::max(std::sqrt(cs[j] / n), 1e-9);
                const double z = (cm[j] - reference->mean[j]) / reference->sd[j];
                shift += z * z;
                slog += std::fabs(std::log(sd_c / reference->sd[j]));
            }
            shift = std::sqrt(shift / static_cast<double>(d));
            slog /= static_cast<double>(d);

            if (shift > opt.mean_shift_threshold || slog > opt.std_log_threshold) {
                nlohmann::json ev;
                ev["mean_shift_in_sd"] = shift;
                ev["avg_abs_log_sd_ratio"] = slog;
                ev["queries"] = qs.size();
                const bool strong = shift > 2.0 * opt.mean_shift_threshold ||
                                    slog > 2.0 * opt.std_log_threshold;
                const double score = std::min(
                    1.0, std::max(shift / (2.0 * opt.mean_shift_threshold),
                                  slog / (2.0 * opt.std_log_threshold)));
                out.push_back(make_finding(client, strong ? Severity::Critical : Severity::Warning,
                                           "distribution_drift", score, ev));
            }
        }
    }

    if (out.empty()) {
        nlohmann::json ev;
        ev["clients"] = by_client.size();
        out.push_back(make_finding("all_clients", Severity::Info, "no_suspicious_clients", 0.0, ev));
    }
    return out;
}

}  // namespace modelguard::monitor
