#include "modelguard/poison/spectral.hpp"

#include <algorithm>
#include <cmath>
#include <map>
#include <random>
#include <stdexcept>
#include <string>
#include <utility>

namespace modelguard::poison {

namespace {

double median(std::vector<double> v) {
    const auto mid = static_cast<std::ptrdiff_t>(v.size() / 2);
    std::nth_element(v.begin(), v.begin() + mid, v.end());
    double m = v[static_cast<std::size_t>(mid)];
    if (v.size() % 2 == 0) {
        const double lo = *std::max_element(v.begin(), v.begin() + mid);
        m = 0.5 * (m + lo);
    }
    return m;
}

double norm(const std::vector<double>& v) {
    double s = 0.0;
    for (double e : v) s += e * e;
    return std::sqrt(s);
}

// Top right singular vector of the m x d matrix x, by power iteration on X^T X.
std::vector<double> top_singular_vector(const std::vector<double>& x, std::size_t m, std::size_t d,
                                        int iterations) {
    std::mt19937 rng(12345);  // fixed seed -> deterministic results
    std::normal_distribution<double> nd(0.0, 1.0);
    std::vector<double> v(d), w(m), u(d);
    for (auto& e : v) e = nd(rng);
    double n0 = norm(v);
    if (n0 < 1e-300) { v[0] = 1.0; n0 = 1.0; }
    for (auto& e : v) e /= n0;

    for (int it = 0; it < iterations; ++it) {
        for (std::size_t i = 0; i < m; ++i) {
            const double* row = &x[i * d];
            double s = 0.0;
            for (std::size_t j = 0; j < d; ++j) s += row[j] * v[j];
            w[i] = s;
        }
        std::fill(u.begin(), u.end(), 0.0);
        for (std::size_t i = 0; i < m; ++i) {
            const double* row = &x[i * d];
            for (std::size_t j = 0; j < d; ++j) u[j] += row[j] * w[i];
        }
        const double nu = norm(u);
        if (nu < 1e-300) break;
        double diff = 0.0;
        for (std::size_t j = 0; j < d; ++j) {
            const double nv = u[j] / nu;
            diff += (nv - v[j]) * (nv - v[j]);
            v[j] = nv;
        }
        if (diff < 1e-18) break;
    }
    return v;
}

}  // namespace

SpectralResult run_spectral(const std::vector<double>& emb, std::size_t n, std::size_t d,
                            const std::vector<std::int64_t>& labels, const SpectralOptions& opt) {
    if (emb.size() != n * d) throw std::invalid_argument("embeddings size does not match n x d");
    if (labels.size() != n) throw std::invalid_argument("labels length does not match n");
    if (d == 0) throw std::invalid_argument("embeddings have zero columns");

    SpectralResult res;
    res.flagged.assign(n, 0);
    res.z.assign(n, 0.0);

    std::map<std::int64_t, std::vector<std::size_t>> groups;
    for (std::size_t i = 0; i < n; ++i) groups[labels[i]].push_back(i);

    std::size_t total_flagged = 0;
    for (const auto& group : groups) {
        const std::int64_t label = group.first;
        const std::vector<std::size_t>& idx = group.second;
        const std::size_t m = idx.size();
        if (m < opt.min_class_size) continue;

        std::vector<double> mean(d, 0.0);
        for (std::size_t i : idx)
            for (std::size_t j = 0; j < d; ++j) mean[j] += emb[i * d + j];
        for (std::size_t j = 0; j < d; ++j) mean[j] /= static_cast<double>(m);

        std::vector<double> xc(m * d);
        for (std::size_t k = 0; k < m; ++k)
            for (std::size_t j = 0; j < d; ++j) xc[k * d + j] = emb[idx[k] * d + j] - mean[j];

        const std::vector<double> v = top_singular_vector(xc, m, d, opt.power_iterations);

        std::vector<double> proj(m);
        for (std::size_t k = 0; k < m; ++k) {
            double s = 0.0;
            for (std::size_t j = 0; j < d; ++j) s += xc[k * d + j] * v[j];
            proj[k] = s;
        }
        const double med = median(proj);
        std::vector<double> dev(m);
        for (std::size_t k = 0; k < m; ++k) dev[k] = std::fabs(proj[k] - med);
        const double scale = 1.4826 * median(dev);  // robust standard deviation
        if (scale < 1e-12) continue;

        std::vector<std::pair<double, std::size_t>> hits;
        for (std::size_t k = 0; k < m; ++k) {
            const double z = dev[k] / scale;
            res.z[idx[k]] = z;
            if (z > opt.z_threshold) {
                res.flagged[idx[k]] = 1;
                hits.emplace_back(z, idx[k]);
            }
        }
        if (hits.empty()) continue;
        total_flagged += hits.size();

        std::sort(hits.begin(), hits.end(),
                  [](const auto& a, const auto& b) { return a.first > b.first; });

        const double frac = static_cast<double>(hits.size()) / static_cast<double>(m);
        Finding f;
        f.module = "poison";
        f.detector = "spectral_signature";
        f.severity = frac >= opt.critical_fraction ? Severity::Critical : Severity::Warning;
        f.score = std::min(1.0, frac / 0.10);
        f.subject = "class_" + std::to_string(label);
        f.evidence["class_size"] = m;
        f.evidence["flagged"] = hits.size();
        f.evidence["fraction"] = frac;
        nlohmann::json top = nlohmann::json::array();
        for (std::size_t k = 0; k < hits.size() && k < 10; ++k) top.push_back(hits[k].second);
        f.evidence["top_indices"] = top;
        res.findings.push_back(std::move(f));
    }

    if (total_flagged == 0) {
        Finding f;
        f.module = "poison";
        f.detector = "spectral_signature";
        f.severity = Severity::Info;
        f.score = 0.0;
        f.subject = "dataset";
        f.evidence["samples"] = n;
        res.findings.push_back(std::move(f));
    }
    return res;
}

}  // namespace modelguard::poison
