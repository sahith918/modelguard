#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>

#include "modelguard/core/finding.hpp"

namespace modelguard::poison {

struct SpectralOptions {
    double z_threshold = 3.5;        // robust z-score above which a sample is flagged
    std::size_t min_class_size = 20; // smaller classes are skipped
    double critical_fraction = 0.01; // >= this share of a class flagged => Critical
    int power_iterations = 200;
};

struct SpectralResult {
    std::vector<char> flagged;     // 1 if the sample was flagged
    std::vector<double> z;         // robust z-score per sample (0 if class skipped)
    std::vector<Finding> findings; // one per class with flagged samples
};

// Spectral-signature poison detection (Tran et al., 2018), simplified:
// per class, centre the representations, find the top singular direction,
// project every sample on it, and flag samples far from the class median.
// `embeddings` is row-major n x d.
SpectralResult run_spectral(const std::vector<double>& embeddings, std::size_t n, std::size_t d,
                            const std::vector<std::int64_t>& labels,
                            const SpectralOptions& options = SpectralOptions());

}  // namespace modelguard::poison
