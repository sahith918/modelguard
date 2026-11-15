#include <gtest/gtest.h>

#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <random>
#include <stdexcept>

#include "modelguard/poison/npy_loader.hpp"
#include "modelguard/poison/spectral.hpp"

using namespace modelguard;
namespace pz = modelguard::poison;
namespace fs = std::filesystem;

namespace {

struct TempFile {
    fs::path path;
    explicit TempFile(const std::string& name) : path(fs::temp_directory_path() / ("mg_test_" + name)) {}
    ~TempFile() {
        std::error_code ec;
        fs::remove(path, ec);
    }
};

// Writes a minimal version-1.0 .npy file.
void write_npy(const fs::path& path, const std::string& descr, const std::string& shape,
               const void* data, std::size_t bytes) {
    std::string header = "{'descr': '" + descr + "', 'fortran_order': False, 'shape': " + shape + ", }";
    while ((10 + header.size() + 1) % 64 != 0) header.push_back(' ');
    header.push_back('\n');
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    const unsigned char magic[6] = {0x93, 'N', 'U', 'M', 'P', 'Y'};
    out.write(reinterpret_cast<const char*>(magic), 6);
    const unsigned char ver[2] = {1, 0};
    out.write(reinterpret_cast<const char*>(ver), 2);
    const auto len = static_cast<std::uint16_t>(header.size());
    const unsigned char lb[2] = {static_cast<unsigned char>(len & 0xFF),
                                 static_cast<unsigned char>(len >> 8)};
    out.write(reinterpret_cast<const char*>(lb), 2);
    out.write(header.data(), static_cast<std::streamsize>(header.size()));
    out.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(bytes));
}

struct Synth {
    std::vector<double> x;
    std::vector<std::int64_t> y;
    std::vector<char> truth;
    std::size_t n = 0, d = 0;
};

Synth make_synth(double shift, double poison_rate) {
    const std::size_t classes = 4, per = 500, d = 16;
    std::mt19937 rng(7);
    std::normal_distribution<double> nd(0.0, 1.0);

    std::vector<double> means(classes * d);
    for (auto& m : means) m = 3.0 * nd(rng);
    std::vector<double> u(d);
    double nu = 0.0;
    for (auto& e : u) {
        e = nd(rng);
        nu += e * e;
    }
    nu = std::sqrt(nu);
    for (auto& e : u) e /= nu;

    Synth s;
    s.n = classes * per;
    s.d = d;
    const auto poisoned_count = static_cast<std::size_t>(poison_rate * static_cast<double>(per));
    for (std::size_t c = 0; c < classes; ++c) {
        for (std::size_t i = 0; i < per; ++i) {
            const bool poisoned = (c == 0 && i < poisoned_count);
            for (std::size_t j = 0; j < d; ++j) {
                s.x.push_back(means[c * d + j] + nd(rng) + (poisoned ? shift * u[j] : 0.0));
            }
            s.y.push_back(static_cast<std::int64_t>(c));
            s.truth.push_back(poisoned ? 1 : 0);
        }
    }
    return s;
}

}  // namespace

TEST(Npy, LoadsFloat64Matrix) {
    TempFile f("m.npy");
    const double values[6] = {1.5, 2.5, 3.5, 4.5, 5.5, 6.5};
    write_npy(f.path, "<f8", "(2, 3)", values, sizeof(values));
    const auto a = pz::load_npy(f.path);
    ASSERT_EQ(a.shape.size(), 2u);
    EXPECT_EQ(a.shape[0], 2u);
    EXPECT_EQ(a.shape[1], 3u);
    EXPECT_EQ(a.data[4], 5.5);
}

TEST(Npy, LoadsInt64Vector) {
    TempFile f("v.npy");
    const std::int64_t values[3] = {5, 6, 7};
    write_npy(f.path, "<i8", "(3,)", values, sizeof(values));
    const auto a = pz::load_npy(f.path);
    ASSERT_EQ(a.shape.size(), 1u);
    EXPECT_EQ(a.data[2], 7.0);
}

TEST(Npy, RejectsGarbage) {
    TempFile f("garbage.npy");
    std::ofstream(f.path, std::ios::binary) << "this is not a numpy file";
    EXPECT_THROW(pz::load_npy(f.path), std::runtime_error);
}

TEST(Spectral, FindsPoisonedSamples) {
    const auto s = make_synth(6.0, 0.10);
    const auto r = pz::run_spectral(s.x, s.n, s.d, s.y);
    std::size_t tp = 0, fp = 0, fn = 0;
    for (std::size_t i = 0; i < s.n; ++i) {
        const bool pred = r.flagged[i] != 0;
        const bool truth = s.truth[i] != 0;
        if (pred && truth) ++tp;
        else if (pred) ++fp;
        else if (truth) ++fn;
    }
    const double recall = static_cast<double>(tp) / static_cast<double>(tp + fn);
    const double precision = static_cast<double>(tp) / static_cast<double>(tp + fp);
    EXPECT_GE(recall, 0.8);
    EXPECT_GE(precision, 0.8);

    bool critical_class0 = false;
    for (const auto& f : r.findings) {
        if (f.subject == "class_0" && f.severity == Severity::Critical) critical_class0 = true;
    }
    EXPECT_TRUE(critical_class0);
}

TEST(Spectral, CleanDataHasNoCriticalFinding) {
    const auto s = make_synth(0.0, 0.0);
    const auto r = pz::run_spectral(s.x, s.n, s.d, s.y);
    for (const auto& f : r.findings) {
        EXPECT_NE(f.severity, Severity::Critical);
    }
}

TEST(Spectral, RejectsSizeMismatch) {
    const std::vector<double> x(10, 0.0);
    const std::vector<std::int64_t> y(3, 0);
    EXPECT_THROW(pz::run_spectral(x, 5, 2, y), std::invalid_argument);
}
