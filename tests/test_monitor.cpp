#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <random>
#include <stdexcept>

#include "modelguard/monitor/monitor.hpp"

using namespace modelguard;
namespace mn = modelguard::monitor;
namespace fs = std::filesystem;

namespace {

constexpr std::size_t kDim = 4;

std::mt19937& rng() {
    static std::mt19937 g(42);
    return g;
}

void add_normal(std::vector<mn::Query>& out, const std::string& client, std::size_t n, double duration) {
    std::normal_distribution<double> nd(0.0, 1.0);
    std::uniform_real_distribution<double> ud(0.0, duration);
    for (std::size_t i = 0; i < n; ++i) {
        mn::Query q;
        q.client = client;
        q.timestamp = ud(rng());
        for (std::size_t j = 0; j < kDim; ++j) q.features.push_back(nd(rng()));
        out.push_back(q);
    }
}

void add_uniform(std::vector<mn::Query>& out, const std::string& client, std::size_t n, double duration) {
    std::uniform_real_distribution<double> ud(0.0, duration);
    std::uniform_real_distribution<double> fd(-4.0, 4.0);
    for (std::size_t i = 0; i < n; ++i) {
        mn::Query q;
        q.client = client;
        q.timestamp = ud(rng());
        for (std::size_t j = 0; j < kDim; ++j) q.features.push_back(fd(rng()));
        out.push_back(q);
    }
}

mn::Reference make_ref() {
    std::normal_distribution<double> nd(0.0, 1.0);
    std::vector<std::vector<double>> rows;
    for (int i = 0; i < 1000; ++i) {
        std::vector<double> r;
        for (std::size_t j = 0; j < kDim; ++j) r.push_back(nd(rng()));
        rows.push_back(r);
    }
    return mn::make_reference(rows);
}

bool has(const std::vector<Finding>& findings, const std::string& detector, const std::string& subject) {
    for (const auto& f : findings) {
        if (f.detector == detector && f.subject == subject) return true;
    }
    return false;
}

struct TempFile {
    fs::path path;
    explicit TempFile(const std::string& name) : path(fs::temp_directory_path() / ("mg_test_" + name)) {}
    ~TempFile() {
        std::error_code ec;
        fs::remove(path, ec);
    }
};

}  // namespace

TEST(Monitor, BenignClientIsNotFlagged) {
    std::vector<mn::Query> q;
    add_normal(q, "benign", 200, 3600.0);
    const auto ref = make_ref();
    const auto findings = mn::analyze(q, &ref, mn::MonitorOptions());
    ASSERT_EQ(findings.size(), 1u);
    EXPECT_EQ(findings[0].detector, "no_suspicious_clients");
}

TEST(Monitor, BurstTriggersRateLimitOnly) {
    std::vector<mn::Query> q;
    add_normal(q, "burst", 500, 30.0);
    const auto ref = make_ref();
    const auto findings = mn::analyze(q, &ref, mn::MonitorOptions());
    EXPECT_TRUE(has(findings, "rate_limit", "burst"));
    EXPECT_FALSE(has(findings, "distribution_drift", "burst"));
}

TEST(Monitor, SlowRandomProbingTriggersDrift) {
    std::vector<mn::Query> q;
    add_uniform(q, "prober", 300, 3600.0);
    const auto ref = make_ref();
    const auto findings = mn::analyze(q, &ref, mn::MonitorOptions());
    EXPECT_TRUE(has(findings, "distribution_drift", "prober"));
    EXPECT_FALSE(has(findings, "rate_limit", "prober"));
}

TEST(Monitor, AllowlistedClientIsSkipped) {
    std::vector<mn::Query> q;
    add_normal(q, "trusted", 500, 30.0);
    mn::MonitorOptions opt;
    opt.allowlist.push_back("trusted");
    const auto findings = mn::analyze(q, nullptr, opt);
    ASSERT_EQ(findings.size(), 1u);
    EXPECT_EQ(findings[0].detector, "no_suspicious_clients");
}

TEST(Monitor, DriftIsSkippedWithoutReference) {
    std::vector<mn::Query> q;
    add_uniform(q, "prober", 300, 3600.0);
    const auto findings = mn::analyze(q, nullptr, mn::MonitorOptions());
    EXPECT_FALSE(has(findings, "distribution_drift", "prober"));
}

TEST(Monitor, LoadsCsvLogAndRejectsBadLines) {
    TempFile good("log_good.csv");
    {
        std::ofstream out(good.path);
        out << "# comment\n"
            << "alice,1.5,0.1,0.2\n"
            << "\n"
            << "bob,2.5,0.3,0.4\n";
    }
    const auto q = mn::load_query_log(good.path);
    ASSERT_EQ(q.size(), 2u);
    EXPECT_EQ(q[0].client, "alice");
    EXPECT_EQ(q[1].features.size(), 2u);

    TempFile bad("log_bad.csv");
    {
        std::ofstream out(bad.path);
        out << "alice,1.5,abc\n";
    }
    EXPECT_THROW(mn::load_query_log(bad.path), std::runtime_error);
}

TEST(Monitor, FeatureCountMismatchThrows) {
    std::vector<mn::Query> q;
    add_normal(q, "x", 50, 100.0);
    mn::Reference ref;
    ref.mean.assign(kDim + 1, 0.0);
    ref.sd.assign(kDim + 1, 1.0);
    EXPECT_THROW(mn::analyze(q, &ref, mn::MonitorOptions()), std::invalid_argument);
}
