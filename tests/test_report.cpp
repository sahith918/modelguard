#include <gtest/gtest.h>

#include "modelguard/core/report.hpp"

using namespace modelguard;

namespace {
Finding make(Severity s, const std::string& detector) {
    Finding f;
    f.module = "test";
    f.detector = detector;
    f.severity = s;
    f.score = 0.5;
    f.subject = "x";
    return f;
}
}  // namespace

TEST(Report, EmptyReportIsInfo) {
    Report r;
    EXPECT_EQ(r.max_severity(), Severity::Info);
    EXPECT_EQ(r.to_json()["summary"]["total"], 0);
}

TEST(Report, MaxSeverityTracksHighest) {
    Report r;
    r.add(make(Severity::Warning, "a"));
    r.add(make(Severity::Critical, "b"));
    r.add(make(Severity::Info, "c"));
    EXPECT_EQ(r.max_severity(), Severity::Critical);
}

TEST(Report, JsonContainsFindings) {
    Report r;
    r.add(make(Severity::Warning, "first"));
    r.add(make(Severity::Info, "second"));
    auto j = r.to_json();
    EXPECT_EQ(j["summary"]["total"], 2);
    EXPECT_EQ(j["findings"][0]["detector"], "first");
    EXPECT_EQ(j["findings"][0]["severity"], "warning");
}

TEST(Report, TextMentionsDetector) {
    Report r;
    r.add(make(Severity::Critical, "tamper"));
    EXPECT_NE(r.to_text().find("tamper"), std::string::npos);
}
