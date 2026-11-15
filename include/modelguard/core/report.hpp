#pragma once
#include <string>
#include <utility>
#include <vector>
#include "modelguard/core/finding.hpp"

namespace modelguard {

struct Report {
    std::vector<Finding> findings;

    void add(Finding f) { findings.push_back(std::move(f)); }
    Severity max_severity() const;
    nlohmann::json to_json() const;
    std::string to_text() const;
};

}  // namespace modelguard
