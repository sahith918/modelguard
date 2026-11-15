#pragma once
#include <string>
#include <nlohmann/json.hpp>

namespace modelguard {

enum class Severity { Info = 0, Warning = 1, Critical = 2 };

inline const char* to_string(Severity s) {
    switch (s) {
        case Severity::Info:     return "info";
        case Severity::Warning:  return "warning";
        case Severity::Critical: return "critical";
    }
    return "unknown";
}

// One result from any detector (integrity, poison, monitor).
struct Finding {
    std::string module;      // "integrity" | "poison" | "monitor"
    std::string detector;    // e.g. "spectral_signature"
    Severity severity = Severity::Info;
    double score = 0.0;      // 0..1 where possible
    std::string subject;     // layer name, sample index, client id
    nlohmann::json evidence = nlohmann::json::object();
};

inline nlohmann::json finding_to_json(const Finding& f) {
    nlohmann::json j;
    j["module"] = f.module;
    j["detector"] = f.detector;
    j["severity"] = to_string(f.severity);
    j["score"] = f.score;
    j["subject"] = f.subject;
    j["evidence"] = f.evidence;
    return j;
}

}  // namespace modelguard
