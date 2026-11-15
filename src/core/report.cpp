#include "modelguard/core/report.hpp"

#include <iomanip>
#include <sstream>

namespace modelguard {

Severity Report::max_severity() const {
    Severity worst = Severity::Info;
    for (const auto& f : findings) {
        if (static_cast<int>(f.severity) > static_cast<int>(worst)) {
            worst = f.severity;
        }
    }
    return worst;
}

nlohmann::json Report::to_json() const {
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& f : findings) {
        arr.push_back(finding_to_json(f));
    }
    nlohmann::json j;
    j["summary"]["total"] = findings.size();
    j["summary"]["max_severity"] = to_string(max_severity());
    j["findings"] = std::move(arr);
    return j;
}

std::string Report::to_text() const {
    std::ostringstream out;
    if (findings.empty()) {
        out << "No findings.\n";
        return out.str();
    }
    for (const auto& f : findings) {
        out << '[' << to_string(f.severity) << "] " << f.module << '/' << f.detector;
        if (!f.subject.empty()) out << "  subject=" << f.subject;
        out << "  score=" << std::fixed << std::setprecision(2) << f.score << '\n';
    }
    out << findings.size() << " finding(s), highest severity: "
        << to_string(max_severity()) << '\n';
    return out.str();
}

}  // namespace modelguard
