#include <algorithm>
#include <cctype>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>

#include <CLI/CLI.hpp>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include "modelguard/core/report.hpp"
#include "modelguard/integrity/signer.hpp"
#include "modelguard/monitor/monitor.hpp"
#include "modelguard/poison/npy_loader.hpp"
#include "modelguard/poison/spectral.hpp"

namespace mg = modelguard;
namespace ig = modelguard::integrity;
namespace pz = modelguard::poison;
namespace mn = modelguard::monitor;
namespace fs = std::filesystem;

namespace {

void write_text(const fs::path& p, const std::string& text) {
    std::ofstream out(p, std::ios::binary);
    if (!out) throw std::runtime_error("cannot write file: " + p.string());
    out << text;
}

std::string read_text(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    if (!in) throw std::runtime_error("cannot read file: " + p.string());
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

ig::Bytes load_hex_key(const fs::path& p) {
    std::string text = read_text(p);
    text.erase(std::remove_if(text.begin(), text.end(),
                              [](unsigned char c) { return std::isspace(c) != 0; }),
               text.end());
    return ig::from_hex(text);
}

// Runs a command body; turns exceptions into a readable error and exit code 1.
template <typename Fn>
int guarded(Fn&& fn) {
    try {
        return fn();
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << '\n';
        return 1;
    }
}

void print_report(const mg::Report& report, bool as_json) {
    if (as_json) {
        std::cout << report.to_json().dump(2) << '\n';
    } else {
        std::cout << report.to_text();
    }
}

// Exit code 2 = something critical was found (usable in scripts / CI).
int exit_for(const mg::Report& report) {
    return report.max_severity() == mg::Severity::Critical ? 2 : 0;
}

}  // namespace

int main(int argc, char** argv) {
    CLI::App app{"ModelGuard - ML model security toolkit", "modelguard"};
    app.set_version_flag("--version", "0.1.0");
    app.require_subcommand(1);

    int exit_code = 0;

    // ---- demo ----
    bool demo_json = false;
    auto* demo = app.add_subcommand("demo", "Print sample findings to test the report pipeline");
    demo->add_flag("--json", demo_json, "Print the report as JSON");
    demo->callback([&]() {
        if (!demo_json) spdlog::info("Running demo detector");
        mg::Report report;

        mg::Finding a;
        a.module = "integrity";
        a.detector = "demo_hash_mismatch";
        a.severity = mg::Severity::Critical;
        a.score = 1.0;
        a.subject = "layer3.weight";
        a.evidence["expected"] = "aa11";
        a.evidence["actual"] = "bb22";
        report.add(a);

        mg::Finding b;
        b.module = "poison";
        b.detector = "demo_outlier";
        b.severity = mg::Severity::Warning;
        b.score = 0.62;
        b.subject = "sample_1042";
        report.add(b);

        print_report(report, demo_json);
        exit_code = exit_for(report);
    });

    // ---- keygen ----
    std::string out_dir = ".";
    auto* keygen = app.add_subcommand("keygen", "Create a signing key pair");
    keygen->add_option("--out-dir", out_dir, "Folder for the key files")->capture_default_str();
    keygen->callback([&]() {
        exit_code = guarded([&]() {
            const fs::path dir(out_dir);
            fs::create_directories(dir);
            const fs::path pub = dir / "modelguard.pub";
            const fs::path key = dir / "modelguard.key";
            if (fs::exists(pub) || fs::exists(key)) {
                throw std::runtime_error("key files already exist in " + dir.string() +
                                         " - refusing to overwrite");
            }
            const auto kp = ig::generate_keypair();
            write_text(pub, ig::to_hex(kp.public_key) + "\n");
            write_text(key, ig::to_hex(kp.secret_key) + "\n");
            std::cout << "Public key (share this):  " << pub.string() << '\n'
                      << "Secret key (KEEP PRIVATE): " << key.string() << '\n';
            return 0;
        });
    });

    // ---- sign ----
    std::string sign_model, sign_key, sign_out;
    auto* sign = app.add_subcommand("sign", "Sign a model file and write a manifest");
    sign->add_option("model", sign_model, "Model file to sign")->required()->check(CLI::ExistingFile);
    sign->add_option("--key", sign_key, "Secret key file")->required()->check(CLI::ExistingFile);
    sign->add_option("--out", sign_out, "Manifest path (default: <model>.mg.json)");
    sign->callback([&]() {
        exit_code = guarded([&]() {
            const auto sk = load_hex_key(sign_key);
            const auto manifest = ig::make_manifest(sign_model, sk);
            const std::string out_path = sign_out.empty() ? sign_model + ".mg.json" : sign_out;
            write_text(out_path, manifest.dump(2) + "\n");
            std::cout << "Signed " << sign_model << '\n'
                      << "Manifest written to " << out_path << '\n'
                      << "sha256: " << manifest.at("sha256").get<std::string>() << '\n';
            return 0;
        });
    });

    // ---- verify ----
    std::string verify_model, verify_manifest_path, verify_pub;
    bool verify_json = false;
    auto* verify = app.add_subcommand("verify", "Check a model file against its manifest");
    verify->add_option("model", verify_model, "Model file to check")->required()->check(CLI::ExistingFile);
    verify->add_option("--manifest", verify_manifest_path, "Manifest file")
        ->required()->check(CLI::ExistingFile);
    verify->add_option("--pub", verify_pub, "Public key file")->required()->check(CLI::ExistingFile);
    verify->add_flag("--json", verify_json, "Print the report as JSON");
    verify->callback([&]() {
        exit_code = guarded([&]() {
            const auto pk = load_hex_key(verify_pub);
            const auto manifest = nlohmann::json::parse(read_text(verify_manifest_path));
            mg::Report report;
            for (auto& f : ig::verify_manifest(verify_model, manifest, pk)) {
                report.add(std::move(f));
            }
            print_report(report, verify_json);
            return exit_for(report);
        });
    });

    // ---- scan (poisoned training data) ----
    std::string scan_emb, scan_labels, scan_truth;
    double scan_z = 3.5;
    bool scan_json = false;
    auto* scan = app.add_subcommand("scan", "Look for poisoned samples in a training set's embeddings");
    scan->add_option("embeddings", scan_emb, "2-D .npy file: one row per sample")
        ->required()->check(CLI::ExistingFile);
    scan->add_option("labels", scan_labels, "1-D .npy file: class label per sample")
        ->required()->check(CLI::ExistingFile);
    scan->add_option("--truth", scan_truth, "Optional .npy 0/1 mask of known-poisoned samples (for evaluation)")
        ->check(CLI::ExistingFile);
    scan->add_option("--z", scan_z, "Robust z-score threshold")->capture_default_str();
    scan->add_flag("--json", scan_json, "Print the report as JSON");
    scan->callback([&]() {
        exit_code = guarded([&]() {
            const auto emb = pz::load_npy(scan_emb);
            const auto lab = pz::load_npy(scan_labels);
            if (emb.shape.size() != 2) throw std::runtime_error("embeddings must be a 2-D array");
            const std::size_t n = emb.shape[0];
            const std::size_t d = emb.shape[1];
            if (lab.shape.size() != 1 || lab.shape[0] != n) {
                throw std::runtime_error("labels must be a 1-D array with one entry per embedding row");
            }
            std::vector<std::int64_t> labels;
            labels.reserve(n);
            for (double v : lab.data) labels.push_back(static_cast<std::int64_t>(std::llround(v)));

            pz::SpectralOptions opt;
            opt.z_threshold = scan_z;
            auto result = pz::run_spectral(emb.data, n, d, labels, opt);

            mg::Report report;
            for (auto& f : result.findings) report.add(std::move(f));

            std::string eval_line;
            if (!scan_truth.empty()) {
                const auto truth = pz::load_npy(scan_truth);
                if (truth.data.size() != n) {
                    throw std::runtime_error("truth mask must have one entry per embedding row");
                }
                std::size_t tp = 0, fp = 0, fn = 0;
                for (std::size_t i = 0; i < n; ++i) {
                    const bool pred = result.flagged[i] != 0;
                    const bool real = truth.data[i] != 0.0;
                    if (pred && real) ++tp;
                    else if (pred) ++fp;
                    else if (real) ++fn;
                }
                const double precision = (tp + fp) ? static_cast<double>(tp) / static_cast<double>(tp + fp) : 0.0;
                const double recall = (tp + fn) ? static_cast<double>(tp) / static_cast<double>(tp + fn) : 0.0;

                mg::Finding e;
                e.module = "poison";
                e.detector = "evaluation";
                e.severity = mg::Severity::Info;
                e.score = recall;
                e.subject = "vs_ground_truth";
                e.evidence["true_positives"] = tp;
                e.evidence["false_positives"] = fp;
                e.evidence["false_negatives"] = fn;
                e.evidence["precision"] = precision;
                e.evidence["recall"] = recall;
                report.add(e);

                std::ostringstream os;
                os << std::fixed << std::setprecision(3) << "Evaluation vs ground truth: TP=" << tp
                   << " FP=" << fp << " FN=" << fn << " precision=" << precision << " recall=" << recall;
                eval_line = os.str();
            }
            print_report(report, scan_json);
            if (!scan_json && !eval_line.empty()) std::cout << eval_line << '\n';
            return exit_for(report);
        });
    });

    // ---- monitor (model extraction attempts) ----
    std::string mon_log, mon_ref;
    double mon_window = 60.0;
    std::size_t mon_rate = 100;
    std::vector<std::string> mon_allow;
    bool mon_json = false;
    auto* mon_cmd = app.add_subcommand("monitor", "Analyse a query log for model-extraction behaviour");
    mon_cmd->add_option("log", mon_log, "CSV log: client,timestamp_seconds,feature1,...")
        ->required()->check(CLI::ExistingFile);
    mon_cmd->add_option("--reference", mon_ref, "CSV of known-benign feature rows (enables drift detection)")
        ->check(CLI::ExistingFile);
    mon_cmd->add_option("--window", mon_window, "Rate window in seconds")->capture_default_str();
    mon_cmd->add_option("--rate-limit", mon_rate, "Queries per window before a warning")->capture_default_str();
    mon_cmd->add_option("--allow", mon_allow, "Client id to ignore (can be repeated)");
    mon_cmd->add_flag("--json", mon_json, "Print the report as JSON");
    mon_cmd->callback([&]() {
        exit_code = guarded([&]() {
            const auto queries = mn::load_query_log(mon_log);
            std::optional<mn::Reference> reference;
            if (!mon_ref.empty()) reference = mn::make_reference(mn::load_feature_rows(mon_ref));

            mn::MonitorOptions opt;
            opt.window_seconds = mon_window;
            opt.rate_threshold = mon_rate;
            opt.allowlist = mon_allow;

            mg::Report report;
            for (auto& f : mn::analyze(queries, reference ? &*reference : nullptr, opt)) {
                report.add(std::move(f));
            }
            print_report(report, mon_json);
            return exit_for(report);
        });
    });

    CLI11_PARSE(app, argc, argv);
    return exit_code;
}
