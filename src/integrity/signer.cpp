#include "modelguard/integrity/signer.hpp"

#include <sodium.h>

#include <cstdint>
#include <fstream>
#include <stdexcept>

namespace modelguard::integrity {

namespace {

void ensure_init() {
    // Safe to call many times; returns 1 if already initialised.
    if (sodium_init() < 0) {
        throw std::runtime_error("libsodium failed to initialise");
    }
}

template <typename Fn>
void for_each_chunk(const std::filesystem::path& path, Fn&& fn) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("cannot open file: " + path.string());
    }
    Bytes buf(static_cast<std::size_t>(1) << 20);  // 1 MiB
    while (in) {
        in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
        const std::streamsize n = in.gcount();
        if (n > 0) {
            fn(buf.data(), static_cast<unsigned long long>(n));
        }
    }
    if (in.bad()) {
        throw std::runtime_error("error while reading file: " + path.string());
    }
}

int nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

Finding make_finding(const std::string& subject, Severity severity, const std::string& detector,
                     double score, nlohmann::json evidence = nlohmann::json::object()) {
    Finding f;
    f.module = "integrity";
    f.detector = detector;
    f.severity = severity;
    f.score = score;
    f.subject = subject;
    f.evidence = std::move(evidence);
    return f;
}

}  // namespace

KeyPair generate_keypair() {
    ensure_init();
    KeyPair kp;
    kp.public_key.resize(crypto_sign_PUBLICKEYBYTES);
    kp.secret_key.resize(crypto_sign_SECRETKEYBYTES);
    crypto_sign_keypair(kp.public_key.data(), kp.secret_key.data());
    return kp;
}

std::string to_hex(const Bytes& bytes) {
    static const char* digits = "0123456789abcdef";
    std::string s;
    s.reserve(bytes.size() * 2);
    for (unsigned char c : bytes) {
        s.push_back(digits[c >> 4]);
        s.push_back(digits[c & 0x0F]);
    }
    return s;
}

Bytes from_hex(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw std::invalid_argument("hex string has odd length");
    }
    Bytes out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        const int hi = nibble(hex[i]);
        const int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            throw std::invalid_argument("hex string has an invalid character");
        }
        out.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return out;
}

std::string sha256_file(const std::filesystem::path& path) {
    ensure_init();
    crypto_hash_sha256_state state;
    crypto_hash_sha256_init(&state);
    for_each_chunk(path, [&](const unsigned char* data, unsigned long long len) {
        crypto_hash_sha256_update(&state, data, len);
    });
    Bytes digest(crypto_hash_sha256_BYTES);
    crypto_hash_sha256_final(&state, digest.data());
    return to_hex(digest);
}

Bytes sign_file(const std::filesystem::path& path, const Bytes& secret_key) {
    ensure_init();
    if (secret_key.size() != crypto_sign_SECRETKEYBYTES) {
        throw std::invalid_argument("secret key has the wrong length");
    }
    crypto_sign_state state;
    crypto_sign_init(&state);
    for_each_chunk(path, [&](const unsigned char* data, unsigned long long len) {
        crypto_sign_update(&state, data, len);
    });
    Bytes sig(crypto_sign_BYTES);
    unsigned long long sig_len = 0;
    if (crypto_sign_final_create(&state, sig.data(), &sig_len, secret_key.data()) != 0) {
        throw std::runtime_error("signing failed");
    }
    sig.resize(static_cast<std::size_t>(sig_len));
    return sig;
}

bool verify_file(const std::filesystem::path& path, const Bytes& signature,
                 const Bytes& public_key) {
    ensure_init();
    if (signature.size() != crypto_sign_BYTES || public_key.size() != crypto_sign_PUBLICKEYBYTES) {
        return false;
    }
    crypto_sign_state state;
    crypto_sign_init(&state);
    for_each_chunk(path, [&](const unsigned char* data, unsigned long long len) {
        crypto_sign_update(&state, data, len);
    });
    return crypto_sign_final_verify(&state, signature.data(), public_key.data()) == 0;
}

nlohmann::json make_manifest(const std::filesystem::path& model, const Bytes& secret_key) {
    nlohmann::json m;
    m["format"] = 1;
    m["file"] = model.filename().string();
    m["size"] = static_cast<std::uint64_t>(std::filesystem::file_size(model));
    m["sha256"] = sha256_file(model);
    m["signature"] = to_hex(sign_file(model, secret_key));
    return m;
}

std::vector<Finding> verify_manifest(const std::filesystem::path& model,
                                     const nlohmann::json& manifest,
                                     const Bytes& public_key) {
    ensure_init();
    std::vector<Finding> out;
    const std::string subject = model.filename().string();

    if (!std::filesystem::exists(model)) {
        out.push_back(make_finding(subject, Severity::Critical, "file_missing", 1.0));
        return out;
    }

    const bool manifest_ok = manifest.is_object() &&
                             manifest.contains("sha256") && manifest.at("sha256").is_string() &&
                             manifest.contains("size") && manifest.at("size").is_number_unsigned() &&
                             manifest.contains("signature") && manifest.at("signature").is_string();
    if (!manifest_ok) {
        out.push_back(make_finding(subject, Severity::Critical, "manifest_invalid", 1.0));
        return out;
    }

    const auto actual_size = static_cast<std::uint64_t>(std::filesystem::file_size(model));
    const auto expected_size = manifest.at("size").get<std::uint64_t>();
    if (actual_size != expected_size) {
        nlohmann::json ev;
        ev["expected"] = expected_size;
        ev["actual"] = actual_size;
        out.push_back(make_finding(subject, Severity::Critical, "size_mismatch", 1.0, ev));
    }

    const std::string actual_hash = sha256_file(model);
    const std::string expected_hash = manifest.at("sha256").get<std::string>();
    if (actual_hash != expected_hash) {
        nlohmann::json ev;
        ev["expected"] = expected_hash;
        ev["actual"] = actual_hash;
        out.push_back(make_finding(subject, Severity::Critical, "hash_mismatch", 1.0, ev));
    }

    Bytes sig;
    bool sig_parsed = true;
    try {
        sig = from_hex(manifest.at("signature").get<std::string>());
    } catch (const std::invalid_argument&) {
        sig_parsed = false;
    }
    if (!sig_parsed) {
        out.push_back(make_finding(subject, Severity::Critical, "signature_malformed", 1.0));
    } else if (!verify_file(model, sig, public_key)) {
        out.push_back(make_finding(subject, Severity::Critical, "signature_invalid", 1.0));
    }

    if (out.empty()) {
        out.push_back(make_finding(subject, Severity::Info, "verified", 0.0));
    }
    return out;
}

}  // namespace modelguard::integrity
