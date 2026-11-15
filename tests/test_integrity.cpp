#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <stdexcept>

#include "modelguard/integrity/signer.hpp"

using namespace modelguard;
namespace ig = modelguard::integrity;
namespace fs = std::filesystem;

namespace {

struct TempFile {
    fs::path path;
    explicit TempFile(const std::string& name, const std::string& content = "")
        : path(fs::temp_directory_path() / ("mg_test_" + name)) {
        if (!content.empty()) write(content);
    }
    ~TempFile() {
        std::error_code ec;
        fs::remove(path, ec);
    }
    void write(const std::string& content) {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        out << content;
    }
};

bool has(const std::vector<Finding>& findings, const std::string& detector) {
    for (const auto& f : findings) {
        if (f.detector == detector) return true;
    }
    return false;
}

}  // namespace

TEST(Integrity, HexRoundTrip) {
    const ig::Bytes b{0x00, 0x01, 0xab, 0xff};
    EXPECT_EQ(ig::to_hex(b), "0001abff");
    EXPECT_EQ(ig::from_hex("0001ABFF"), b);
    EXPECT_THROW(ig::from_hex("abc"), std::invalid_argument);
    EXPECT_THROW(ig::from_hex("zz"), std::invalid_argument);
}

TEST(Integrity, Sha256KnownVector) {
    TempFile f("sha_abc.bin", "abc");
    EXPECT_EQ(ig::sha256_file(f.path),
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(Integrity, SignedFileVerifies) {
    const auto kp = ig::generate_keypair();
    TempFile f("model_ok.bin", "hello model weights");
    const auto manifest = ig::make_manifest(f.path, kp.secret_key);
    const auto findings = ig::verify_manifest(f.path, manifest, kp.public_key);
    ASSERT_EQ(findings.size(), 1u);
    EXPECT_EQ(findings[0].detector, "verified");
    EXPECT_EQ(findings[0].severity, Severity::Info);
}

TEST(Integrity, SameSizeTamperingIsDetected) {
    const auto kp = ig::generate_keypair();
    TempFile f("model_flip.bin", "hello model weights");
    const auto manifest = ig::make_manifest(f.path, kp.secret_key);
    f.write("hello model weightz");  // one byte changed, same length
    const auto findings = ig::verify_manifest(f.path, manifest, kp.public_key);
    EXPECT_TRUE(has(findings, "hash_mismatch"));
    EXPECT_TRUE(has(findings, "signature_invalid"));
    EXPECT_FALSE(has(findings, "size_mismatch"));
}

TEST(Integrity, AppendedDataIsDetected) {
    const auto kp = ig::generate_keypair();
    TempFile f("model_append.bin", "hello model weights");
    const auto manifest = ig::make_manifest(f.path, kp.secret_key);
    f.write("hello model weights plus extra");
    const auto findings = ig::verify_manifest(f.path, manifest, kp.public_key);
    EXPECT_TRUE(has(findings, "size_mismatch"));
    EXPECT_TRUE(has(findings, "signature_invalid"));
}

TEST(Integrity, WrongPublicKeyIsRejected) {
    const auto signer = ig::generate_keypair();
    const auto other = ig::generate_keypair();
    TempFile f("model_key.bin", "hello model weights");
    const auto manifest = ig::make_manifest(f.path, signer.secret_key);
    const auto findings = ig::verify_manifest(f.path, manifest, other.public_key);
    EXPECT_TRUE(has(findings, "signature_invalid"));
    EXPECT_FALSE(has(findings, "hash_mismatch"));  // file itself is unchanged
}

TEST(Integrity, MissingFileIsReported) {
    const auto kp = ig::generate_keypair();
    const fs::path missing = fs::temp_directory_path() / "mg_test_does_not_exist.bin";
    const auto findings = ig::verify_manifest(missing, nlohmann::json::object(), kp.public_key);
    ASSERT_EQ(findings.size(), 1u);
    EXPECT_EQ(findings[0].detector, "file_missing");
}

TEST(Integrity, BrokenManifestIsReported) {
    const auto kp = ig::generate_keypair();
    TempFile f("model_badmanifest.bin", "hello");
    const auto findings = ig::verify_manifest(f.path, nlohmann::json::object(), kp.public_key);
    ASSERT_EQ(findings.size(), 1u);
    EXPECT_EQ(findings[0].detector, "manifest_invalid");
}
