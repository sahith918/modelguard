#pragma once
#include <filesystem>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "modelguard/core/finding.hpp"

namespace modelguard::integrity {

using Bytes = std::vector<unsigned char>;

struct KeyPair {
    Bytes public_key;   // share this with whoever verifies the model
    Bytes secret_key;   // keep this private
};

KeyPair generate_keypair();

std::string to_hex(const Bytes& bytes);
Bytes from_hex(const std::string& hex);  // throws std::invalid_argument on bad input

// SHA-256 of a file, as lowercase hex. Reads the file in chunks.
std::string sha256_file(const std::filesystem::path& path);

// Ed25519 signature over the whole file (streamed, so large models are fine).
Bytes sign_file(const std::filesystem::path& path, const Bytes& secret_key);
bool verify_file(const std::filesystem::path& path, const Bytes& signature,
                 const Bytes& public_key);

// Manifest = small JSON describing the model file: name, size, hash, signature.
nlohmann::json make_manifest(const std::filesystem::path& model, const Bytes& secret_key);

// Checks a model file against its manifest and public key.
// Returns one Info finding ("verified") if all is well, otherwise Critical findings.
std::vector<Finding> verify_manifest(const std::filesystem::path& model,
                                     const nlohmann::json& manifest,
                                     const Bytes& public_key);

}  // namespace modelguard::integrity
