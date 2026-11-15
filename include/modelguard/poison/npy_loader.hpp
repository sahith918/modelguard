#pragma once
#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

namespace modelguard::poison {

// A NumPy .npy array, with every value converted to double (row-major).
struct NpyArray {
    std::string dtype;               // e.g. "<f4"
    std::vector<std::size_t> shape;  // empty for a scalar
    std::vector<double> data;
};

// Supports little-endian f4, f8, i4, i8, u1, b1 in C order.
// Throws std::runtime_error with a readable message otherwise.
NpyArray load_npy(const std::filesystem::path& path);

}  // namespace modelguard::poison
