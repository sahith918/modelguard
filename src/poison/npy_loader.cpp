#include "modelguard/poison/npy_loader.hpp"

#include <cstdint>
#include <cstring>
#include <fstream>
#include <stdexcept>

namespace modelguard::poison {

namespace {

std::string value_after_key(const std::string& header, const std::string& key) {
    const auto k = header.find("'" + key + "'");
    if (k == std::string::npos) {
        throw std::runtime_error(".npy header is missing '" + key + "'");
    }
    const auto colon = header.find(':', k);
    if (colon == std::string::npos) {
        throw std::runtime_error(".npy header is malformed");
    }
    return header.substr(colon + 1);
}

template <typename T>
void convert(const std::vector<char>& raw, std::size_t count, std::vector<double>& out) {
    out.resize(count);
    for (std::size_t i = 0; i < count; ++i) {
        T v;
        std::memcpy(&v, raw.data() + i * sizeof(T), sizeof(T));
        out[i] = static_cast<double>(v);
    }
}

}  // namespace

NpyArray load_npy(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open file: " + path.string());

    char magic[6];
    in.read(magic, 6);
    if (!in || static_cast<unsigned char>(magic[0]) != 0x93 || std::memcmp(magic + 1, "NUMPY", 5) != 0) {
        throw std::runtime_error("not a .npy file: " + path.string());
    }

    unsigned char ver[2];
    in.read(reinterpret_cast<char*>(ver), 2);
    std::uint32_t header_len = 0;
    if (ver[0] == 1) {
        unsigned char b[2];
        in.read(reinterpret_cast<char*>(b), 2);
        header_len = static_cast<std::uint32_t>(b[0]) | (static_cast<std::uint32_t>(b[1]) << 8);
    } else {
        unsigned char b[4];
        in.read(reinterpret_cast<char*>(b), 4);
        header_len = static_cast<std::uint32_t>(b[0]) | (static_cast<std::uint32_t>(b[1]) << 8) |
                     (static_cast<std::uint32_t>(b[2]) << 16) | (static_cast<std::uint32_t>(b[3]) << 24);
    }
    if (!in) throw std::runtime_error("truncated .npy header: " + path.string());

    std::string header(header_len, '\0');
    in.read(header.data(), static_cast<std::streamsize>(header_len));
    if (!in) throw std::runtime_error("truncated .npy header: " + path.string());

    // dtype string, e.g. '<f4'
    const std::string descr_part = value_after_key(header, "descr");
    const auto q1 = descr_part.find('\'');
    const auto q2 = (q1 == std::string::npos) ? q1 : descr_part.find('\'', q1 + 1);
    if (q2 == std::string::npos) throw std::runtime_error(".npy descr is malformed");
    NpyArray arr;
    arr.dtype = descr_part.substr(q1 + 1, q2 - q1 - 1);

    // fortran_order
    const std::string fo = value_after_key(header, "fortran_order");
    const auto fo_start = fo.find_first_not_of(' ');
    const bool fortran = (fo_start != std::string::npos) && fo.compare(fo_start, 4, "True") == 0;

    // shape, e.g. (2000, 32) or (2000,)
    const std::string shape_part = value_after_key(header, "shape");
    const auto open = shape_part.find('(');
    const auto close = shape_part.find(')');
    if (open == std::string::npos || close == std::string::npos || close < open) {
        throw std::runtime_error(".npy shape is malformed");
    }
    std::size_t cur = 0;
    bool have = false;
    for (std::size_t i = open + 1; i < close; ++i) {
        const char c = shape_part[i];
        if (c >= '0' && c <= '9') {
            cur = cur * 10 + static_cast<std::size_t>(c - '0');
            have = true;
        } else if (c == ',') {
            if (have) arr.shape.push_back(cur);
            cur = 0;
            have = false;
        }
    }
    if (have) arr.shape.push_back(cur);

    if (fortran && arr.shape.size() > 1) {
        throw std::runtime_error("Fortran-ordered .npy files are not supported "
                                 "(save with np.ascontiguousarray)");
    }
    if (arr.dtype.size() < 3 || arr.dtype[0] == '>') {
        throw std::runtime_error("unsupported .npy dtype '" + arr.dtype + "' (need little-endian)");
    }

    const char kind = arr.dtype[1];
    const int size = std::stoi(arr.dtype.substr(2));
    std::size_t count = 1;
    for (std::size_t s : arr.shape) count *= s;

    std::vector<char> raw(count * static_cast<std::size_t>(size));
    in.read(raw.data(), static_cast<std::streamsize>(raw.size()));
    if (static_cast<std::size_t>(in.gcount()) != raw.size()) {
        throw std::runtime_error(".npy file is shorter than its header says: " + path.string());
    }

    if (kind == 'f' && size == 4)      convert<float>(raw, count, arr.data);
    else if (kind == 'f' && size == 8) convert<double>(raw, count, arr.data);
    else if (kind == 'i' && size == 4) convert<std::int32_t>(raw, count, arr.data);
    else if (kind == 'i' && size == 8) convert<std::int64_t>(raw, count, arr.data);
    else if ((kind == 'u' || kind == 'b') && size == 1) convert<std::uint8_t>(raw, count, arr.data);
    else throw std::runtime_error("unsupported .npy dtype '" + arr.dtype + "'");

    return arr;
}

}  // namespace modelguard::poison
