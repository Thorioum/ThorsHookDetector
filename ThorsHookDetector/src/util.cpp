#include "../include/util.hpp"
#include <sstream>
#include <iomanip>

bool Util::equalsIgnoreCase(const std::string& a, const std::string& b) {
    return std::equal(a.begin(), a.end(), b.begin(), b.end(),
        [](char c1, char c2) {
            return std::tolower(c1) == std::tolower(c2);
        });
}

bool Util::byteVectorsEqual(const std::vector<BYTE>& vec1, const std::vector<BYTE>& vec2) {
    if (vec1.size() != vec2.size()) {
        return false;
    }
    return memcmp(vec1.data(), vec2.data(), vec1.size()) == 0;
}

