#pragma once
#include <string>
#include <vector>
#include <wtypes.h>

namespace Util {

    bool equalsIgnoreCase(const std::string& a, const std::string& b);
    bool byteVectorsEqual(const std::vector<BYTE>& vec1, const std::vector<BYTE>& vec2);
    std::string toByteString(const std::vector<BYTE>& vec);
}