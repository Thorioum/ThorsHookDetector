#pragma once
#include <string>
#include <vector>
#include <wtypes.h>
#include <unordered_map>
#include <sstream>
#include <iostream>

namespace Util {

    bool equalsIgnoreCase(const std::string& a, const std::string& b);
    bool byteVectorsEqual(const std::vector<BYTE>& vec1, const std::vector<BYTE>& vec2);

    std::string toByteString(const std::vector<BYTE>& vec);
	std::string toHexString(ULONGLONG value);

    template<typename Key, typename Value>
    ULONGLONG countMatchingKeys(const std::unordered_map<Key, Value>& map1, const std::unordered_map<Key, Value>& map2) {
        ULONGLONG matching = 0;
        for (auto& element : map1) {
            if (map2.count(element.first)) {
                matching++;
            }
        }
        return matching;
    }

    std::vector<std::string> split(std::string string, char delimeter);
}