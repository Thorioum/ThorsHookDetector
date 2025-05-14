#include "../include/util.hpp"
#include <sstream>
#include <iomanip>

bool Util::equalsIgnoreCase(const std::string& a, const std::string& b) {
    return std::equal(a.begin(), a.end(), b.begin(), b.end(),
        [](char c1, char c2) {
            return std::tolower(c1) == std::tolower(c2);
        });
}
std::string Util::toByteString(const std::vector<BYTE>& vec) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');

    for (BYTE b : vec) {
        oss << std::setw(2) << static_cast<int>(b);
        oss << " ";
    }

    std::string result = oss.str();

    if (!result.empty()) {
        result.pop_back();
    }
    return result;
}

bool Util::byteVectorsEqual(const std::vector<BYTE>& vec1, const std::vector<BYTE>& vec2) {
    if (vec1.size() != vec2.size()) {
        return false;
    }
    return memcmp(vec1.data(), vec2.data(), vec1.size()) == 0;
}

std::string Util::toHexString(ULONGLONG value)
{
    std::stringstream ss;
    ss << std::hex << value;
    return "0x" + ss.str();
}

std::vector<std::string> Util::split(std::string string, char delimeter) {
	std::vector<std::string> args;
	std::stringstream ss(string);
	std::string token;
	while (std::getline(ss, token, delimeter)) {
		args.push_back(token);
	}
	return args;
}
