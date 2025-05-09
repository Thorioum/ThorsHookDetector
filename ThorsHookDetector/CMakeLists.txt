# CMakeList.txt : CMake project for ThorsHookDetector, include source and define
# project specific logic here.
#

# Add source to this project's executable.
add_executable (ThorsHookDetector "src/main.cpp"  "src/memory.cpp" "src/util.cpp" "src/hookhandler.cpp" "src/decompilation.cpp")

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET ThorsHookDetector PROPERTY CXX_STANDARD 20)
endif()

#includes
include(FetchContent)

FetchContent_Declare (
	argparse 
	URL https://github.com/p-ranav/argparse/archive/refs/tags/v3.1.zip
	DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable (argparse)
target_link_libraries(ThorsHookDetector PRIVATE argparse)

FetchContent_Declare (
	capstone 
	URL https://github.com/capstone-engine/capstone/archive/refs/tags/5.0.6.zip
	DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable (capstone)
target_link_libraries(ThorsHookDetector PRIVATE capstone)

FetchContent_Declare (
	spdlog 
	URL https://github.com/gabime/spdlog/archive/refs/tags/v1.15.0.zip
	DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable (spdlog)
target_link_libraries(ThorsHookDetector PRIVATE spdlog::spdlog)