cmake_minimum_required(VERSION 3.10)
project(VulnDriverScanner)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(VulnDriverScanner 
    src/main.cpp
    src/driver_scanner.cpp
    src/string_utils.cpp
)

target_link_libraries(VulnDriverScanner PRIVATE winhttp) 
target_include_directories(VulnDriverScanner PRIVATE src) 