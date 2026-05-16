cmake_minimum_required(VERSION 3.16)
project(SecureUAV_C2 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)

pkg_check_modules(GMP REQUIRED gmp)
pkg_check_modules(GMPXX REQUIRED gmpxx)

add_library(crypto_utils STATIC crypto_utils.cpp)

target_include_directories(crypto_utils PUBLIC
    ${GMP_INCLUDE_DIRS}
    ${GMPXX_INCLUDE_DIRS}
)

target_link_libraries(crypto_utils PUBLIC
    ${GMPXX_LIBRARIES}
    ${GMP_LIBRARIES}
    OpenSSL::Crypto
)

add_executable(mcc mcc.cpp)
target_link_libraries(mcc PRIVATE crypto_utils pthread)

add_executable(drone drone.cpp)
target_link_libraries(drone PRIVATE crypto_utils pthread)

add_executable(attacks attacks.cpp)
target_link_libraries(attacks PRIVATE crypto_utils pthread)