cmake_minimum_required(VERSION 3.20)
project(file-crypt LANGUAGES CXX)

# Компилятор + стандарт
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra -pedantic)

# vcpkg интеграция
include(${CMAKE_TOOLCHAIN_FILE})

find_package(OpenSSL REQUIRED)
find_package(doctest CONFIG REQUIRED)

# Библиотека
add_library(filecrypt STATIC src/Crypto.cpp)
target_include_directories(filecrypt PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(filecrypt PUBLIC OpenSSL::SSL OpenSSL::Crypto)

# CLI-утилита
add_executable(filecrypt_cli src/main.cpp)
target_link_libraries(filecrypt_cli PRIVATE filecrypt)

# Тесты
enable_testing()
add_executable(filecrypt_tests tests/test_crypto.cpp)
target_link_libraries(filecrypt_tests PRIVATE filecrypt doctest::doctest)
add_test(NAME all FILE filecrypt_tests)