cmake_minimum_required(VERSION 3.5)
project(file-crypt LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra -pedantic)

# ---------- OpenSSL --------------------------------------------------------
find_package(OpenSSL REQUIRED QUIET)

# ---------- doctest: сначала ищем, при отсутствии — FetchContent -----------

find_package(doctest CONFIG QUIET)

if(NOT doctest_FOUND)
    include(FetchContent)

    # полноценный архив с CMake-скриптами doctest
    FetchContent_Declare(
        doctest
        URL https://github.com/doctest/doctest/archive/refs/tags/v2.4.11.tar.gz
        # при желании укажите URL_HASH SHA256=<хеш>
    )
    FetchContent_MakeAvailable(doctest)   # добавит target doctest::doctest
endif()

# ---------- библиотека -----------------------------------------------------
add_library(filecrypt STATIC crypto.cpp)
target_include_directories(filecrypt PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(filecrypt PUBLIC OpenSSL::SSL OpenSSL::Crypto)

# ---------- CLI ------------------------------------------------------------
add_executable(filecrypt_cli main.cpp)
target_link_libraries(filecrypt_cli PRIVATE filecrypt)

# ---------- тесты ----------------------------------------------------------
enable_testing()
add_executable(filecrypt_tests tests.cpp)
target_link_libraries(filecrypt_tests PRIVATE filecrypt doctest::doctest)
add_test(NAME all COMMAND filecrypt_tests)
