#include "crypto.hpp"

#include <fstream>
#include <iostream>
#include <iterator>

static fc::Buffer read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

static void write_file(const std::string& path, const fc::Buffer& buf) {
    std::ofstream f(path, std::ios::binary);
    f.write(reinterpret_cast<const char*>(buf.data()), buf.size());
}

int main(int argc, char* argv[]) try {
    if (argc != 5) {
        std::cerr << "Usage: filecrypt_cli (enc|dec) <in> <out> <password>\n";
        return 1;
    }
    const bool enc = std::string_view(argv[1]) == "enc";
    auto data = read_file(argv[2]);
    auto out  = enc ? fc::aes_encrypt(data, argv[4])
                    : fc::aes_decrypt(data, argv[4]);
    write_file(argv[3], out);
    std::cout << (enc ? "Encrypted" : "Decrypted") << " OK\n";
    return 0;
} catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << '\n';
    return 2;
}
