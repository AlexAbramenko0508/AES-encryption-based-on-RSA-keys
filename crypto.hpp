#pragma once
/** @file  crypto.hpp
    @brief Мини-API для AES-256-CBC и RSA-2048 на базе OpenSSL.

    Все функции бросают std::runtime_error при любой ошибке.
*/
#include <array>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace fc {
using Buffer = std::vector<uint8_t>;               ///< удобный alias байтового вектора

/** @brief SHA-256 от произвольного буфера. */
[[nodiscard]] std::array<uint8_t, 32> sha256(const Buffer& data);

/** @brief AES-256-CBC + PBKDF2.
    @return salt(16)|iv(16)|cipher */
[[nodiscard]] Buffer aes_encrypt(const Buffer& plaintext,
                                 const std::string& password);

/** @brief Расшифровка буфера формата salt|iv|cipher. */
[[nodiscard]] Buffer aes_decrypt(const Buffer& ciphertext,
                                 const std::string& password);

/** @brief Сгенерировать RSA-2048 PEM-пару {priv, pub}. */
[[nodiscard]] std::pair<std::string, std::string> rsa_generate_keypair();

/** @brief Зашифровать симметричный ключ публичным PEM. */
[[nodiscard]] Buffer rsa_encrypt_key(const Buffer& key,
                                     const std::string& pub_pem);

/** @brief Расшифровать симметричный ключ приватным PEM. */
[[nodiscard]] Buffer rsa_decrypt_key(const Buffer& enc_key,
                                     const std::string& priv_pem);

} // namespace fc
