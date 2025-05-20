#include "crypto.hpp"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace {

/*--------------------- RAII-утилиты ---------------------------------------*/
struct EVP_CTX {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CTX() = default;
    EVP_CTX(const EVP_CTX&) = delete;
    EVP_CTX& operator=(const EVP_CTX&) = delete;
    ~EVP_CTX() { EVP_CIPHER_CTX_free(ctx); }
};

[[nodiscard]] std::runtime_error ossl_err(const char* msg) {
    return std::runtime_error(msg);
}

} // namespace

/*--------------------- SHA-256 --------------------------------------------*/
std::array<uint8_t, 32> fc::sha256(const Buffer& data) {
    std::array<uint8_t, 32> out{};
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    if (!md ||
        !EVP_DigestInit_ex(md, EVP_sha256(), nullptr) ||
        !EVP_DigestUpdate(md, data.data(), data.size()) ||
        !EVP_DigestFinal_ex(md, out.data(), nullptr)) {
        EVP_MD_CTX_free(md);
        throw ossl_err("SHA-256 failed");
    }
    EVP_MD_CTX_free(md);
    return out;
}

/*--------------------- AES-256-CBC ----------------------------------------*/
fc::Buffer fc::aes_encrypt(const Buffer& plaintext,
                           const std::string& password) {
    constexpr size_t SALT_LEN = 16, IV_LEN = 16;
    uint8_t salt[SALT_LEN], iv[IV_LEN];
    RAND_bytes(salt, SALT_LEN);
    RAND_bytes(iv, IV_LEN);

    /* PBKDF2-HMAC-SHA1 → 32-байтный ключ */
    uint8_t key[32];
    if (!PKCS5_PBKDF2_HMAC(password.c_str(), password.size(),
                           salt, SALT_LEN,
                           /*iter*/ 10'000,
                           EVP_sha256(), sizeof(key), key))
        throw ossl_err("PBKDF2");

    EVP_CTX e;
    if (!EVP_EncryptInit_ex(e.ctx, EVP_aes_256_cbc(), nullptr, key, iv))
        throw ossl_err("EncryptInit");

    Buffer cipher(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int len = 0, total = 0;
    if (!EVP_EncryptUpdate(e.ctx, cipher.data(), &len,
                           plaintext.data(), plaintext.size()))
        throw ossl_err("EncryptUpdate");
    total = len;
    if (!EVP_EncryptFinal_ex(e.ctx, cipher.data() + len, &len))
        throw ossl_err("EncryptFinal");
    total += len;
    cipher.resize(total);

    Buffer out;
    out.insert(out.end(), salt, salt + SALT_LEN);
    out.insert(out.end(), iv, iv + IV_LEN);
    out.insert(out.end(), cipher.begin(), cipher.end());
    return out;
}

fc::Buffer fc::aes_decrypt(const Buffer& ciphertext,
                           const std::string& password) {
    if (ciphertext.size() < 32)
        throw std::runtime_error("cipher too short");

    const uint8_t* salt = ciphertext.data();
    const uint8_t* iv   = salt + 16;
    const uint8_t* enc  = iv + 16;
    size_t enc_len = ciphertext.size() - 32;

    uint8_t key[32];
    if (!PKCS5_PBKDF2_HMAC(password.c_str(), password.size(),
                           salt, 16,
                           10'000, EVP_sha256(), sizeof(key), key))
        throw ossl_err("PBKDF2");

    EVP_CTX d;
    if (!EVP_DecryptInit_ex(d.ctx, EVP_aes_256_cbc(), nullptr, key, iv))
        throw ossl_err("DecryptInit");

    Buffer plain(enc_len);
    int len = 0, total = 0;
    if (!EVP_DecryptUpdate(d.ctx, plain.data(), &len, enc, enc_len))
        throw ossl_err("DecryptUpdate");
    total = len;
    if (!EVP_DecryptFinal_ex(d.ctx, plain.data() + len, &len))
        throw std::runtime_error("bad password or data");
    total += len;
    plain.resize(total);
    return plain;
}

/*--------------------- RSA -------------------------------------------------*/
std::pair<std::string, std::string> fc::rsa_generate_keypair() {
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY*     pkey = nullptr;
    if (!kctx || !EVP_PKEY_keygen_init(kctx) ||
        !EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048) ||
        !EVP_PKEY_keygen(kctx, &pkey))
        throw ossl_err("RSA keygen");

    auto to_pem = [](EVP_PKEY* k, bool priv) {
        BIO* bio = BIO_new(BIO_s_mem());
        if (priv) PEM_write_bio_PrivateKey(bio, k, nullptr, nullptr, 0, nullptr, nullptr);
        else      PEM_write_bio_PUBKEY(bio, k);
        BUF_MEM* mem = nullptr;
        BIO_get_mem_ptr(bio, &mem);
        std::string pem(mem->data, mem->length);
        BIO_free(bio);
        return pem;
    };
    std::string priv_pem = to_pem(pkey, true);
    std::string pub_pem  = to_pem(pkey, false);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(kctx);
    return {priv_pem, pub_pem};
}

fc::Buffer fc::rsa_encrypt_key(const Buffer& key,
                               const std::string& pub_pem) {
    BIO* bio = BIO_new_mem_buf(pub_pem.data(), pub_pem.size());
    EVP_PKEY* pub = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    if (!pub) throw ossl_err("bad pub pem");
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pub, nullptr);
    if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0)
        throw ossl_err("encrypt_init");

    size_t outlen = 0;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, key.data(), key.size()) <= 0)
        throw ossl_err("enc size");
    Buffer out(outlen);
    if (EVP_PKEY_encrypt(ctx, out.data(), &outlen, key.data(), key.size()) <= 0)
        throw ossl_err("enc");
    out.resize(outlen);
    EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(pub); BIO_free(bio);
    return out;
}

fc::Buffer fc::rsa_decrypt_key(const Buffer& enc_key,
                               const std::string& priv_pem) {
    BIO* bio = BIO_new_mem_buf(priv_pem.data(), priv_pem.size());
    EVP_PKEY* priv = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    if (!priv) throw ossl_err("bad priv pem");
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv, nullptr);
    if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0)
        throw ossl_err("decrypt_init");

    size_t outlen = 0;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, enc_key.data(), enc_key.size()) <= 0)
        throw ossl_err("dec size");
    Buffer out(outlen);
    if (EVP_PKEY_decrypt(ctx, out.data(), &outlen, enc_key.data(), enc_key.size()) <= 0)
        throw ossl_err("dec");
    out.resize(outlen);
    EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(priv); BIO_free(bio);
    return out;
}
