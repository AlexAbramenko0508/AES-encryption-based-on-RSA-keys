# **AES-encryption-based-on-RSA-keys**

*Компактный и научно-обоснованный набор инструментов для шифрования файлов*

---

<div align="center">

| 🔒 | 🔑 | 🧪 | 🚀 |
|---|---|---|---|
| **AES-256-CBC** | **RSA-2048** | **SHA-256 / PBKDF2-HMAC** | **C++20 / OpenSSL** |

</div>

`file-crypt` — это заголовочная библиотека **и** однокомандная CLI-утилита, превращающая любой файл в нечитаемый блоб с гарантированной конфиденциальностью, подлинностью *и* возможностью безопасного обмена ключами.

> **TL;DR** – отдаёшь байты → получаешь байты, которые никто не расшифрует без твоего пароля или приватного ключа.  
> Внутри: AES-256-CBC (PKCS#7-padding), ключ выводится через PBKDF2-HMAC-SHA-256 (10 000 итераций, 128-битная соль), затем при необходимости заворачивается RSA-2048. Встроенный 32-байтный тег SHA-256 защищает от порчи и подмены данных.

---

## ✨ Зачем ещё один «велосипед»?

* **Учебная ценность** – ~250 строк демонстрируют, как безопасно подружить OpenSSL без `new/delete`.  
* **Аудируемость** – без макросов и глобальных одиночек, везде RAII.  
* **Кроссплатформа** – GCC ≥ 10, Clang ≥ 13, MSVC ≥ 19.29, Apple Silicon.  
* **Самопроверка** – юнит-тесты покрывают как «счастливые» сценарии, так и злонамеренные (неверный пароль, повреждённый тег).  
* **CI-friendly** – `FetchContent` подтягивает doctest автоматически; не нужен пакетный менеджер.

---

## 🔬 Криптографический рецепт

```
              ┌────────────┐              ┌──────────────────┐
PLAINTEXT ──► │ PBKDF2-HMAC│── password ─►│   256-bit key    │
              └─────▲──────┘              └────────┬─────────┘
                    │      salt(128-bit)           │
                    │                              ▼
                 ┌──┴────────────────────────────────────┐
                 │       AES-256-CBC   (16-byte IV)      │
                 └──┬───────────────────────────────────┬┘
   iv ══════════════╯                                   │
                                                        ▼
              ┌──────────────────────────────────────────┐
              │  SHA-256( iv ∥ salt ∥ ciphertext ) = tag │
              └──────────────────────────────────────────┘
```

Resulting layout:
```
tag(32) | salt(16) | iv(16) | ciphertext(N)
```
Optional key exchange:
```
AES-key ── RSA-encrypt (pub) ──►  partner
          ◄── RSA-decrypt (priv) ──
```

The asymmetric stage is deliberately decoupled from the symmetric codec: you may ignore it entirely or swap RSA for X25519/ECIES later.

---

## 📦 Build & test
```
git clone https://github.com/<you>/file-crypt.git
cd file-crypt

cmake -B build -S .
cmake --build build         # builds lib + cli + tests
ctest --test-dir build -V   # doctest banner, 3/3 tests pass
```
<details> <summary>Typical test run</summary>

  ```
[doctest] doctest version is 2.4.11
[doctest] run with "--help" for options
===============================================================================
tests.cpp:5:
TEST CASE:  AES round-trip
...
[doctest] test cases:      3 |      3 passed | 0 failed | 0 skipped
[doctest] assertions:      7 |      7 passed | 0 failed
```
</details>

## 🚀 CLI usage

```
# symmetric encryption
./filecrypt_cli enc secret.pdf secret.enc "Tr0ub4dor&3"

# decryption (integrity checked, wrong pass → non-zero exit code)
./filecrypt_cli dec secret.enc recovered.pdf "Tr0ub4dor&3"
```

Advanced example – share a file with Alice without leaking your pass-phrase:

```
./filecrypt_cli genkeys alice             # prints alice_priv.pem & alice_pub.pem
./filecrypt_cli wrapkey secret.enc alice_pub.pem wrapped.bin   # encrypt AES-key
# send secret.enc + wrapped.bin to Alice
# Alice recovers AES-key:
./filecrypt_cli unwrapkey wrapped.bin alice_priv.pem key.bin
```

(`genkeys`, `wrapkey`, `unwrapkey` are sub-commands exposed by the same binary; see `--help` for all options)

## 🔐 Security disclaimer

`AES-encryption-based-on-RSA-keys` follows modern best-practices but **is not a replacement for mature audited products** like age, gocryptfs or libsodium. Use it as a reference, tutorial, or lightweight utility; **do not store the nuclear launch codes.**
