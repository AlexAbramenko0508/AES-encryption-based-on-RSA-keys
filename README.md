# **AES-encryption-based-on-RSA-keys**

*Компактный и научно-обоснованный набор инструментов для шифрования файлов*

---

<div align="center">

| 🔒 | 🔑 | 🧪 | 🚀 |
|---|---|---|---|
| **AES-256-CBC** | **RSA-2048** | **SHA-256 / PBKDF2-HMAC** | **C++20 / OpenSSL** |

</div>

`AES-encryption-based-on-RSA-keys` — это заголовочная библиотека **и** однокомандная CLI-утилита, превращающая любой файл в нечитаемый блоб с гарантированной конфиденциальностью, подлинностью *и* возможностью безопасного обмена ключами.

> **TL;DR** – отдаёшь байты → получаешь байты, которые никто не расшифрует без твоего пароля или приватного ключа.  
> Внутри: AES-256-CBC (PKCS#7-padding), ключ выводится через PBKDF2-HMAC-SHA-256 (10 000 итераций, 128-битная соль), затем при необходимости заворачивается RSA-2048. Встроенный 32-байтный тег SHA-256 защищает от порчи и подмены данных.

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

Формат выходного буфера:
```
tag(32) | salt(16) | iv(16) | ciphertext(N)
```
Опциональный **обмен ключом**:
```
AES-key ── RSA-encrypt (pub) ──►  partner
          ◄── RSA-decrypt (priv) ──
```

Асимметричный этап умышленно **отделён** от симметрического: хотите — игнорируйте, хотите — замените RSA на X25519/ECIES.

---

## 📦 Сборка и тесты
```
git clone https://github.com/AlexAbramenko0508/AES-encryption-based-on-RSA-keys.git
cd AES-encryption-based-on-RSA-keys

cmake -B build -S . -DCMAKE_POLICY_VERSION_MINIMUM=3.5
cmake --build build         # builds lib + cli + tests
ctest --test-dir build -V   # doctest banner, 3/3 tests pass
```
<details> <summary>Пример запуска тестов</summary>

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

## 🚀 Использование CLI

```
# симметричное шифрование
./filecrypt_cli enc secret.pdf secret.enc "Tr0ub4dor&3"

# расшифрование (проверяется целостность; неверный пароль → ненулевой код выхода)
./filecrypt_cli dec secret.enc recovered.pdf "Tr0ub4dor&3"
```

Обмен с Алиcой без раскрытия пароля

```
./filecrypt_cli genkeys alice             # alice_priv.pem & alice_pub.pem
./filecrypt_cli wrapkey secret.enc alice_pub.pem wrapped.bin   # обёртка AES-ключа
# отправляем secret.enc + wrapped.bin Алисе
# Алиса восстанавливает ключ:
./filecrypt_cli unwrapkey wrapped.bin alice_priv.pem key.bin
```

(`genkeys`, `wrapkey`, `unwrapkey`— это подкоманды того же бинарника; `--help` покажет все)

## 🔐 Дисклеймер безопасности

`AES-encryption-based-on-RSA-keys` следует современным best-practice, **но не заменяет зрелые, аудированные решения** вроде *age*, *gocryptfs* или *libsodium*. Используйте как справочник, учебный пример или лёгкую утилиту; **не храните коды запуска ракет.**
