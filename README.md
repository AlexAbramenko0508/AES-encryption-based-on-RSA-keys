# file-crypt

CLI-утилита и библиотека на C++20 для шифрования файлов:
* AES-256-CBC + пароль → конфиденциальность  
* RSA-2048 → безопасная передача ключа  
* SHA-256 → контроль целостности  

## Сборка

```bash
git clone https://github.com/you/file-crypt.git
cd file-crypt
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake
cmake --build build
ctest --test-dir build      # прогон тестов