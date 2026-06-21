# AES

Программная модель алгоритма симметричного шифрования AES (Advanced Encryption Standard), реализованная на языке С в соответствии со стандартом FIPS-197.

## Содержание

* [Документация](https://github.com/Dimakdrshv/AES_System_Model#%D0%B4%D0%BE%D0%BA%D1%83%D0%BC%D0%B5%D0%BD%D1%82%D0%B0%D1%86%D0%B8%D1%8F)
* [Реализованные функции](https://github.com/Dimakdrshv/AES_System_Model#%D1%80%D0%B5%D0%B0%D0%BB%D0%B8%D0%B7%D0%BE%D0%B2%D0%B0%D0%BD%D0%BD%D1%8B%D0%B5-%D1%84%D1%83%D0%BD%D0%BA%D1%86%D0%B8%D0%B8)
* [Структура проекта](https://github.com/Dimakdrshv/AES_System_Model#%D1%80%D0%B5%D0%B0%D0%BB%D0%B8%D0%B7%D0%BE%D0%B2%D0%B0%D0%BD%D0%BD%D1%8B%D0%B5-%D1%84%D1%83%D0%BD%D0%BA%D1%86%D0%B8%D0%B8)
* [Сборка проекта](https://github.com/Dimakdrshv/AES_System_Model#%D1%80%D0%B5%D0%B0%D0%BB%D0%B8%D0%B7%D0%BE%D0%B2%D0%B0%D0%BD%D0%BD%D1%8B%D0%B5-%D1%84%D1%83%D0%BD%D0%BA%D1%86%D0%B8%D0%B8)
  * [AES-128](https://github.com/Dimakdrshv/AES_System_Model#%D1%80%D0%B5%D0%B0%D0%BB%D0%B8%D0%B7%D0%BE%D0%B2%D0%B0%D0%BD%D0%BD%D1%8B%D0%B5-%D1%84%D1%83%D0%BD%D0%BA%D1%86%D0%B8%D0%B8)
  * [AES-192](https://github.com/Dimakdrshv/AES_System_Model#%D1%80%D0%B5%D0%B0%D0%BB%D0%B8%D0%B7%D0%BE%D0%B2%D0%B0%D0%BD%D0%BD%D1%8B%D0%B5-%D1%84%D1%83%D0%BD%D0%BA%D1%86%D0%B8%D0%B8)
  * [AES-256](https://github.com/Dimakdrshv/AES_System_Model#%D1%80%D0%B5%D0%B0%D0%BB%D0%B8%D0%B7%D0%BE%D0%B2%D0%B0%D0%BD%D0%BD%D1%8B%D0%B5-%D1%84%D1%83%D0%BD%D0%BA%D1%86%D0%B8%D0%B8)
* [Запуск модели](https://github.com/Dimakdrshv/AES_System_Model#%D1%80%D0%B5%D0%B0%D0%BB%D0%B8%D0%B7%D0%BE%D0%B2%D0%B0%D0%BD%D0%BD%D1%8B%D0%B5-%D1%84%D1%83%D0%BD%D0%BA%D1%86%D0%B8%D0%B8)
* [Тестирование](https://github.com/Dimakdrshv/AES_System_Model#%D1%80%D0%B5%D0%B0%D0%BB%D0%B8%D0%B7%D0%BE%D0%B2%D0%B0%D0%BD%D0%BD%D1%8B%D0%B5-%D1%84%D1%83%D0%BD%D0%BA%D1%86%D0%B8%D0%B8)
* [Используемые ресурсы](https://github.com/Dimakdrshv/AES_System_Model#%D1%80%D0%B5%D0%B0%D0%BB%D0%B8%D0%B7%D0%BE%D0%B2%D0%B0%D0%BD%D0%BD%D1%8B%D0%B5-%D1%84%D1%83%D0%BD%D0%BA%D1%86%D0%B8%D0%B8)
* [Лицензия](https://github.com/Dimakdrshv/AES_System_Model#%D1%80%D0%B5%D0%B0%D0%BB%D0%B8%D0%B7%D0%BE%D0%B2%D0%B0%D0%BD%D0%BD%D1%8B%D0%B5-%D1%84%D1%83%D0%BD%D0%BA%D1%86%D0%B8%D0%B8)

## Документация

С документацией работы устройства можно ознакомиться по ссылке: [документация](https://github.com/Dimakdrshv/AES_System_Model/wiki/%D0%94%D0%BE%D0%BA%D1%83%D0%BC%D0%B5%D0%BD%D1%82%D0%B0%D1%86%D0%B8%D1%8F).

## Реализованные функции

1. AES-128 encryption/decryption.
2. AES-192 encryption/decryption.
3. AES-256 encryption/decryption.
4. Автоматизированное тестирование с использованием CTest.

## Структура проекта

* include/ - заголовочные файлы;
* src/ - исходные файлы;
* test/ - автоматизированные тесты;
* docs/ - документация NIST.

## Сборка проекта

Размер ключа для основного приложения выбирается на этапе конфигурирования CMake.

### AES-128

```bash
cmake -S . -B build -G "MinGW Makefiles" -DAES_KEY_SIZE=128
cmake --build build
```

### AES-192

```bash
cmake -S . -B build -G "MinGW Makefiles" -DAES_KEY_SIZE=192
cmake --build build
```

### AES-256

```bash
cmake -S . -B build -G "MinGW Makefiles" -DAES_KEY_SIZE=256
cmake --build build
```

## Запуск модели

```bash
./build/aes_model.exe
```

После запуска необходимо ввести ключ и входные данные в шестнадцатеричном формате.

## Тестирование

Для проверки корректности работы реализованы автоматизированные тесты для конфигураций AES-128, AES-192 и AES-256.

Запуск тестирования:

```bash
ctest --test-dir build --verbose
```

При выполнении тестов производится многократное шифрование и дешифрование случайно сгенерированных данных с последующей проверкой совпадения исходного и восстановленного текста.

## Используемые ресурсы

Based on FIPS-197 (Advanced Encryption Standard) and publicly available cryptographic reference materials.

Used for non-commercial educational purposes.

## Лицензия

MIT License.

