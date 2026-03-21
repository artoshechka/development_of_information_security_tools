# Лабораторная работа по предмету: "Разработка средств защиты информации"
## Тема: "Рекурсивный шифратор/дешифратор"
> 4 курс 2 семестр \
> Студент группы 932223 - Артеменко Антон Дмитриевич 

## Постановка задачи
> Реализовать защиту данных пользовательских папок и файлов, находящихся в папке, а также под-папках путем шифрования. Для доступа к данным исходной папке необходимо выполнить дешифрование.

## Зависимости проекта
Проект использует следующие сторонние библиотеки:
- **Qt** v5.18
- **OpenSSL** v3.3.6
- **CMake** v3.12 +

## Архитектура решения
Приложение реализовано как консольная программа с использованием классов **Qt Core** и библиотеки **OpenSSL**.

Основные компоненты решения:
- **main.cpp** — точка входа приложения. Проверяет аргументы командной строки, запрашивает пароль пользователя и координирует обработку файлов.
- **RecursiveStepper** — класс, отвечающий за рекурсивный обход целевой директории и построение списка файлов для последующей обработки.
- **ICryptoStrategy / OpenSslCryptoStrategy** — подсистема стратегий шифрования и дешифрования файлов.
- **CryptoManager + фабрики** — менеджер криптографических операций с внедряемой стратегией, создаваемой через tag-based template фабрики и получающей системный логгер по ссылке.
- **AppLogger** — singleton-логгер приложения, который используется в `main.cpp` для фиксации ошибок и ключевых этапов обработки.
- **AppSysLogger** — singleton-логгер подсистем, создается в `main.cpp` и передается в `RecursiveStepper`, `CryptoManager` и `OpenSslCryptoStrategy` через DI.
- **QDirIterator / QFile / QSaveFile + OpenSSL EVP** — используются для обхода файловой системы, потокового чтения/записи файлов, атомарной замены результата и криптографических операций.

## Алгоритм шифрования

Для защиты файла используется схема на базе **PBKDF2 + AES-256-GCM (AEAD)**.

Шаги шифрования:
1. Генерируется случайная соль `salt` (16 байт).
2. Из пользовательского пароля и `salt` через `PBKDF2-HMAC-SHA256` (200000 итераций) выводится 256-битный ключ.
3. Генерируется случайный `nonce` для GCM (12 байт).
4. Файл шифруется потоково алгоритмом `AES-256-GCM`.
5. Вычисляется и сохраняется `GCM tag` (16 байт), который обеспечивает контроль целостности и подлинности.
6. Результат записывается атомарно через `QSaveFile`, чтобы при ошибке исходный файл не был поврежден.

Формат зашифрованного файла:
`MAGIC | SALT | NONCE | CIPHERTEXT | TAG`

Шаги дешифрования:
1. Читаются `MAGIC`, `SALT`, `NONCE`, `CIPHERTEXT`, `TAG`.
2. По паролю и `SALT` повторно выводится ключ через PBKDF2.
3. Выполняется потоковое дешифрование `AES-256-GCM`.
4. На финальном шаге проверяется `TAG`.

Если пароль неверный или файл был изменен, проверка тега завершается ошибкой, операция прерывается, и исходный файл остается без изменений.

## Предлагаемое решение

### UML-диаграмма классов

#### Общая диаграмма
```mermaid
classDiagram
    class MainApplication

    class ILogger {
        <<interface>>
        +SetSettings(settings)
        +GetSettings()
        +Log(level, message, file, line, function)
    }

    class ThreadSafeLogger {
        +ThreadSafeLogger(componentName, output)
        +SetSettings(settings)
        +GetSettings()
        +Log(level, message, file, line, function)
        #FormatMessage(level, message, file, line, function)
    }

    class AppLogger {
        +AppLogger(output)
    }

    class AppSysLogger {
        +AppSysLogger(output)
    }

    class LoggerFactory {
        +GetLogger~AppLoggerTag~()
        +GetLogger~AppSysLoggerTag~()
    }

    class LogEntryStream {
        +LogEntryStream(logger, level, file, line, function)
        +operator<<()
    }

    class LoggerSettings {
        +logFilePath_ : optional~QString~
        +logLevel_ : LogLevel
        +output_ : LogOutput
    }

    class LogLevel {
        <<enumeration>>
        Trace
        Debug
        Info
        Warning
        Error
        Fatal
    }

    class LogOutput {
        <<enumeration>>
        Console
        File
    }

    class OpenSslTag

    class ICryptoStrategy {
        <<interface>>
        +EncryptFile(filePath, password)
        +DecryptFile(filePath, password)
    }

    class OpenSslCryptoStrategy {
        -logger_ : shared_ptr~ILogger~
        +OpenSslCryptoStrategy(const shared_ptr~ILogger~& logger)
        +EncryptFile(filePath, password)
        +DecryptFile(filePath, password)
    }

    class ICryptoManager {
        <<interface>>
        +EncryptFile(filePath, password)
        +DecryptFile(filePath, password)
    }

    class CryptoManager {
        -cryptoStrategy_ : unique_ptr~ICryptoStrategy~
        -logger_ : shared_ptr~ILogger~
        +CryptoManager(cryptoStrategy, const shared_ptr~ILogger~& logger)
        +EncryptFile(filePath, password)
        +DecryptFile(filePath, password)
    }

    class CryptoStrategyFactory {
        +CreateCryptoStrategy~TBackendTag~(const shared_ptr~ILogger~& logger)
        +CreateCryptoStrategy~OpenSslTag~(const shared_ptr~ILogger~& logger)
    }

    class CryptoManagerFactory {
        +CreateCryptoManager(cryptoStrategy, const shared_ptr~ILogger~& logger)
        +GetCryptoManager~TBackendTag~(const shared_ptr~ILogger~& logger)
        +GetCryptoManager~OpenSslTag~(const shared_ptr~ILogger~& logger)
    }

    class RecursiveStepper {
        -QString dirPath_
        -logger_ : shared_ptr~ILogger~
        +RecursiveStepper(dirPath, const shared_ptr~ILogger~& logger)
        +BuildIndex() FileSystemIndex
    }

    ILogger <|.. ThreadSafeLogger
    ThreadSafeLogger <|-- AppLogger
    ThreadSafeLogger <|-- AppSysLogger
    ThreadSafeLogger ..> LoggerSettings
    LoggerSettings ..> LogLevel
    LoggerSettings ..> LogOutput
    LoggerFactory ..> AppLogger
    LoggerFactory ..> AppSysLogger
    LogEntryStream ..> ILogger

    ICryptoManager <|.. CryptoManager
    ICryptoStrategy <|.. OpenSslCryptoStrategy
    CryptoManager o--> ICryptoStrategy
    CryptoManager ..> ILogger
    OpenSslCryptoStrategy ..> ILogger
    RecursiveStepper ..> ILogger

    MainApplication ..> LoggerFactory
    MainApplication ..> AppLogger
    MainApplication ..> AppSysLogger
    MainApplication ..> CryptoManagerFactory
    MainApplication ..> RecursiveStepper

    CryptoManagerFactory ..> CryptoStrategyFactory
    CryptoManagerFactory ..> CryptoManager
    CryptoStrategyFactory ..> OpenSslCryptoStrategy
    CryptoStrategyFactory ..> OpenSslTag
    CryptoManagerFactory ..> OpenSslTag
```
## Инструкция для пользователя
Сборка проекта производится следующим образом:

<details>
<summary>Windows</summary>

Создайте директорию `build` и перейдите в нее:
```powershell
mkdir build
cd build
```

> Примечание: если переменная `PATH` не настроена, используйте полные пути к `cmake` и `windeployqt`.

Сконфигурируйте и соберите проект:
```powershell
cmake .. && cmake --build .
```

При необходимости разверните Qt-зависимости рядом с `.exe`:

```powershell
<path>\windeployqt .\recursive_encoder.exe
```

Запустите программу:
```powershell
.\recursive_encoder.exe <MODE> <ENCODING_TARGET>
```

После запуска программа запросит пароль в консоли.

</details>

<details>
<summary>Linux / macOS</summary>

Создайте директорию `build` и перейдите в нее:
```bash
mkdir -p build && cd build
```

Сконфигурируйте и соберите проект:
```bash
cmake ..
cmake --build .
```

Запустите программу:
```bash
./recursive_encoder <MODE> <ENCODING_TARGET>
```

После запуска программа запросит пароль в консоли.

</details>

Описание передаваемых параметров:
* *MODE* - принимает значения
    1. encrypt - шифровать
    2. decrypt - дешифровать
* *ENCODING_TARGET* - путь до шифруемой/дешифруемой директории

## Тестирование

* **Test Case 1:** Шифрование одиночного файла при корректном режиме работы и корректном пароле пользователя.
* **Test Case 2:** Дешифрование ранее зашифрованного файла при использовании правильного пароля.
* **Test Case 3:** Рекурсивное шифрование всех файлов в целевой директории, включая вложенные поддиректории.
* **Test Case 4:** Попытка повторно зашифровать уже зашифрованный файл.
* **Test Case 5:** Попытка дешифрования зашифрованного файла с неверным паролем.
* **Test Case 6:** Попытка дешифрования обычного файла, который не имеет признаков предварительного шифрования.
* **Test Case 7:** Запуск программы с недостаточным количеством аргументов командной строки.
* **Test Case 8:** Запуск программы с путем к директории, которая отсутствует в файловой системе.
*  **Test Case 9:** Запуск программы с недопустимым значением режима работы (отличным от `encrypt` и `decrypt`).
*  **Test Case 10:** Обработка пустой директории, не содержащей файлов для шифрования или дешифрования.