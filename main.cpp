/// @file
/// @brief Главное приложение
/// @author Artemenko Anton
#include <QCoreApplication>
#include <QDir>
#include <QTextStream>
#include <crypto_manager_factory.hpp>
#include <limits>
#include <logger_factory.hpp>
#include <logger_macros.hpp>
#include <memory>
#include <recursive_stepper.hpp>

#ifdef _WIN32
#define NOMINMAX
#include <Windows.h>
#undef EncryptFile
#undef DecryptFile
#else
#include <termios.h>
#include <unistd.h>
#endif
#include <algorithm>

namespace
{
/// @brief Сообщение об ошибке при неправильном использовании программы
const QString errorMsg =
    "Usage:\nprogram encrypt <path>\nprogram decrypt <path>\n"
    "Backends: openssl\n";

/// @brief Скрытое чтение пароля из консоли (для Unix/macOS).
static QString ReadPassword(QTextStream& cin, QTextStream& cout)
{
    cout << "Enter password: ";
    cout.flush();

#ifdef _WIN32
    HANDLE inputHandle = GetStdHandle(STD_INPUT_HANDLE);
    DWORD oldConsoleMode = 0;
    bool echoDisabled = false;

    if (inputHandle != INVALID_HANDLE_VALUE && GetConsoleMode(inputHandle, &oldConsoleMode))
    {
        const DWORD newConsoleMode = oldConsoleMode & ~ENABLE_ECHO_INPUT;
        if (SetConsoleMode(inputHandle, newConsoleMode) != 0)
        {
            echoDisabled = true;
        }
    }

    const QString password = cin.readLine();

    if (echoDisabled)
    {
        SetConsoleMode(inputHandle, oldConsoleMode);
        cout << "\n";
        cout.flush();
    }

    return password;
#else
    termios oldTerminalAttributes{};
    bool echoDisabled = false;

    if (tcgetattr(STDIN_FILENO, &oldTerminalAttributes) == 0)
    {
        termios newTerminalAttributes = oldTerminalAttributes;
        newTerminalAttributes.c_lflag &= ~ECHO;
        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &newTerminalAttributes) == 0)
        {
            echoDisabled = true;
        }
    }

    const QString password = cin.readLine();

    if (echoDisabled)
    {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldTerminalAttributes);
        cout << "\n";
        cout.flush();
    }

    return password;
#endif
}

/// @brief Безопасная очистка строки с паролем.
static void SecureClear(QString& data)
{
    if (!data.isEmpty())
    {
        data.fill(QChar('\0'));
        data.clear();
        data.squeeze();
    }
}
}  // namespace

/// @brief Точка входа в программу.
/// @param[in] argc количество аргументов командной строки
/// @param[in] argv массив аргументов командной строки
/// @return код завершения приложения
int main(int argc, char* argv[])
{
    QCoreApplication app(argc, argv);
    QTextStream cin(stdin);
    QTextStream cout(stdout);
    QTextStream cerr(stderr);
    const auto appLogger = logger::GetLogger<logger::AppLoggerTag>();
    const auto appSysLogger = logger::GetLogger<logger::AppSysLoggerTag>();

    QString mode;
    QString path;
    QString backendName = "openssl";

    // Проверка аргументов
    if (argc >= 3)
    {
        mode = argv[1];
        path = QString::fromLocal8Bit(argv[2]);

        if (argc >= 4)
        {
            backendName = QString::fromLocal8Bit(argv[3]).toLower();

            if (backendName != "openssl")
            {
                LogError(appLogger) << "Unknown backend: " << backendName;
                cerr << errorMsg;
                return 1;
            }
        }
    } else
    {
        LogError(appLogger) << "Invalid arguments: expected at least mode and path";
        cerr << errorMsg;
        return 1;
    }

    QDir dir(path);

    if (!dir.exists())
    {
        LogError(appLogger) << "Directory does not exist: " << path;
        return 1;
    }

    QString password = ReadPassword(cin, cout);

    if (password.isEmpty())
    {
        LogWarning(appLogger) << "Empty password is not allowed";
        return 1;
    }

    if (password.size() > std::numeric_limits<int>::max() / 4)
    {
        LogError(appLogger) << "Password is too long";
        SecureClear(password);
        return 1;
    }

    const auto& stepper = std::make_unique<recursive_stepper::RecursiveStepper>(path, appSysLogger);
    std::shared_ptr<crypto_manager::ICryptoManager> encoder;

    if (backendName == "openssl")
    {
        encoder = crypto_manager::GetCryptoManager<crypto_manager::OpenSslTag>(appSysLogger);
    }

    if (!encoder)
    {
        LogError(appLogger) << "Failed to create crypto manager for selected backend";
        SecureClear(password);
        return 1;
    }

    LogInfo(appLogger) << "Processing started. Mode: " << mode << ", Path: " << path;

    for (const auto& file : stepper->BuildIndex())
    {
        bool result = false;

        if (mode == "encrypt")
        {
            result = encoder->EncryptFile(file, password);
        } else if (mode == "decrypt")
        {
            result = encoder->DecryptFile(file, password);
        } else
        {
            LogError(appLogger) << "Invalid mode: " << mode;
            SecureClear(password);
            cerr << errorMsg;
            return 1;
        }

        if (result)
        {
            LogInfo(appLogger) << "File processed: " << file;
            cout << "File processed: " << file << "\n";
        } else
        {
            LogWarning(appLogger) << "File skipped: " << file;
            cout << "File skipped: " << file << "\n";
        }
    }

    SecureClear(password);

    return 0;
}