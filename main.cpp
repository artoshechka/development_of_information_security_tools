/// @file
/// @brief Главное приложение
/// @author Artemenko Anton
#include <QCoreApplication>
#include <QDir>
#include <QTextStream>
#include <crypto_manager_factory.hpp>
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
constexpr int kMaxPasswordLength = 100;

/// @brief Скрытое чтение пароля из консоли
static QString ReadPassword()
{
    QTextStream cin(stdin);
    QTextStream cout(stdout);

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
    const auto appLogger = logger::GetLogger<logger::AppLoggerTag>();
    const auto appSysLogger = logger::GetLogger<logger::AppSysLoggerTag>();

    QString mode;
    QString path;
    QString strategyType = "openssl";

    if (argc >= 3)
    {
        mode = argv[1];
        path = QString::fromLocal8Bit(argv[2]);

        if (argc >= 4)
        {
            strategyType = QString::fromLocal8Bit(argv[3]).toLower();

            if (strategyType != "openssl")
            {
                LogError(appLogger) << "Unknown strategy: " << strategyType << ". Supported strategies: openssl";
                return 1;
            }
        }
    } else
    {
        LogError(appLogger) << "Invalid arguments: expected at least mode and path"
                            << ". Supported modes: encrypt, decrypt";
        return 1;
    }

    QDir dir(path);

    if (!dir.exists())
    {
        LogError(appLogger) << "Directory does not exist: " << path;
        return 1;
    }

    QString password = ReadPassword();

    if (password.isEmpty())
    {
        LogWarning(appLogger) << "Empty password is not allowed";
        return 1;
    }

    if (password.size() > kMaxPasswordLength)
    {
        LogError(appLogger) << "Password is too long. Max length: " << kMaxPasswordLength;
        SecureClear(password);
        return 1;
    }

    const auto& stepper = std::make_unique<recursive_stepper::RecursiveStepper>(path, appSysLogger);
    std::shared_ptr<crypto_manager::ICryptoManager> cryptoManager;

    if (strategyType == "openssl")
    {
        cryptoManager = crypto_manager::GetCryptoManager<crypto_manager::OpenSslTag>(appSysLogger);
    }

    if (!cryptoManager)
    {
        LogError(appLogger) << "Failed to create crypto manager for selected strategy: " << strategyType;
        SecureClear(password);
        return 1;
    }

    LogInfo(appLogger) << "Processing started. Mode: " << mode << ", Path: " << path;

    for (const auto& file : stepper->GetPaths())
    {
        bool result = false;

        if (mode == "encrypt")
        {
            result = cryptoManager->EncryptFile(file, password);
        } else if (mode == "decrypt")
        {
            result = cryptoManager->DecryptFile(file, password);
        } else
        {
            LogError(appLogger) << "Invalid mode: " << mode << ". Supported modes: encrypt, decrypt";
            SecureClear(password);
            return 1;
        }

        if (result)
        {
            LogInfo(appLogger) << "File processed: " << file;
        } else
        {
            LogWarning(appLogger) << "File skipped: " << file;
        }
    }

    SecureClear(password);

    return 0;
}