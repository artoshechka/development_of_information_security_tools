/// @file
/// @brief Главное приложение
/// @author Artemenko Anton
#include <crypto_manager_factory.hpp>
#include <recursive_stepper.hpp>

#include <QCoreApplication>
#include <QDir>
#include <QTextStream>

#include <memory>

#ifdef _WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace
{
/// @brief Сообщение об ошибке при неправильном использовании программы
const QString &errorMsg = "Usage:\nprogram encrypt <path>\nprogram decrypt <path>\n";

/// @brief Скрытое чтение пароля из консоли (для Unix/macOS).
static QString ReadPassword(QTextStream &cin, QTextStream &cout)
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
    termios oldTerminalAttributes {};
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
static void SecureClear(QString &data)
{
    if (!data.isEmpty())
    {
        data.fill(QChar('\0'));
        data.clear();
        data.squeeze();
    }
}
} // namespace

/// @brief Точка входа в программу.
/// @param[in] argc количество аргументов командной строки
/// @param[in] argv массив аргументов командной строки
/// @return код завершения приложения
int main(int argc, char *argv[])
{
    QTextStream cin(stdin);
    QTextStream cout(stdout);
    QTextStream cerr(stderr);

    QString mode;
    QString path;

    // Проверка аргументов
    if (argc >= 3)
    {
        mode = argv[1];
        path = QString::fromLocal8Bit(argv[2]);
    }
    else
    {
        cerr << errorMsg;
        return 1;
    }

    QDir dir(path);

    if (!dir.exists())
    {
        cerr << "Directory does not exist\n";
        return 1;
    }

    QString password = ReadPassword(cin, cout);

    const auto &stepper = std::make_unique<recursive_stepper::RecursiveStepper>(path);
    const auto &encoder = crypto_manager::GetCryptoManager();

    for (const auto &file : stepper->BuildIndex())
    {
        bool result = false;

        if (mode == "encrypt")
        {
            result = encoder->EncryptFile(file, password);
        }
        else if (mode == "decrypt")
        {
            result = encoder->DecryptFile(file, password);
        }
        else
        {
            SecureClear(password);
            cerr << errorMsg;
            return 1;
        }

        if (result)
        {
            cout << "File processed: " << file << "\n";
        }
        else
        {
            cout << "File skipped: " << file << "\n";
        }
    }

    SecureClear(password);

    return 0;
}