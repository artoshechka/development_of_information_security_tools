/// @file
/// @brief Объявление интерфейса менеджера криптографических операций.
/// @author Artemenko Anton
#pragma once
#ifndef GUID_576efe32_b524_4693_8d65_155ffe5e24ec
#define GUID_576efe32_b524_4693_8d65_155ffe5e24ec

#include <QString>

/// @brief Интерфейс менеджера криптографических операций.
class ICryptoManager
{
  public:
    /// @brief Виртуальный деструктор.
    virtual ~ICryptoManager() = default;

    /// @brief Выполняет шифрование файла.
    ///
    /// @param[in] filePath Полный путь к файлу.
    /// @param[in] password Пароль, используемый для генерации ключа.
    /// @return True — если операция выполнена успешно, иначе False
    virtual bool EncryptFile(const QString &filePath, const QString &password) = 0;

    /// @brief Выполняет дешифрование файла.
    ///
    /// @param[in] filePath Полный путь к зашифрованному файлу.
    /// @param[in] password Пароль, используемый для генерации ключа.
    /// @return True — если операция выполнена успешно, иначе False
    virtual bool DecryptFile(const QString &filePath, const QString &password) = 0;
};
#endif // GUID_576efe32_b524_4693_8d65_155ffe5e24ec