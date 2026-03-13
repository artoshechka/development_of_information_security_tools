/// @file
/// @brief Объявление интерфейса менеджера криптографических операций.
/// @author Artemenko Anton
#ifndef GUID_576EFE32_B524_4693_8D65_155FFE5E24EC
#define GUID_576EFE32_B524_4693_8D65_155FFE5E24EC

#include <QString>

namespace crypto_manager
{
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
    /// @return `true`, если операция выполнена успешно, иначе `false`.
    virtual bool EncryptFile(const QString &filePath, const QString &password) = 0;

    /// @brief Выполняет дешифрование файла.
    ///
    /// @param[in] filePath Полный путь к зашифрованному файлу.
    /// @param[in] password Пароль, используемый для генерации ключа.
    /// @return `true`, если операция выполнена успешно, иначе `false`.
    virtual bool DecryptFile(const QString &filePath, const QString &password) = 0;
};

} // namespace crypto_manager

#endif // GUID_576EFE32_B524_4693_8D65_155FFE5E24EC