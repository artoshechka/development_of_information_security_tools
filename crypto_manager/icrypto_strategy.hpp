/// @file
/// @brief Объявление интерфейса криптографической стратегии.
/// @author Artemenko Anton
#ifndef GUID_F5A5C5F8_7B2D_4BA0_A52D_42ACB7B2DE2E
#define GUID_F5A5C5F8_7B2D_4BA0_A52D_42ACB7B2DE2E

#include <QString>

namespace crypto_manager
{
/// @brief Интерфейс криптографической стратегии.
class ICryptoStrategy
{
   public:
    /// @brief Виртуальный деструктор.
    virtual ~ICryptoStrategy() = default;

    /// @brief Выполняет шифрование файла.
    /// @param[in] filePath Полный путь к файлу.
    /// @param[in] password Пароль для генерации ключа.
    /// @return `true`, если операция завершена успешно.
    virtual bool EncryptFile(const QString& filePath, const QString& password) = 0;

    /// @brief Выполняет дешифрование файла.
    /// @param[in] filePath Полный путь к зашифрованному файлу.
    /// @param[in] password Пароль для генерации ключа.
    /// @return `true`, если операция завершена успешно.
    virtual bool DecryptFile(const QString& filePath, const QString& password) = 0;
};

}  // namespace crypto_manager

#endif  // GUID_F5A5C5F8_7B2D_4BA0_A52D_42ACB7B2DE2E
