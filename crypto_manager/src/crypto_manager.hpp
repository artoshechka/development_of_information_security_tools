/// @file
/// @brief Объявление менеджера криптографических операций (Singleton).
/// @author Artemenko Anton
#ifndef GUID_D77F818F_E9D1_416E_939C_72463F45C000
#define GUID_D77F818F_E9D1_416E_939C_72463F45C000

#include <icrypto_manager.hpp>

namespace crypto_manager
{
/// @brief Класс менеджера криптографических операций.
class OpenSSLCryptoManager final : public ICryptoManager
{
  public:
    /// @brief Получить единственный экземпляр класса.
    /// @return Ссылка на единственный экземпляр OpenSSLCryptoManager.
    static OpenSSLCryptoManager &Instance();

    /// @brief Выполняет шифрование файла.
    /// @param[in] filePath Полный путь к файлу для шифрования.
    /// @param[in] password Пароль для генерации криптографического ключа.
    /// @return `true`, если операция завершена успешно, иначе `false`.
    bool EncryptFile(const QString &filePath, const QString &password) override;

    /// @brief Выполняет дешифрование файла.
    /// @param[in] filePath Полный путь к зашифрованному файлу.
    /// @param[in] password Пароль для генерации криптографического ключа.
    /// @return `true`, если операция завершена успешно, иначе `false`.
    bool DecryptFile(const QString &filePath, const QString &password) override;

    /// @brief Копирование запрещено
    OpenSSLCryptoManager(const OpenSSLCryptoManager &) = delete;

    /// @brief Копирование запрещено
    OpenSSLCryptoManager &operator=(const OpenSSLCryptoManager &) = delete;

  private:
    /// @brief Закрытый конструктор (Singleton).
    OpenSSLCryptoManager() = default;

    /// @brief Закрытый деструктор.
    ~OpenSSLCryptoManager() = default;
};

} // namespace crypto_manager

#endif // GUID_D77F818F_E9D1_416E_939C_72463F45C000