/// @file
/// @brief Объявление менеджера криптографических операций.
/// @author Artemenko Anton
#ifndef GUID_D77F818F_E9D1_416E_939C_72463F45C000
#define GUID_D77F818F_E9D1_416E_939C_72463F45C000

#include <icrypto_strategy.hpp>
#include <icrypto_manager.hpp>

#include <memory>

namespace crypto_manager
{
/// @brief Класс менеджера криптографических операций.
class CryptoManager final : public ICryptoManager
{
  public:
    /// @brief Конструктор менеджера со стратегией криптографии.
    /// @param[in] cryptoStrategy Конкретная стратегия шифрования/дешифрования.
    explicit CryptoManager(std::unique_ptr<ICryptoStrategy> cryptoStrategy);

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

  private:
    std::unique_ptr<ICryptoStrategy> cryptoStrategy_;
};

} // namespace crypto_manager

#endif // GUID_D77F818F_E9D1_416E_939C_72463F45C000