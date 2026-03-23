/// @file
/// @brief Объявление OpenSSL-реализации криптографической стратегии.
/// @author Artemenko Anton
#ifndef GUID_4C8E4AE2_3D8A_4A20_82E7_5F3D40B87F45
#define GUID_4C8E4AE2_3D8A_4A20_82E7_5F3D40B87F45

#include <icrypto_strategy.hpp>
#include <ilogger.hpp>
#include <memory>

namespace crypto_manager
{
/// @brief Криптографическая стратегия на базе OpenSSL.
class OpenSslCryptoStrategy final : public ICryptoStrategy
{
   public:
    /// @brief Конструктор стратегии с внедрением логгера.
    /// @param[in] logger Логгер для системных ошибок.
    explicit OpenSslCryptoStrategy(const std::shared_ptr<logger::ILogger>& logger);

    /// @brief Выполняет шифрование файла.
    bool EncryptFile(const QString& filePath, const QString& password) override;

    /// @brief Выполняет дешифрование файла.
    bool DecryptFile(const QString& filePath, const QString& password) override;

   private:
    std::shared_ptr<logger::ILogger> logger_;
};

}  // namespace crypto_manager

#endif  // GUID_4C8E4AE2_3D8A_4A20_82E7_5F3D40B87F45
