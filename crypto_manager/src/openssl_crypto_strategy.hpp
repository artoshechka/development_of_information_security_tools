/// @file
/// @brief Объявление OpenSSL-реализации криптографической стратегии.
/// @author Artemenko Anton
#ifndef GUID_4C8E4AE2_3D8A_4A20_82E7_5F3D40B87F45
#define GUID_4C8E4AE2_3D8A_4A20_82E7_5F3D40B87F45

#include <icrypto_strategy.hpp>

namespace crypto_manager
{
/// @brief Криптографическая стратегия на базе OpenSSL.
class OpenSslCryptoStrategy final : public ICryptoStrategy
{
  public:
    /// @brief Выполняет шифрование файла.
    bool EncryptFile(const QString &filePath, const QString &password) override;

    /// @brief Выполняет дешифрование файла.
    bool DecryptFile(const QString &filePath, const QString &password) override;
};

} // namespace crypto_manager

#endif // GUID_4C8E4AE2_3D8A_4A20_82E7_5F3D40B87F45
