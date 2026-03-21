/// @file
/// @brief Определение менеджера криптографических операций.
/// @author Artemenko Anton

#include <src/crypto_manager.hpp>

#include <stdexcept>

namespace crypto_manager
{
CryptoManager::CryptoManager(std::unique_ptr<ICryptoStrategy> cryptoStrategy)
    : cryptoStrategy_(std::move(cryptoStrategy))
{
    if (!cryptoStrategy_)
    {
        throw std::invalid_argument("crypto strategy must not be null");
    }
}

bool CryptoManager::EncryptFile(const QString &filePath, const QString &password)
{
    return cryptoStrategy_->EncryptFile(filePath, password);
}

bool CryptoManager::DecryptFile(const QString &filePath, const QString &password)
{
    return cryptoStrategy_->DecryptFile(filePath, password);
}

} // namespace crypto_manager
