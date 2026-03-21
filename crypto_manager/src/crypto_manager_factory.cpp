/// @file
/// @brief Определение фабрики для менеджера криптографических операций.
/// @author Artemenko Anton
#include <crypto_manager_factory.hpp>
#include <src/crypto_manager.hpp>

#include <memory>

std::shared_ptr<crypto_manager::ICryptoManager> crypto_manager::CreateCryptoManager(
    std::unique_ptr<ICryptoStrategy> cryptoStrategy)
{
    return std::make_shared<CryptoManager>(std::move(cryptoStrategy));
}

template <>
std::shared_ptr<crypto_manager::ICryptoManager> crypto_manager::GetCryptoManager<crypto_manager::OpenSslTag>()
{
    return CreateCryptoManager(CreateCryptoStrategy<OpenSslTag>());
}
