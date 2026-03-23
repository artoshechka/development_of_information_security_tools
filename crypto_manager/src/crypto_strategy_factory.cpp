/// @file
/// @brief Определение фабрики криптографических стратегий.
/// @author Artemenko Anton

#include <crypto_strategy_factory.hpp>
#include <src/openssl_crypto_strategy.hpp>

template <>
std::unique_ptr<crypto_manager::ICryptoStrategy> crypto_manager::CreateCryptoStrategy<crypto_manager::OpenSslTag>(
    const std::shared_ptr<logger::ILogger>& logger)
{
    return std::make_unique<OpenSslCryptoStrategy>(logger);
}
