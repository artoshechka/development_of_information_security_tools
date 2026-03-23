/// @file
/// @brief Определение фабрики для менеджера криптографических операций.
/// @author Artemenko Anton
#include <crypto_manager_factory.hpp>
#include <logger_macros.hpp>
#include <memory>
#include <src/crypto_manager.hpp>

std::shared_ptr<crypto_manager::ICryptoManager> crypto_manager::CreateCryptoManager(
    std::unique_ptr<ICryptoStrategy> cryptoStrategy, const std::shared_ptr<logger::ILogger>& logger)
{
    if (!cryptoStrategy)
    {
        LogError(logger) << "CreateCryptoManager received null crypto strategy";
        return nullptr;
    }

    return std::make_shared<CryptoManager>(std::move(cryptoStrategy), logger);
}

template <>
std::shared_ptr<crypto_manager::ICryptoManager> crypto_manager::GetCryptoManager<crypto_manager::OpenSslTag>(
    const std::shared_ptr<logger::ILogger>& logger)
{
    return CreateCryptoManager(CreateCryptoStrategy<OpenSslTag>(logger), logger);
}
