/// @file
/// @brief Объявление фабрики для менеджера криптографических операций.
/// @author Artemenko Anton
#ifndef GUID_DEA1E190_A43E_4746_AAB4_44380D2D63C1
#define GUID_DEA1E190_A43E_4746_AAB4_44380D2D63C1

#include <crypto_strategy_factory.hpp>
#include <icrypto_manager.hpp>
#include <ilogger.hpp>
#include <memory>

namespace crypto_manager
{
/// @brief Создает менеджер криптографических операций с указанной стратегией.
/// @param[in] cryptoStrategy Конкретная крипто-стратегия.
/// @param[in] logger Логгер для системных ошибок.
/// @return Умный указатель на менеджер криптографических операций.
std::shared_ptr<ICryptoManager> CreateCryptoManager(std::unique_ptr<ICryptoStrategy> cryptoStrategy,
                                                    const std::shared_ptr<logger::ILogger>& logger);

/// @brief Создает менеджер криптографических операций по backend-тегу.
/// @tparam TBackendTag Тип тега backend'а.
/// @param[in] logger Логгер для системных ошибок.
/// @return Умный указатель на менеджер криптографических операций.
template <typename TBackendTag>
std::shared_ptr<ICryptoManager> GetCryptoManager(const std::shared_ptr<logger::ILogger>& logger);

/// @brief Специализация фабрики менеджера для OpenSSL backend'а.
template <>
std::shared_ptr<ICryptoManager> GetCryptoManager<OpenSslTag>(const std::shared_ptr<logger::ILogger>& logger);

}  // namespace crypto_manager

#endif  // GUID_DEA1E190_A43E_4746_AAB4_44380D2D63C1