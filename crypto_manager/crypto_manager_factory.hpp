/// @file
/// @brief Объявление фабрики для менеджера криптографических операций.
/// @author Artemenko Anton
#ifndef GUID_DEA1E190_A43E_4746_AAB4_44380D2D63C1
#define GUID_DEA1E190_A43E_4746_AAB4_44380D2D63C1

#include <crypto_strategy_factory.hpp>
#include <icrypto_manager.hpp>

#include <memory>

namespace crypto_manager
{
/// @brief Создает менеджер криптографических операций с указанной стратегией.
/// @param[in] cryptoStrategy Конкретная крипто-стратегия.
/// @return Умный указатель на менеджер криптографических операций.
std::shared_ptr<ICryptoManager> CreateCryptoManager(std::unique_ptr<ICryptoStrategy> cryptoStrategy);

/// @brief Создает менеджер криптографических операций по backend-тегу.
/// @tparam TBackendTag Тип тега backend'а.
/// @return Умный указатель на менеджер криптографических операций.
template <typename TBackendTag> std::shared_ptr<ICryptoManager> GetCryptoManager();

/// @brief Специализация фабрики менеджера для OpenSSL backend'а.
template <> std::shared_ptr<ICryptoManager> GetCryptoManager<OpenSslTag>();

} // namespace crypto_manager

#endif // GUID_DEA1E190_A43E_4746_AAB4_44380D2D63C1