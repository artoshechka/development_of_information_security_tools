/// @file
/// @brief Объявление фабрики криптографических стратегий.
/// @author Artemenko Anton
#ifndef GUID_6F34AE39_0BB3_4A98_83D7_C1945278D4A2
#define GUID_6F34AE39_0BB3_4A98_83D7_C1945278D4A2

#include <icrypto_strategy.hpp>
#include <ilogger.hpp>
#include <memory>

namespace crypto_manager
{
/// @brief Fwd decl тега OpenSSL для фабрик.
struct OpenSslTag;

/// @brief Создает криптографическую стратегию по тегу.
/// @tparam TBackendTag Тип тега
/// @param[in] logger Логгер для системных ошибок.
/// @return Уникальный указатель на стратегию.
template <typename TBackendTag>
std::unique_ptr<ICryptoStrategy> CreateCryptoStrategy(const std::shared_ptr<logger::ILogger>& logger);

/// @brief Специализация фабрики для OpenSSL
template <>
std::unique_ptr<ICryptoStrategy> CreateCryptoStrategy<OpenSslTag>(const std::shared_ptr<logger::ILogger>& logger);

}  // namespace crypto_manager

#endif  // GUID_6F34AE39_0BB3_4A98_83D7_C1945278D4A2
