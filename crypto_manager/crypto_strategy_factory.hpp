/// @file
/// @brief Объявление фабрики криптографических стратегий.
/// @author Artemenko Anton
#ifndef GUID_6F34AE39_0BB3_4A98_83D7_C1945278D4A2
#define GUID_6F34AE39_0BB3_4A98_83D7_C1945278D4A2

#include <icrypto_strategy.hpp>

#include <memory>

namespace crypto_manager
{
/// @brief Fwd decl тега OpenSSL для фабрик.
struct OpenSslTag;

/// @brief Создает криптографическую стратегию по backend-тегу.
/// @tparam TBackendTag Тип тега backend'а.
/// @return Уникальный указатель на стратегию.
template <typename TBackendTag> std::unique_ptr<ICryptoStrategy> CreateCryptoStrategy();

/// @brief Специализация фабрики для OpenSSL backend'а.
template <> std::unique_ptr<ICryptoStrategy> CreateCryptoStrategy<OpenSslTag>();

} // namespace crypto_manager

#endif // GUID_6F34AE39_0BB3_4A98_83D7_C1945278D4A2
