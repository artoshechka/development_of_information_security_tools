/// @file
/// @brief Объявление фабрики для менеджера криптографических операций.
/// @author Artemenko Anton
#ifndef GUID_DEA1E190_A43E_4746_AAB4_44380D2D63C1
#define GUID_DEA1E190_A43E_4746_AAB4_44380D2D63C1

#include <icrypto_manager.hpp>

namespace crypto_manager
{
/// @brief Получает единственный экземпляр менеджера криптографических операций.
/// @return Умный указатель на единственный экземпляр менеджера криптографических операций.
std::shared_ptr<ICryptoManager> GetCryptoManager();

} // namespace crypto_manager

#endif // GUID_DEA1E190_A43E_4746_AAB4_44380D2D63C1