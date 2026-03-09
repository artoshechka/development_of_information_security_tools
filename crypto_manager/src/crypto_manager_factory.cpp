/// @file
/// @brief Определение фабрики для менеджера криптографических операций.
/// @author Artemenko Anton
#include <crypto_manager_factory.hpp>
#include <src/crypto_manager.hpp>

std::shared_ptr<crypto_manager::ICryptoManager> crypto_manager::GetCryptoManager()
{
    // Используем пользовательский deleter, который ничего не делает
    return std::shared_ptr<crypto_manager::ICryptoManager>(&crypto_manager::OpenSSLCryptoManager::Instance(),
                                                           [](crypto_manager::ICryptoManager *) {});
}
