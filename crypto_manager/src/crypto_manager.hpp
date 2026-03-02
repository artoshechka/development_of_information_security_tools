/// @file
/// @brief Объявление менеджера криптографических операций (Singleton).
/// @author Artemenko Anton
#pragma once
#ifndef GUID_d77f818f_e9d1_416e_939c_72463f45c000
#define GUID_d77f818f_e9d1_416e_939c_72463f45c000

#include <icrypto_manager.hpp>

/// @brief Класс менеджера криптографических операций.
class CryptoManager final : public ICryptoManager
{
  public:
    /// @brief Получить единственный экземпляр класса.
    /// @return Ссылка на единственный экземпляр CryptoManager.
    static CryptoManager &Instance();

    /// @brief Выполняет шифрование файла.
    /// @param[in] filePath Полный путь к файлу для шифрования.
    /// @param[in] password Пароль для генерации криптографического ключа.
    /// @return True — операция завершена успешно. Иначе - False
    bool EncryptFile(const QString &filePath, const QString &password) override;

    /// @brief Выполняет дешифрование файла.
    /// @param[in] filePath Полный путь к зашифрованному файлу.
    /// @param[in] password Пароль для генерации криптографического ключа.
    /// @return True — операция завершена успешно. Иначе - False
    bool DecryptFile(const QString &filePath, const QString &password) override;

  private:
    /// @brief Закрытый конструктор (Singleton).
    CryptoManager() = default;

    /// @brief Закрытый деструктор.
    ~CryptoManager() = default;

    /// @brief Запрет копирования.
    Q_DISABLE_COPY(CryptoManager)
};
#endif // GUID_d77f818f_e9d1_416e_939c_72463f45c000