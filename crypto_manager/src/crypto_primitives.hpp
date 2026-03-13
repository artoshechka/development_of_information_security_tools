/// @file
/// @brief Внутренние криптографические примитивы для модуля crypto_manager.
#ifndef GUID_4A790AFF_6D26_41A8_9E45_90D2BA76219E
#define GUID_4A790AFF_6D26_41A8_9E45_90D2BA76219E

#include <QByteArray>
#include <QString>

#include <memory>

#include <openssl/evp.h>

namespace crypto_manager::crypto_primitives
{
/// @brief Магическая сигнатура зашифрованного файла.
inline const QByteArray kFileMagicSignature = "A5E2BDE2-21FD-4D6B-A905-78A326846E07";
/// @brief Размер соли для PBKDF2 в байтах.
inline constexpr int kPasswordSaltSize = 16;
/// @brief Размер AES-256 ключа в байтах.
inline constexpr int kAesKeySize = 32;
/// @brief Количество итераций PBKDF2.
inline constexpr int kPbkdf2IterationCount = 200000;
/// @brief Размер nonce для AES-GCM в байтах.
inline constexpr int kAesGcmNonceSize = 12;
/// @brief Размер тега аутентификации AES-GCM в байтах.
inline constexpr int kAesGcmTagSize = 16;
/// @brief Размер чанка при обработке файла в байтах.
inline constexpr qint64 kFileProcessingChunkSize = 64 * 1024;

/// @brief Удалитель контекста OpenSSL `EVP_CIPHER_CTX` для `std::unique_ptr`.
struct EVP_CIPHER_CTX_Deleter
{
    /// @brief Освобождает контекст шифрования OpenSSL.
    /// @param[in] ctx Указатель на контекст OpenSSL.
    void operator()(EVP_CIPHER_CTX *ctx) const;
};

/// @brief Уникальный указатель на `EVP_CIPHER_CTX` с кастомным удалителем.
using UniqPtrCipherContext = std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter>;

/// @brief Безопасно очищает буфер, содержащий чувствительные данные.
/// @param[in,out] data Буфер для очистки.
void SecureClear(QByteArray &data);

/// @brief Вычисляет ключ шифрования из пароля и соли.
/// @param[in] userPassword Пользовательский пароль.
/// @param[in] salt Соль для PBKDF2.
/// @param[out] outEncryptionKey Сгенерированный ключ шифрования.
/// @return `true`, если ключ успешно сгенерирован, иначе `false`.
bool DeriveEncryptionKey(const QString &userPassword, const QByteArray &salt, QByteArray &outEncryptionKey);

} // namespace crypto_manager::crypto_primitives

#endif // GUID_4A790AFF_6D26_41A8_9E45_90D2BA76219E
