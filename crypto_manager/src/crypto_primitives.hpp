/// @file
/// @brief Внутренние криптографические примитивы для модуля crypto_manager.
#pragma once

#include <QByteArray>
#include <QString>

#include <memory>

#include <openssl/evp.h>

namespace crypto_manager::crypto_primitives
{
inline const QByteArray kFileMagicSignature = "A5E2BDE2-21FD-4D6B-A905-78A326846E07";
inline constexpr int kPasswordSaltSize = 16;
inline constexpr int kAesKeySize = 32;
inline constexpr int kHmacKeySize = 32;
inline constexpr int kHmacTagSize = 32;
inline constexpr int kPbkdf2IterationCount = 200000;
inline constexpr int kAesInitializationVectorSize = 16;
inline constexpr qint64 kFileProcessingChunkSize = 64 * 1024;

struct EVP_CIPHER_CTX_Deleter
{
    void operator()(EVP_CIPHER_CTX *ctx) const;
};

struct MacDeleter
{
    void operator()(EVP_MAC *mac) const;
};

struct MacContextDeleter
{
    void operator()(EVP_MAC_CTX *ctx) const;
};

using UniqPtrCipherContext = std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter>;
using UniqPtrMac = std::unique_ptr<EVP_MAC, MacDeleter>;
using UniqPtrMacContext = std::unique_ptr<EVP_MAC_CTX, MacContextDeleter>;

struct HmacState
{
    UniqPtrMac mac_;
    UniqPtrMacContext context_;
};

void SecureClear(QByteArray &data);
bool DeriveKeys(const QString &userPassword, const QByteArray &salt, QByteArray &outEncryptionKey,
                QByteArray &outAuthKey);
bool InitializeHmacState(const QByteArray &authKey, HmacState &hmacState);

} // namespace crypto_manager::crypto_primitives
