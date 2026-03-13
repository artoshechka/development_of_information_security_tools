/// @file
/// @brief Реализация внутренних криптографических примитивов для crypto_manager.

#include <src/crypto_primitives.hpp>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/params.h>

namespace crypto_manager::crypto_primitives
{
void EVP_CIPHER_CTX_Deleter::operator()(EVP_CIPHER_CTX *ctx) const
{
    if (ctx)
    {
        EVP_CIPHER_CTX_free(ctx);
    }
}

void MacDeleter::operator()(EVP_MAC *mac) const
{
    if (mac)
    {
        EVP_MAC_free(mac);
    }
}

void MacContextDeleter::operator()(EVP_MAC_CTX *ctx) const
{
    if (ctx)
    {
        EVP_MAC_CTX_free(ctx);
    }
}

void SecureClear(QByteArray &data)
{
    if (!data.isEmpty())
    {
        OPENSSL_cleanse(data.data(), static_cast<size_t>(data.size()));
        data.clear();
        data.squeeze();
    }
}

bool DeriveKeys(const QString &userPassword, const QByteArray &salt, QByteArray &outEncryptionKey,
                QByteArray &outAuthKey)
{
    QByteArray passwordBytes = userPassword.toUtf8();
    QByteArray keyMaterial(kAesKeySize + kHmacKeySize, Qt::Uninitialized);

    const bool isOk = PKCS5_PBKDF2_HMAC(
                          passwordBytes.constData(), passwordBytes.size(),
                          reinterpret_cast<const unsigned char *>(salt.constData()), salt.size(),
                          kPbkdf2IterationCount, EVP_sha256(), keyMaterial.size(),
                          reinterpret_cast<unsigned char *>(keyMaterial.data())) == 1;

    SecureClear(passwordBytes);

    if (!isOk)
    {
        SecureClear(keyMaterial);
        SecureClear(outEncryptionKey);
        SecureClear(outAuthKey);
        return false;
    }

    outEncryptionKey = keyMaterial.left(kAesKeySize);
    outAuthKey = keyMaterial.mid(kAesKeySize, kHmacKeySize);
    SecureClear(keyMaterial);

    return true;
}

bool InitializeHmacState(const QByteArray &authKey, HmacState &hmacState)
{
    hmacState.mac_.reset(EVP_MAC_fetch(nullptr, "HMAC", nullptr));
    if (!hmacState.mac_)
    {
        return false;
    }

    hmacState.context_.reset(EVP_MAC_CTX_new(hmacState.mac_.get()));
    if (!hmacState.context_)
    {
        return false;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(const_cast<char *>(OSSL_MAC_PARAM_DIGEST),
                                         const_cast<char *>("SHA256"), 0),
        OSSL_PARAM_construct_end(),
    };

    return EVP_MAC_init(hmacState.context_.get(), reinterpret_cast<const unsigned char *>(authKey.constData()),
                        static_cast<size_t>(authKey.size()), params) == 1;
}

} // namespace crypto_manager::crypto_primitives
