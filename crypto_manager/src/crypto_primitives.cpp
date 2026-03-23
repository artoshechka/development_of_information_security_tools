/// @file
/// @brief Реализация внутренних криптографических примитивов для crypto_manager.

#include <openssl/crypto.h>

#include <src/crypto_primitives.hpp>

namespace crypto_manager::crypto_primitives
{
void EVP_CIPHER_CTX_Deleter::operator()(EVP_CIPHER_CTX* ctx) const
{
    if (ctx)
    {
        EVP_CIPHER_CTX_free(ctx);
    }
}

void SecureClear(QByteArray& data)
{
    if (!data.isEmpty())
    {
        OPENSSL_cleanse(data.data(), static_cast<size_t>(data.size()));
        data.clear();
        data.squeeze();
    }
}

bool DeriveEncryptionKey(const QString& userPassword, const QByteArray& salt, QByteArray& outEncryptionKey)
{
    QByteArray passwordBytes = userPassword.toUtf8();
    outEncryptionKey.resize(kAesKeySize);

    const bool isOk = PKCS5_PBKDF2_HMAC(passwordBytes.constData(), passwordBytes.size(),
                                        reinterpret_cast<const unsigned char*>(salt.constData()), salt.size(),
                                        kPbkdf2IterationCount, EVP_sha256(), outEncryptionKey.size(),
                                        reinterpret_cast<unsigned char*>(outEncryptionKey.data())) == 1;

    SecureClear(passwordBytes);

    if (!isOk)
    {
        SecureClear(outEncryptionKey);
        return false;
    }

    return true;
}

}  // namespace crypto_manager::crypto_primitives
