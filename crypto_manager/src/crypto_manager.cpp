/// @file
/// @brief Определение менеджера криптографических операций (Singleton).
/// @author Artemenko Anton

#include <src/crypto_manager.hpp>
#include <src/crypto_primitives.hpp>

#include <QByteArray>
#include <QFile>
#include <QSaveFile>
#include <QString>

#include <algorithm>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

using crypto_manager::OpenSSLCryptoManager;
using namespace crypto_manager::crypto_primitives;
namespace
{

/// @brief Безопасная запись буфера в файл с проверкой полного количества байт.
static bool writeAll(QSaveFile &outputFile, const char *data, const qint64 size)
{
    return outputFile.write(data, size) == size;
}

static void secureClearVector(std::vector<unsigned char> &data)
{
    if (!data.empty())
    {
        OPENSSL_cleanse(data.data(), data.size());
        data.clear();
    }
}

/// @brief Чтение и шифрование файла по частям.
static bool encryptStream(QFile &inputFile, QSaveFile &outputFile, EVP_CIPHER_CTX *cipherContext)
{
    while (!inputFile.atEnd())
    {
        const QByteArray chunk = inputFile.read(kFileProcessingChunkSize);

        if (chunk.isEmpty() && inputFile.error() != QFileDevice::NoError)
        {
            return false;
        }

        QByteArray encryptedChunk(chunk.size() + EVP_MAX_BLOCK_LENGTH, 0);
        int outputLength = 0;

        if (!EVP_EncryptUpdate(cipherContext, reinterpret_cast<unsigned char *>(encryptedChunk.data()), &outputLength,
                               reinterpret_cast<const unsigned char *>(chunk.constData()), chunk.size()))
        {
            return false;
        }

        if (outputLength > 0 && !writeAll(outputFile, encryptedChunk.constData(), static_cast<qint64>(outputLength)))
        {
            return false;
        }

    }

    QByteArray finalChunk(EVP_MAX_BLOCK_LENGTH, 0);
    int finalLength = 0;

    if (!EVP_EncryptFinal_ex(cipherContext, reinterpret_cast<unsigned char *>(finalChunk.data()), &finalLength))
    {
        return false;
    }

    if (finalLength > 0 && !writeAll(outputFile, finalChunk.constData(), static_cast<qint64>(finalLength)))
    {
        return false;
    }

    return true;
}

/// @brief Чтение и дешифрование файла по частям.
static bool decryptStream(QFile &inputFile, QSaveFile &outputFile, EVP_CIPHER_CTX *cipherContext,
                          qint64 encryptedPayloadSize)
{
    qint64 bytesRemaining = encryptedPayloadSize;

    while (bytesRemaining > 0)
    {
        const qint64 bytesToRead = std::min(bytesRemaining, kFileProcessingChunkSize);
        const QByteArray chunk = inputFile.read(bytesToRead);

        if (chunk.size() != bytesToRead)
        {
            return false;
        }

        bytesRemaining -= chunk.size();

        QByteArray decryptedChunk(chunk.size() + EVP_MAX_BLOCK_LENGTH, 0);
        int outputLength = 0;

        if (!EVP_DecryptUpdate(cipherContext, reinterpret_cast<unsigned char *>(decryptedChunk.data()), &outputLength,
                               reinterpret_cast<const unsigned char *>(chunk.constData()), chunk.size()))
        {
            return false;
        }

        if (outputLength > 0 && !writeAll(outputFile, decryptedChunk.constData(), static_cast<qint64>(outputLength)))
        {
            return false;
        }
    }

    return true;
}

} // namespace

OpenSSLCryptoManager &OpenSSLCryptoManager::Instance()
{
    static OpenSSLCryptoManager singletonInstance;
    return singletonInstance;
}

bool OpenSSLCryptoManager::EncryptFile(const QString &filePath, const QString &password)
{
    QFile inputFile(filePath);

    if (!inputFile.open(QIODevice::ReadOnly))
        return false;

    const QByteArray filePrefix = inputFile.read(kFileMagicSignature.size());

    if (filePrefix == kFileMagicSignature)
        return false;

    if (!inputFile.seek(0))
        return false;

    QSaveFile outputFile(filePath);
    if (!outputFile.open(QIODevice::WriteOnly))
        return false;

    QByteArray passwordSalt(kPasswordSaltSize, Qt::Uninitialized);

    if (!RAND_bytes(reinterpret_cast<unsigned char *>(passwordSalt.data()), passwordSalt.size()))
    {
        outputFile.cancelWriting();
        return false;
    }

    QByteArray encryptionKey;
    if (!DeriveEncryptionKey(password, passwordSalt, encryptionKey))
    {
        outputFile.cancelWriting();
        return false;
    }

    std::vector<unsigned char> nonce(kAesGcmNonceSize);

    if (!RAND_bytes(nonce.data(), nonce.size()))
    {
        outputFile.cancelWriting();
        SecureClear(encryptionKey);
        SecureClear(passwordSalt);
        return false;
    }

    UniqPtrCipherContext cipherContext(EVP_CIPHER_CTX_new());
    if (!cipherContext)
    {
        outputFile.cancelWriting();
        SecureClear(encryptionKey);
        SecureClear(passwordSalt);
        return false;
    }

    if (!EVP_EncryptInit_ex(cipherContext.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) ||
        !EVP_CIPHER_CTX_ctrl(cipherContext.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) ||
        !EVP_EncryptInit_ex(cipherContext.get(), nullptr, nullptr,
                            reinterpret_cast<const unsigned char *>(encryptionKey.constData()), nonce.data()))
    {
        outputFile.cancelWriting();
        SecureClear(encryptionKey);
        secureClearVector(nonce);
        SecureClear(passwordSalt);
        return false;
    }

    if (!writeAll(outputFile, kFileMagicSignature.constData(), kFileMagicSignature.size()) ||
        !writeAll(outputFile, passwordSalt.constData(), passwordSalt.size()) ||
        !writeAll(outputFile, reinterpret_cast<const char *>(nonce.data()), static_cast<qint64>(nonce.size())) ||
        !encryptStream(inputFile, outputFile, cipherContext.get()))
    {
        outputFile.cancelWriting();
        SecureClear(encryptionKey);
        secureClearVector(nonce);
        SecureClear(passwordSalt);
        return false;
    }

    QByteArray authTag(kAesGcmTagSize, Qt::Uninitialized);
    if (!EVP_CIPHER_CTX_ctrl(cipherContext.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(authTag.size()),
                             authTag.data()) ||
        !writeAll(outputFile, authTag.constData(), authTag.size()) || !outputFile.commit())
    {
        outputFile.cancelWriting();
        SecureClear(encryptionKey);
        secureClearVector(nonce);
        SecureClear(passwordSalt);
        SecureClear(authTag);
        return false;
    }

    SecureClear(encryptionKey);
    secureClearVector(nonce);
    SecureClear(passwordSalt);
    SecureClear(authTag);

    return true;
}

bool OpenSSLCryptoManager::DecryptFile(const QString &filePath, const QString &password)
{
    QFile inputFile(filePath);
    if (!inputFile.open(QIODevice::ReadOnly))
        return false;

    const QByteArray fileSignature = inputFile.read(kFileMagicSignature.size());

    if (fileSignature != kFileMagicSignature)
        return false;

    QByteArray passwordSalt = inputFile.read(kPasswordSaltSize);

    if (passwordSalt.size() != kPasswordSaltSize)
        return false;

    QByteArray nonce = inputFile.read(kAesGcmNonceSize);

    if (nonce.size() != kAesGcmNonceSize)
        return false;

    const qint64 headerSize = kFileMagicSignature.size() + kPasswordSaltSize + kAesGcmNonceSize;
    const qint64 encryptedFileSize = inputFile.size();

    if (encryptedFileSize < headerSize + kAesGcmTagSize)
        return false;

    const qint64 encryptedPayloadSize = encryptedFileSize - headerSize - kAesGcmTagSize;

    QByteArray decryptionKey;
    if (!DeriveEncryptionKey(password, passwordSalt, decryptionKey))
    {
        SecureClear(passwordSalt);
        SecureClear(nonce);
        return false;
    }

    QSaveFile outputFile(filePath);
    if (!outputFile.open(QIODevice::WriteOnly))
    {
        SecureClear(decryptionKey);
        SecureClear(passwordSalt);
        SecureClear(nonce);
        return false;
    }

    UniqPtrCipherContext cipherContext(EVP_CIPHER_CTX_new());
    if (!cipherContext)
    {
        outputFile.cancelWriting();
        SecureClear(decryptionKey);
        SecureClear(passwordSalt);
        SecureClear(nonce);
        return false;
    }

    if (!EVP_DecryptInit_ex(cipherContext.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) ||
        !EVP_CIPHER_CTX_ctrl(cipherContext.get(), EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) ||
        !EVP_DecryptInit_ex(cipherContext.get(), nullptr, nullptr,
                            reinterpret_cast<const unsigned char *>(decryptionKey.constData()),
                            reinterpret_cast<const unsigned char *>(nonce.constData())))
    {
        outputFile.cancelWriting();
        SecureClear(decryptionKey);
        SecureClear(passwordSalt);
        SecureClear(nonce);
        return false;
    }

    if (!decryptStream(inputFile, outputFile, cipherContext.get(), encryptedPayloadSize))
    {
        outputFile.cancelWriting();
        SecureClear(decryptionKey);
        SecureClear(passwordSalt);
        SecureClear(nonce);
        return false;
    }

    QByteArray authTag = inputFile.read(kAesGcmTagSize);

    if (authTag.size() != kAesGcmTagSize ||
        !EVP_CIPHER_CTX_ctrl(cipherContext.get(), EVP_CTRL_GCM_SET_TAG, authTag.size(), authTag.data()))
    {
        outputFile.cancelWriting();
        SecureClear(decryptionKey);
        SecureClear(passwordSalt);
        SecureClear(nonce);
        SecureClear(authTag);
        return false;
    }

    QByteArray finalChunk(EVP_MAX_BLOCK_LENGTH, 0);
    int finalLength = 0;
    if (EVP_DecryptFinal_ex(cipherContext.get(), reinterpret_cast<unsigned char *>(finalChunk.data()), &finalLength) <= 0)
    {
        outputFile.cancelWriting();
        SecureClear(decryptionKey);
        SecureClear(passwordSalt);
        SecureClear(nonce);
        SecureClear(authTag);
        SecureClear(finalChunk);
        return false;
    }

    if ((finalLength > 0 && !writeAll(outputFile, finalChunk.constData(), static_cast<qint64>(finalLength))) ||
        !outputFile.commit())
    {
        outputFile.cancelWriting();
        SecureClear(decryptionKey);
        SecureClear(passwordSalt);
        SecureClear(nonce);
        SecureClear(authTag);
        SecureClear(finalChunk);
        return false;
    }

    SecureClear(decryptionKey);
    SecureClear(passwordSalt);
    SecureClear(nonce);
    SecureClear(authTag);
    SecureClear(finalChunk);

    return true;
}