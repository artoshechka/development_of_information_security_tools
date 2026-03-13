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

/// @brief Чтение и шифрование файла по частям.
static bool encryptStream(QFile &inputFile, QSaveFile &outputFile, EVP_CIPHER_CTX *cipherContext,
                          EVP_MAC_CTX *hmacContext)
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

        if (outputLength > 0 &&
            EVP_MAC_update(hmacContext, reinterpret_cast<const unsigned char *>(encryptedChunk.constData()),
                           static_cast<size_t>(outputLength)) != 1)
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

    if (finalLength > 0 &&
        EVP_MAC_update(hmacContext, reinterpret_cast<const unsigned char *>(finalChunk.constData()),
                   static_cast<size_t>(finalLength)) != 1)
    {
        return false;
    }

    return true;
}

/// @brief Чтение и дешифрование файла по частям.
static bool decryptStream(QFile &inputFile, QSaveFile &outputFile, EVP_CIPHER_CTX *cipherContext,
                          EVP_MAC_CTX *hmacContext, qint64 encryptedPayloadSize)
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

        if (EVP_MAC_update(hmacContext, reinterpret_cast<const unsigned char *>(chunk.constData()),
                           static_cast<size_t>(chunk.size())) != 1)
        {
            return false;
        }

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

    QByteArray finalChunk(EVP_MAX_BLOCK_LENGTH, 0);
    int finalLength = 0;

    if (!EVP_DecryptFinal_ex(cipherContext, reinterpret_cast<unsigned char *>(finalChunk.data()), &finalLength))
    {
        return false;
    }

    if (finalLength > 0 && !writeAll(outputFile, finalChunk.constData(), static_cast<qint64>(finalLength)))
    {
        return false;
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
    QByteArray authKey;
    if (!DeriveKeys(password, passwordSalt, encryptionKey, authKey))
    {
        outputFile.cancelWriting();
        return false;
    }

    std::vector<unsigned char> initializationVector(kAesInitializationVectorSize);

    if (!RAND_bytes(initializationVector.data(), initializationVector.size()))
    {
        outputFile.cancelWriting();
        SecureClear(encryptionKey);
        SecureClear(authKey);
        SecureClear(passwordSalt);
        return false;
    }

    UniqPtrCipherContext cipherContext(EVP_CIPHER_CTX_new());
    if (!cipherContext)
    {
        outputFile.cancelWriting();
        SecureClear(encryptionKey);
        SecureClear(authKey);
        SecureClear(passwordSalt);
        return false;
    }

    HmacState hmacState;
    if (!InitializeHmacState(authKey, hmacState))
    {
        outputFile.cancelWriting();
        SecureClear(encryptionKey);
        SecureClear(authKey);
        SecureClear(passwordSalt);
        return false;
    }

    if (!EVP_EncryptInit_ex(cipherContext.get(), EVP_aes_256_cbc(), nullptr,
                            reinterpret_cast<const unsigned char *>(encryptionKey.data()), initializationVector.data()))
    {
        outputFile.cancelWriting();
        SecureClear(encryptionKey);
        SecureClear(passwordSalt);
        return false;
    }

    if (!writeAll(outputFile, kFileMagicSignature.constData(), kFileMagicSignature.size()) ||
        !writeAll(outputFile, passwordSalt.constData(), passwordSalt.size()) ||
        !writeAll(outputFile, reinterpret_cast<const char *>(initializationVector.data()),
                  static_cast<qint64>(initializationVector.size())) ||
        !encryptStream(inputFile, outputFile, cipherContext.get(), hmacState.context_.get()))
    {
        outputFile.cancelWriting();
        SecureClear(encryptionKey);
        SecureClear(authKey);
        SecureClear(passwordSalt);
        return false;
    }

    QByteArray authTag(kHmacTagSize, Qt::Uninitialized);
    size_t authTagLength = 0;
    if (EVP_MAC_final(hmacState.context_.get(), reinterpret_cast<unsigned char *>(authTag.data()), &authTagLength,
                      static_cast<size_t>(authTag.size())) != 1 ||
        authTagLength != kHmacTagSize || !writeAll(outputFile, authTag.constData(), authTag.size()) ||
        !outputFile.commit())
    {
        outputFile.cancelWriting();
        SecureClear(encryptionKey);
        SecureClear(authKey);
        SecureClear(passwordSalt);
        SecureClear(authTag);
        return false;
    }

    SecureClear(encryptionKey);
    SecureClear(authKey);
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

    QByteArray initializationVector = inputFile.read(kAesInitializationVectorSize);

    if (initializationVector.size() != kAesInitializationVectorSize)
        return false;

    const qint64 headerSize = kFileMagicSignature.size() + kPasswordSaltSize + kAesInitializationVectorSize;
    const qint64 encryptedFileSize = inputFile.size();

    if (encryptedFileSize < headerSize + kHmacTagSize)
        return false;

    const qint64 encryptedPayloadSize = encryptedFileSize - headerSize - kHmacTagSize;

    QByteArray decryptionKey;
    QByteArray authKey;
    if (!DeriveKeys(password, passwordSalt, decryptionKey, authKey))
    {
        SecureClear(passwordSalt);
        return false;
    }

    QSaveFile outputFile(filePath);
    if (!outputFile.open(QIODevice::WriteOnly))
    {
        SecureClear(decryptionKey);
        SecureClear(authKey);
        SecureClear(passwordSalt);
        return false;
    }

    UniqPtrCipherContext cipherContext(EVP_CIPHER_CTX_new());
    if (!cipherContext)
    {
        outputFile.cancelWriting();
        SecureClear(decryptionKey);
        SecureClear(authKey);
        SecureClear(passwordSalt);
        return false;
    }

    if (!EVP_DecryptInit_ex(cipherContext.get(), EVP_aes_256_cbc(), nullptr,
                            reinterpret_cast<const unsigned char *>(decryptionKey.data()),
                            reinterpret_cast<const unsigned char *>(initializationVector.data())))
    {
        outputFile.cancelWriting();
        SecureClear(decryptionKey);
        SecureClear(authKey);
        SecureClear(passwordSalt);
        return false;
    }

    HmacState hmacState;
    if (!InitializeHmacState(authKey, hmacState))
    {
        outputFile.cancelWriting();
        SecureClear(decryptionKey);
        SecureClear(authKey);
        SecureClear(passwordSalt);
        return false;
    }

    if (!decryptStream(inputFile, outputFile, cipherContext.get(), hmacState.context_.get(), encryptedPayloadSize))
    {
        outputFile.cancelWriting();
        SecureClear(decryptionKey);
        SecureClear(authKey);
        SecureClear(passwordSalt);
        return false;
    }

    const QByteArray expectedAuthTag = inputFile.read(kHmacTagSize);
    QByteArray actualAuthTag(kHmacTagSize, Qt::Uninitialized);
    size_t actualAuthTagLength = 0;

    if (expectedAuthTag.size() != kHmacTagSize ||
        EVP_MAC_final(hmacState.context_.get(), reinterpret_cast<unsigned char *>(actualAuthTag.data()),
                      &actualAuthTagLength, static_cast<size_t>(actualAuthTag.size())) != 1 ||
        actualAuthTagLength != kHmacTagSize ||
        CRYPTO_memcmp(expectedAuthTag.constData(), actualAuthTag.constData(), kHmacTagSize) != 0 ||
        !outputFile.commit())
    {
        outputFile.cancelWriting();
        SecureClear(decryptionKey);
        SecureClear(authKey);
        SecureClear(passwordSalt);
        SecureClear(actualAuthTag);
        return false;
    }

    SecureClear(decryptionKey);
    SecureClear(authKey);
    SecureClear(passwordSalt);
    SecureClear(actualAuthTag);

    return true;
}