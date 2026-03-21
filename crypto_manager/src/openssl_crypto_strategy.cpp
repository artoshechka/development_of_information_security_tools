/// @file
/// @brief OpenSSL-реализация криптографической стратегии.
/// @author Artemenko Anton

#include <src/openssl_crypto_strategy.hpp>
#include <src/crypto_primitives.hpp>

#include <logger_macros.hpp>

#include <QByteArray>
#include <QFile>
#include <QSaveFile>
#include <QString>

#include <algorithm>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

using crypto_manager::OpenSslCryptoStrategy;
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

OpenSslCryptoStrategy::OpenSslCryptoStrategy(const std::shared_ptr<logger::ILogger> &logger) : logger_(logger)
{
}

bool OpenSslCryptoStrategy::EncryptFile(const QString &filePath, const QString &password)
{
    QFile inputFile(filePath);

    if (!inputFile.open(QIODevice::ReadOnly))
    {
        LogError(logger_) << "Failed to open input file for encryption: " << filePath;
        return false;
    }

    const QByteArray filePrefix = inputFile.read(kFileMagicSignature.size());

    if (filePrefix == kFileMagicSignature)
    {
        LogWarning(logger_) << "File is already encrypted: " << filePath;
        return false;
    }

    if (!inputFile.seek(0))
    {
        LogError(logger_) << "Failed to seek input file: " << filePath;
        return false;
    }

    QSaveFile outputFile(filePath);
    if (!outputFile.open(QIODevice::WriteOnly))
    {
        LogError(logger_) << "Failed to open output file for encryption: " << filePath;
        return false;
    }

    QByteArray passwordSalt(kPasswordSaltSize, Qt::Uninitialized);

    if (!RAND_bytes(reinterpret_cast<unsigned char *>(passwordSalt.data()), passwordSalt.size()))
    {
        LogError(logger_) << "Failed to generate salt for encryption";
        outputFile.cancelWriting();
        return false;
    }

    QByteArray encryptionKey;
    if (!DeriveEncryptionKey(password, passwordSalt, encryptionKey))
    {
        LogError(logger_) << "Failed to derive encryption key";
        outputFile.cancelWriting();
        return false;
    }

    std::vector<unsigned char> nonce(kAesGcmNonceSize);

    if (!RAND_bytes(nonce.data(), nonce.size()))
    {
        LogError(logger_) << "Failed to generate nonce for encryption";
        outputFile.cancelWriting();
        SecureClear(encryptionKey);
        SecureClear(passwordSalt);
        return false;
    }

    UniqPtrCipherContext cipherContext(EVP_CIPHER_CTX_new());
    if (!cipherContext)
    {
        LogError(logger_) << "Failed to allocate OpenSSL cipher context";
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
        LogError(logger_) << "Failed to initialize AES-256-GCM encryption context";
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
        LogError(logger_) << "Failed during encrypted stream write";
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
        LogError(logger_) << "Failed to finalize encrypted file";
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

bool OpenSslCryptoStrategy::DecryptFile(const QString &filePath, const QString &password)
{
    QFile inputFile(filePath);
    if (!inputFile.open(QIODevice::ReadOnly))
    {
        LogError(logger_) << "Failed to open input file for decryption: " << filePath;
        return false;
    }

    const QByteArray fileSignature = inputFile.read(kFileMagicSignature.size());

    if (fileSignature != kFileMagicSignature)
    {
        LogWarning(logger_) << "File does not match encrypted format: " << filePath;
        return false;
    }

    QByteArray passwordSalt = inputFile.read(kPasswordSaltSize);

    if (passwordSalt.size() != kPasswordSaltSize)
    {
        LogError(logger_) << "Invalid salt size in encrypted file";
        return false;
    }

    QByteArray nonce = inputFile.read(kAesGcmNonceSize);

    if (nonce.size() != kAesGcmNonceSize)
    {
        LogError(logger_) << "Invalid nonce size in encrypted file";
        return false;
    }

    const qint64 headerSize = kFileMagicSignature.size() + kPasswordSaltSize + kAesGcmNonceSize;
    const qint64 encryptedFileSize = inputFile.size();

    if (encryptedFileSize < headerSize + kAesGcmTagSize)
    {
        LogError(logger_) << "Encrypted file is too small";
        return false;
    }

    const qint64 encryptedPayloadSize = encryptedFileSize - headerSize - kAesGcmTagSize;

    QByteArray decryptionKey;
    if (!DeriveEncryptionKey(password, passwordSalt, decryptionKey))
    {
        LogError(logger_) << "Failed to derive decryption key";
        SecureClear(passwordSalt);
        SecureClear(nonce);
        return false;
    }

    QSaveFile outputFile(filePath);
    if (!outputFile.open(QIODevice::WriteOnly))
    {
        LogError(logger_) << "Failed to open output file for decryption: " << filePath;
        SecureClear(decryptionKey);
        SecureClear(passwordSalt);
        SecureClear(nonce);
        return false;
    }

    UniqPtrCipherContext cipherContext(EVP_CIPHER_CTX_new());
    if (!cipherContext)
    {
        LogError(logger_) << "Failed to allocate OpenSSL cipher context";
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
        LogError(logger_) << "Failed to initialize AES-256-GCM decryption context";
        outputFile.cancelWriting();
        SecureClear(decryptionKey);
        SecureClear(passwordSalt);
        SecureClear(nonce);
        return false;
    }

    if (!decryptStream(inputFile, outputFile, cipherContext.get(), encryptedPayloadSize))
    {
        LogError(logger_) << "Failed during encrypted stream read";
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
        LogError(logger_) << "Failed to set authentication tag for decryption";
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
        LogError(logger_) << "Authentication failed during decrypt finalization";
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
        LogError(logger_) << "Failed to write decrypted output file";
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
