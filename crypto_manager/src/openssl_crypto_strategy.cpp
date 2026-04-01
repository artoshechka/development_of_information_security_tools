/// @file
/// @brief OpenSSL-реализация криптографической стратегии.
/// @author Artemenko Anton

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <QByteArray>
#include <QFile>
#include <QSaveFile>
#include <QString>
#include <algorithm>
#include <logger_macros.hpp>
#include <src/crypto_primitives.hpp>
#include <src/openssl_crypto_strategy.hpp>
#include <vector>

using crypto_manager::OpenSslCryptoStrategy;
using namespace crypto_manager::crypto_primitives;
namespace
{

/// @brief Безопасная запись буфера в файл с проверкой полного количества байт.
/// @param[in, out] outputFile Файл для записи.
/// @param[in,out] data Буфер данных для записи.
/// @param[in] size Количество байт для записи.
static bool writeAll(QSaveFile& outputFile, const char* data, const qint64 size)
{
    return outputFile.write(data, size) == size;
}
/// @brief Безопасное очищение вектора.
/// @param data Вектор для очищения.
static void secureClearVector(std::vector<unsigned char>& data)
{
    if (!data.empty())
    {
        OPENSSL_cleanse(data.data(), data.size());
        data.clear();
    }
}

/// @brief Шифрование содержимого файла целиком.
/// @param[in] plaintext Исходные данные для шифрования.
/// @param[out] encryptedData Зашифрованные данные.
/// @param[in] cipherContext Инициализированный контекст шифрования OpenSSL.
static bool encryptData(const QByteArray& plaintext, QByteArray& encryptedData, EVP_CIPHER_CTX* cipherContext)
{
    encryptedData.clear();
    if (plaintext.isEmpty())
    {
        return true;
    }

    QByteArray buffer(plaintext.size() + EVP_MAX_BLOCK_LENGTH, 0);
    int outputLength = 0;

    if (!EVP_EncryptUpdate(cipherContext, reinterpret_cast<unsigned char*>(buffer.data()), &outputLength,
                           reinterpret_cast<const unsigned char*>(plaintext.constData()), plaintext.size()))
    {
        return false;
    }

    encryptedData.append(buffer.constData(), outputLength);

    QByteArray finalChunk(EVP_MAX_BLOCK_LENGTH, 0);
    int finalLength = 0;

    if (!EVP_EncryptFinal_ex(cipherContext, reinterpret_cast<unsigned char*>(finalChunk.data()), &finalLength))
    {
        return false;
    }

    if (finalLength > 0)
    {
        encryptedData.append(finalChunk.constData(), finalLength);
    }

    return true;
}

/// @brief Дешифрование содержимого файла целиком.
/// @param[in] ciphertext Зашифрованные данные.
/// @param[out] decryptedData Расшифрованные данные.
/// @param[in] cipherContext Инициализированный контекст дешифрования OpenSSL.
static bool decryptData(const QByteArray& ciphertext, QByteArray& decryptedData, EVP_CIPHER_CTX* cipherContext)
{
    decryptedData.clear();
    if (ciphertext.isEmpty())
    {
        return true;
    }

    QByteArray buffer(ciphertext.size() + EVP_MAX_BLOCK_LENGTH, 0);
    int outputLength = 0;

    if (!EVP_DecryptUpdate(cipherContext, reinterpret_cast<unsigned char*>(buffer.data()), &outputLength,
                           reinterpret_cast<const unsigned char*>(ciphertext.constData()), ciphertext.size()))
    {
        return false;
    }

    decryptedData.append(buffer.constData(), outputLength);

    QByteArray finalChunk(EVP_MAX_BLOCK_LENGTH, 0);
    int finalLength = 0;

    if (EVP_DecryptFinal_ex(cipherContext, reinterpret_cast<unsigned char*>(finalChunk.data()), &finalLength) <= 0)
    {
        return false;
    }

    if (finalLength > 0)
    {
        decryptedData.append(finalChunk.constData(), finalLength);
    }

    return true;
}

}  // namespace

OpenSslCryptoStrategy::OpenSslCryptoStrategy(const std::shared_ptr<logger::ILogger>& logger) : logger_(logger)
{
}

bool OpenSslCryptoStrategy::PerformEncryptionOperation(const QString& filePath, const QString& password)
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
        inputFile.close();
        return false;
    }

    if (!inputFile.seek(0))
    {
        LogError(logger_) << "Failed to seek input file: " << filePath;
        inputFile.close();
        return false;
    }

    const QByteArray fileContent = inputFile.readAll();

    if (inputFile.error() != QFileDevice::NoError)
    {
        LogError(logger_) << "Failed to read input file: " << filePath;
        inputFile.close();
        return false;
    }

    inputFile.close();

    QSaveFile outputFile(filePath);
    if (!outputFile.open(QIODevice::WriteOnly))
    {
        LogError(logger_) << "Failed to open output file for encryption: " << filePath;
        return false;
    }

    QByteArray passwordSalt(kPasswordSaltSize, Qt::Uninitialized);

    if (!RAND_bytes(reinterpret_cast<unsigned char*>(passwordSalt.data()), passwordSalt.size()))
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
                            reinterpret_cast<const unsigned char*>(encryptionKey.constData()), nonce.data()))
    {
        LogError(logger_) << "Failed to initialize AES-256-GCM encryption context";
        outputFile.cancelWriting();
        SecureClear(encryptionKey);
        secureClearVector(nonce);
        SecureClear(passwordSalt);
        return false;
    }

    QByteArray encryptedData;
    if (!encryptData(fileContent, encryptedData, cipherContext.get()))
    {
        LogError(logger_) << "Failed to encrypt data";
        outputFile.cancelWriting();
        SecureClear(encryptionKey);
        secureClearVector(nonce);
        SecureClear(passwordSalt);
        return false;
    }

    if (!writeAll(outputFile, kFileMagicSignature.constData(), kFileMagicSignature.size()) ||
        !writeAll(outputFile, passwordSalt.constData(), passwordSalt.size()) ||
        !writeAll(outputFile, reinterpret_cast<const char*>(nonce.data()), static_cast<qint64>(nonce.size())) ||
        !writeAll(outputFile, encryptedData.constData(), encryptedData.size()))
    {
        LogError(logger_) << "Failed to write encrypted data to file";
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

bool OpenSslCryptoStrategy::PerformDecryptionOperation(const QString& filePath, const QString& password)
{
    QFile inputFile(filePath);
    if (!inputFile.open(QIODevice::ReadOnly))
    {
        LogError(logger_) << "Failed to open input file for decryption: " << filePath;
        return false;
    }

    const qint64 fileSize = inputFile.size();
    const qint64 headerSize = kFileMagicSignature.size() + kPasswordSaltSize + kAesGcmNonceSize;

    if (fileSize < headerSize + kAesGcmTagSize)
    {
        LogError(logger_) << "Encrypted file is too small";
        inputFile.close();
        return false;
    }

    const QByteArray fileSignature = inputFile.read(kFileMagicSignature.size());

    if (fileSignature != kFileMagicSignature)
    {
        LogWarning(logger_) << "File does not match encrypted format: " << filePath;
        inputFile.close();
        return false;
    }

    QByteArray passwordSalt = inputFile.read(kPasswordSaltSize);

    if (passwordSalt.size() != kPasswordSaltSize)
    {
        LogError(logger_) << "Invalid salt size in encrypted file";
        inputFile.close();
        return false;
    }

    QByteArray nonce = inputFile.read(kAesGcmNonceSize);

    if (nonce.size() != kAesGcmNonceSize)
    {
        LogError(logger_) << "Invalid nonce size in encrypted file";
        inputFile.close();
        return false;
    }

    const qint64 encryptedPayloadSize = fileSize - headerSize - kAesGcmTagSize;
    const QByteArray encryptedData = inputFile.read(encryptedPayloadSize);

    if (encryptedData.size() != encryptedPayloadSize)
    {
        LogError(logger_) << "Failed to read encrypted payload";
        inputFile.close();
        return false;
    }

    QByteArray authTag = inputFile.read(kAesGcmTagSize);

    if (authTag.size() != kAesGcmTagSize)
    {
        LogError(logger_) << "Invalid authentication tag size in encrypted file";
        inputFile.close();
        SecureClear(authTag);
        return false;
    }

    inputFile.close();

    QByteArray decryptionKey;
    if (!DeriveEncryptionKey(password, passwordSalt, decryptionKey))
    {
        LogError(logger_) << "Failed to derive decryption key";
        SecureClear(passwordSalt);
        SecureClear(nonce);
        SecureClear(authTag);
        return false;
    }

    UniqPtrCipherContext cipherContext(EVP_CIPHER_CTX_new());
    if (!cipherContext)
    {
        LogError(logger_) << "Failed to allocate OpenSSL cipher context";
        SecureClear(decryptionKey);
        SecureClear(passwordSalt);
        SecureClear(nonce);
        SecureClear(authTag);
        return false;
    }

    if (!EVP_DecryptInit_ex(cipherContext.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) ||
        !EVP_CIPHER_CTX_ctrl(cipherContext.get(), EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) ||
        !EVP_DecryptInit_ex(cipherContext.get(), nullptr, nullptr,
                            reinterpret_cast<const unsigned char*>(decryptionKey.constData()),
                            reinterpret_cast<const unsigned char*>(nonce.constData())) ||
        !EVP_CIPHER_CTX_ctrl(cipherContext.get(), EVP_CTRL_GCM_SET_TAG, authTag.size(), authTag.data()))
    {
        LogError(logger_) << "Failed to initialize AES-256-GCM decryption context";
        SecureClear(decryptionKey);
        SecureClear(passwordSalt);
        SecureClear(nonce);
        SecureClear(authTag);
        return false;
    }

    QByteArray decryptedData;
    if (!decryptData(encryptedData, decryptedData, cipherContext.get()))
    {
        LogError(logger_) << "Authentication failed or decryption error";
        SecureClear(decryptionKey);
        SecureClear(passwordSalt);
        SecureClear(nonce);
        SecureClear(authTag);
        return false;
    }

    QSaveFile outputFile(filePath);
    if (!outputFile.open(QIODevice::WriteOnly))
    {
        LogError(logger_) << "Failed to open output file for decryption: " << filePath;
        SecureClear(decryptionKey);
        SecureClear(passwordSalt);
        SecureClear(nonce);
        SecureClear(authTag);
        return false;
    }

    if (!writeAll(outputFile, decryptedData.constData(), decryptedData.size()) || !outputFile.commit())
    {
        LogError(logger_) << "Failed to write decrypted output file";
        outputFile.cancelWriting();
        SecureClear(decryptionKey);
        SecureClear(passwordSalt);
        SecureClear(nonce);
        SecureClear(authTag);
        SecureClear(decryptedData);
        return false;
    }

    SecureClear(decryptionKey);
    SecureClear(passwordSalt);
    SecureClear(nonce);
    SecureClear(authTag);
    SecureClear(decryptedData);

    return true;
}
