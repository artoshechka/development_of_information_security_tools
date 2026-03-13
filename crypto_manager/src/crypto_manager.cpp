/// @file
/// @brief Определение менеджера криптографических операций (Singleton).
/// @author Artemenko Anton

#include <src/crypto_manager.hpp>

#include <QByteArray>
#include <QFile>
#include <QSaveFile>
#include <QString>

#include <algorithm>
#include <memory>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>

using crypto_manager::OpenSSLCryptoManager;
namespace
{

/// Сигнатура зашифрованного файла
static const QByteArray FILE_MAGIC_SIGNATURE = "A5E2BDE2-21FD-4D6B-A905-78A326846E07";

/// Размер соли для PBKDF2.
static constexpr int PASSWORD_SALT_SIZE = 16;

/// Размер ключа AES-256.
static constexpr int AES_KEY_SIZE = 32;

/// Размер ключа HMAC-SHA256.
static constexpr int HMAC_KEY_SIZE = 32;

/// Размер тега HMAC-SHA256.
static constexpr int HMAC_TAG_SIZE = 32;

/// Количество итераций PBKDF2.
static constexpr int PBKDF2_ITERATION_COUNT = 200000;

/// Размер вектора инициализации для AES-CBC.
static constexpr int AES_INITIALIZATION_VECTOR_SIZE = 16;

/// Размер блока чтения для потоковой обработки файла.
static constexpr qint64 FILE_PROCESSING_CHUNK_SIZE = 64 * 1024;

/// @brief Безопасная очистка чувствительного буфера.
static void secureClear(QByteArray &data)
{
    if (!data.isEmpty())
    {
        OPENSSL_cleanse(data.data(), static_cast<size_t>(data.size()));
        data.clear();
        data.squeeze();
    }
}

/// @brief Генерация ключей шифрования и аутентификации из пароля и соли через PBKDF2.
/// @param[in] userPassword Пароль пользователя.
/// @param[in] salt Случайная соль.
/// @param[out] outEncryptionKey Итоговый 32-байтовый ключ шифрования.
/// @param[out] outAuthKey Итоговый 32-байтовый ключ аутентификации.
/// @return True при успешной генерации ключа.
static bool deriveKeys(const QString &userPassword, const QByteArray &salt, QByteArray &outEncryptionKey,
                       QByteArray &outAuthKey)
{
    QByteArray passwordBytes = userPassword.toUtf8();
    QByteArray keyMaterial(AES_KEY_SIZE + HMAC_KEY_SIZE, Qt::Uninitialized);

    const bool isOk = PKCS5_PBKDF2_HMAC(
                          passwordBytes.constData(), passwordBytes.size(),
                          reinterpret_cast<const unsigned char *>(salt.constData()), salt.size(),
                          PBKDF2_ITERATION_COUNT, EVP_sha256(), keyMaterial.size(),
                          reinterpret_cast<unsigned char *>(keyMaterial.data())) == 1;

    secureClear(passwordBytes);

    if (!isOk)
    {
        secureClear(keyMaterial);
        secureClear(outEncryptionKey);
        secureClear(outAuthKey);
        return false;
    }

    outEncryptionKey = keyMaterial.left(AES_KEY_SIZE);
    outAuthKey = keyMaterial.mid(AES_KEY_SIZE, HMAC_KEY_SIZE);
    secureClear(keyMaterial);

    return true;
}

/// @brief Структура для автоматического освобождения ресурсов EVP_CIPHER_CTX с помощью std::unique_ptr.
struct EVP_CIPHER_CTX_Deleter
{
    void operator()(EVP_CIPHER_CTX *ctx) const
    {
        if (ctx)
        {
            EVP_CIPHER_CTX_free(ctx);
        }
    }
};

/// @brief Тип умного указателя для EVP_CIPHER_CTX
using UniqPtrCipherContext = std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter>;

/// @brief Структура для автоматического освобождения ресурсов EVP_MAC.
struct MacDeleter
{
    void operator()(EVP_MAC *mac) const
    {
        if (mac)
        {
            EVP_MAC_free(mac);
        }
    }
};

/// @brief Структура для автоматического освобождения ресурсов EVP_MAC_CTX.
struct MacContextDeleter
{
    void operator()(EVP_MAC_CTX *ctx) const
    {
        if (ctx)
        {
            EVP_MAC_CTX_free(ctx);
        }
    }
};

/// @brief Умные указатели для MAC-ресурсов OpenSSL.
using UniqPtrMac = std::unique_ptr<EVP_MAC, MacDeleter>;
using UniqPtrMacContext = std::unique_ptr<EVP_MAC_CTX, MacContextDeleter>;

/// @brief Контейнер для MAC алгоритма и контекста.
struct HmacState
{
    UniqPtrMac mac_;
    UniqPtrMacContext context_;
};

/// @brief Инициализация HMAC-SHA256 контекста на базе EVP_MAC.
static bool initializeHmacState(const QByteArray &authKey, HmacState &hmacState)
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
        const QByteArray chunk = inputFile.read(FILE_PROCESSING_CHUNK_SIZE);

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
        const qint64 bytesToRead = std::min(bytesRemaining, FILE_PROCESSING_CHUNK_SIZE);
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

    const QByteArray filePrefix = inputFile.read(FILE_MAGIC_SIGNATURE.size());

    if (filePrefix == FILE_MAGIC_SIGNATURE)
        return false;

    if (!inputFile.seek(0))
        return false;

    QSaveFile outputFile(filePath);
    if (!outputFile.open(QIODevice::WriteOnly))
        return false;

    QByteArray passwordSalt(PASSWORD_SALT_SIZE, Qt::Uninitialized);

    if (!RAND_bytes(reinterpret_cast<unsigned char *>(passwordSalt.data()), passwordSalt.size()))
    {
        outputFile.cancelWriting();
        return false;
    }

    QByteArray encryptionKey;
    QByteArray authKey;
    if (!deriveKeys(password, passwordSalt, encryptionKey, authKey))
    {
        outputFile.cancelWriting();
        return false;
    }

    std::vector<unsigned char> initializationVector(AES_INITIALIZATION_VECTOR_SIZE);

    if (!RAND_bytes(initializationVector.data(), initializationVector.size()))
    {
        outputFile.cancelWriting();
        secureClear(encryptionKey);
        secureClear(authKey);
        secureClear(passwordSalt);
        return false;
    }

    UniqPtrCipherContext cipherContext(EVP_CIPHER_CTX_new());
    if (!cipherContext)
    {
        outputFile.cancelWriting();
        secureClear(encryptionKey);
        secureClear(authKey);
        secureClear(passwordSalt);
        return false;
    }

    HmacState hmacState;
    if (!initializeHmacState(authKey, hmacState))
    {
        outputFile.cancelWriting();
        secureClear(encryptionKey);
        secureClear(authKey);
        secureClear(passwordSalt);
        return false;
    }

    if (!EVP_EncryptInit_ex(cipherContext.get(), EVP_aes_256_cbc(), nullptr,
                            reinterpret_cast<const unsigned char *>(encryptionKey.data()), initializationVector.data()))
    {
        outputFile.cancelWriting();
        secureClear(encryptionKey);
        secureClear(passwordSalt);
        return false;
    }

    if (!writeAll(outputFile, FILE_MAGIC_SIGNATURE.constData(), FILE_MAGIC_SIGNATURE.size()) ||
        !writeAll(outputFile, passwordSalt.constData(), passwordSalt.size()) ||
        !writeAll(outputFile, reinterpret_cast<const char *>(initializationVector.data()),
                  static_cast<qint64>(initializationVector.size())) ||
        !encryptStream(inputFile, outputFile, cipherContext.get(), hmacState.context_.get()))
    {
        outputFile.cancelWriting();
        secureClear(encryptionKey);
        secureClear(authKey);
        secureClear(passwordSalt);
        return false;
    }

    QByteArray authTag(HMAC_TAG_SIZE, Qt::Uninitialized);
    size_t authTagLength = 0;
    if (EVP_MAC_final(hmacState.context_.get(), reinterpret_cast<unsigned char *>(authTag.data()), &authTagLength,
                      static_cast<size_t>(authTag.size())) != 1 ||
        authTagLength != HMAC_TAG_SIZE || !writeAll(outputFile, authTag.constData(), authTag.size()) ||
        !outputFile.commit())
    {
        outputFile.cancelWriting();
        secureClear(encryptionKey);
        secureClear(authKey);
        secureClear(passwordSalt);
        secureClear(authTag);
        return false;
    }

    secureClear(encryptionKey);
    secureClear(authKey);
    secureClear(passwordSalt);
    secureClear(authTag);

    return true;
}

bool OpenSSLCryptoManager::DecryptFile(const QString &filePath, const QString &password)
{
    QFile inputFile(filePath);
    if (!inputFile.open(QIODevice::ReadOnly))
        return false;

    const QByteArray fileSignature = inputFile.read(FILE_MAGIC_SIGNATURE.size());

    if (fileSignature != FILE_MAGIC_SIGNATURE)
        return false;

    QByteArray passwordSalt = inputFile.read(PASSWORD_SALT_SIZE);

    if (passwordSalt.size() != PASSWORD_SALT_SIZE)
        return false;

    QByteArray initializationVector = inputFile.read(AES_INITIALIZATION_VECTOR_SIZE);

    if (initializationVector.size() != AES_INITIALIZATION_VECTOR_SIZE)
        return false;

    const qint64 headerSize = FILE_MAGIC_SIGNATURE.size() + PASSWORD_SALT_SIZE + AES_INITIALIZATION_VECTOR_SIZE;
    const qint64 encryptedFileSize = inputFile.size();

    if (encryptedFileSize < headerSize + HMAC_TAG_SIZE)
        return false;

    const qint64 encryptedPayloadSize = encryptedFileSize - headerSize - HMAC_TAG_SIZE;

    QByteArray decryptionKey;
    QByteArray authKey;
    if (!deriveKeys(password, passwordSalt, decryptionKey, authKey))
    {
        secureClear(passwordSalt);
        return false;
    }

    QSaveFile outputFile(filePath);
    if (!outputFile.open(QIODevice::WriteOnly))
    {
        secureClear(decryptionKey);
        secureClear(authKey);
        secureClear(passwordSalt);
        return false;
    }

    UniqPtrCipherContext cipherContext(EVP_CIPHER_CTX_new());
    if (!cipherContext)
    {
        outputFile.cancelWriting();
        secureClear(decryptionKey);
        secureClear(authKey);
        secureClear(passwordSalt);
        return false;
    }

    if (!EVP_DecryptInit_ex(cipherContext.get(), EVP_aes_256_cbc(), nullptr,
                            reinterpret_cast<const unsigned char *>(decryptionKey.data()),
                            reinterpret_cast<const unsigned char *>(initializationVector.data())))
    {
        outputFile.cancelWriting();
        secureClear(decryptionKey);
        secureClear(authKey);
        secureClear(passwordSalt);
        return false;
    }

    HmacState hmacState;
    if (!initializeHmacState(authKey, hmacState))
    {
        outputFile.cancelWriting();
        secureClear(decryptionKey);
        secureClear(authKey);
        secureClear(passwordSalt);
        return false;
    }

    if (!decryptStream(inputFile, outputFile, cipherContext.get(), hmacState.context_.get(), encryptedPayloadSize))
    {
        outputFile.cancelWriting();
        secureClear(decryptionKey);
        secureClear(authKey);
        secureClear(passwordSalt);
        return false;
    }

    const QByteArray expectedAuthTag = inputFile.read(HMAC_TAG_SIZE);
    QByteArray actualAuthTag(HMAC_TAG_SIZE, Qt::Uninitialized);
    size_t actualAuthTagLength = 0;

    if (expectedAuthTag.size() != HMAC_TAG_SIZE ||
        EVP_MAC_final(hmacState.context_.get(), reinterpret_cast<unsigned char *>(actualAuthTag.data()),
                      &actualAuthTagLength, static_cast<size_t>(actualAuthTag.size())) != 1 ||
        actualAuthTagLength != HMAC_TAG_SIZE ||
        CRYPTO_memcmp(expectedAuthTag.constData(), actualAuthTag.constData(), HMAC_TAG_SIZE) != 0 ||
        !outputFile.commit())
    {
        outputFile.cancelWriting();
        secureClear(decryptionKey);
        secureClear(authKey);
        secureClear(passwordSalt);
        secureClear(actualAuthTag);
        return false;
    }

    secureClear(decryptionKey);
    secureClear(authKey);
    secureClear(passwordSalt);
    secureClear(actualAuthTag);

    return true;
}