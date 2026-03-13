/// @file
/// @brief Определение менеджера криптографических операций (Singleton).
/// @author Artemenko Anton

#include <src/crypto_manager.hpp>

#include <QByteArray>
#include <QCryptographicHash>
#include <QFile>
#include <QSaveFile>
#include <QString>

#include <memory>
#include <vector>

#include <openssl/evp.h>
#include <openssl/rand.h>

using crypto_manager::OpenSSLCryptoManager;
namespace
{

/// Сигнатура зашифрованного файла
static const QByteArray FILE_MAGIC_SIGNATURE = "A5E2BDE2-21FD-4D6B-A905-78A326846E07";

/// Размер вектора инициализации для AES-CBC.
static constexpr int AES_INITIALIZATION_VECTOR_SIZE = 16;

/// Размер блока чтения для потоковой обработки файла.
static constexpr qint64 FILE_PROCESSING_CHUNK_SIZE = 64 * 1024;

/// @brief Генерация криптографического ключа из пароля.
/// @param[in] userPassword Пароль пользователя.
/// @return 32-байтовый ключ (SHA-256), подходящий для AES-256.
static QByteArray deriveKey(const QString &userPassword)
{
    return QCryptographicHash::hash(userPassword.toUtf8(), QCryptographicHash::Sha256);
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

/// @brief Безопасная запись буфера в файл с проверкой полного количества байт.
static bool writeAll(QSaveFile &outputFile, const char *data, const qint64 size)
{
    return outputFile.write(data, size) == size;
}

/// @brief Чтение и шифрование файла по частям.
static bool encryptStream(QFile &inputFile, QSaveFile &outputFile, EVP_CIPHER_CTX *cipherContext)
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
static bool decryptStream(QFile &inputFile, QSaveFile &outputFile, EVP_CIPHER_CTX *cipherContext)
{
    while (!inputFile.atEnd())
    {
        const QByteArray chunk = inputFile.read(FILE_PROCESSING_CHUNK_SIZE);

        if (chunk.isEmpty() && inputFile.error() != QFileDevice::NoError)
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

    const QByteArray encryptionKey = deriveKey(password);

    std::vector<unsigned char> initializationVector(AES_INITIALIZATION_VECTOR_SIZE);

    if (!RAND_bytes(initializationVector.data(), initializationVector.size()))
        return false;

    UniqPtrCipherContext cipherContext(EVP_CIPHER_CTX_new());
    if (!cipherContext)
    {
        return false;
    }

    if (!EVP_EncryptInit_ex(cipherContext.get(), EVP_aes_256_cbc(), nullptr,
                            reinterpret_cast<const unsigned char *>(encryptionKey.data()), initializationVector.data()))
    {
        return false;
    }

    if (!writeAll(outputFile, FILE_MAGIC_SIGNATURE.constData(), FILE_MAGIC_SIGNATURE.size()) ||
        !writeAll(outputFile, reinterpret_cast<const char *>(initializationVector.data()),
                  static_cast<qint64>(initializationVector.size())) ||
        !encryptStream(inputFile, outputFile, cipherContext.get()) || !outputFile.commit())
    {
        outputFile.cancelWriting();
        return false;
    }

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

    QByteArray initializationVector = inputFile.read(AES_INITIALIZATION_VECTOR_SIZE);

    if (initializationVector.size() != AES_INITIALIZATION_VECTOR_SIZE)
        return false;

    const QByteArray decryptionKey = deriveKey(password);

    QSaveFile outputFile(filePath);
    if (!outputFile.open(QIODevice::WriteOnly))
        return false;

    UniqPtrCipherContext cipherContext(EVP_CIPHER_CTX_new());
    if (!cipherContext)
    {
        outputFile.cancelWriting();
        return false;
    }

    if (!EVP_DecryptInit_ex(cipherContext.get(), EVP_aes_256_cbc(), nullptr,
                            reinterpret_cast<const unsigned char *>(decryptionKey.data()),
                            reinterpret_cast<const unsigned char *>(initializationVector.data())))
    {
        outputFile.cancelWriting();
        return false;
    }

    if (!decryptStream(inputFile, outputFile, cipherContext.get()) || !outputFile.commit())
    {
        outputFile.cancelWriting();
        return false;
    }

    return true;
}