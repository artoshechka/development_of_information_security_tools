/// @file
/// @brief Определение менеджера криптографических операций (Singleton).
/// @author Artemenko Anton

#include <src/crypto_manager.hpp>

#include <QByteArray>
#include <QCryptographicHash>
#include <QFile>
#include <QString>

#include <openssl/evp.h>
#include <openssl/rand.h>

using crypto_manager::OpenSSLCryptoManager;
namespace
{

/// Сигнатура зашифрованного файла
static const QByteArray FILE_MAGIC_SIGNATURE = "A5E2BDE2-21FD-4D6B-A905-78A326846E07";

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

} // namespace

OpenSSLCryptoManager &OpenSSLCryptoManager::Instance()
{
    static OpenSSLCryptoManager singletonInstance;
    return singletonInstance;
}

bool OpenSSLCryptoManager::EncryptFile(const QString &filePath, const QString &password)
{
    QFile inputFile(filePath);

    if (!inputFile.open(QIODevice::ReadWrite))
        return false;

    const auto &fileContent = inputFile.readAll();
    inputFile.close();

    if (fileContent.startsWith(FILE_MAGIC_SIGNATURE))
        return false;

    const auto &encryptionKey = deriveKey(password);

    std::vector<unsigned char> initializationVector(16);

    if (!RAND_bytes(initializationVector.data(), initializationVector.size()))
        return false;

    UniqPtrCipherContext cipherContext(EVP_CIPHER_CTX_new());
    if (!cipherContext)
    {
        return false;
    }

    QByteArray encryptedData(fileContent.size() + EVP_MAX_BLOCK_LENGTH, 0);

    int bytesProcessed = 0;
    int totalCiphertextLength = 0;

    if (!EVP_EncryptInit_ex(cipherContext.get(), EVP_aes_256_cbc(), nullptr,
                            reinterpret_cast<const unsigned char *>(encryptionKey.data()), initializationVector.data()))
    {
        return false;
    }

    if (!EVP_EncryptUpdate(cipherContext.get(), reinterpret_cast<unsigned char *>(encryptedData.data()),
                           &bytesProcessed, reinterpret_cast<const unsigned char *>(fileContent.data()),
                           fileContent.size()))
    {
        return false;
    }
    totalCiphertextLength = bytesProcessed;

    if (!EVP_EncryptFinal_ex(cipherContext.get(),
                             reinterpret_cast<unsigned char *>(encryptedData.data()) + bytesProcessed, &bytesProcessed))
    {
        return false;
    }
    totalCiphertextLength += bytesProcessed;

    encryptedData.resize(totalCiphertextLength);

    QFile outputFile(filePath);
    if (!outputFile.open(QIODevice::WriteOnly))
        return false;

    outputFile.write(FILE_MAGIC_SIGNATURE);
    outputFile.write(reinterpret_cast<char *>(initializationVector.data()), initializationVector.size());
    outputFile.write(encryptedData);

    outputFile.close();
    return true;
}

bool OpenSSLCryptoManager::DecryptFile(const QString &filePath, const QString &password)
{
    QFile inputFile(filePath);
    if (!inputFile.open(QIODevice::ReadWrite))
        return false;

    const auto &fileContent = inputFile.readAll();
    inputFile.close();

    if (!fileContent.startsWith(FILE_MAGIC_SIGNATURE))
        return false;

    const auto &decryptionKey = deriveKey(password);

    QByteArray initializationVector = fileContent.mid(FILE_MAGIC_SIGNATURE.size(), 16);
    QByteArray encryptedData = fileContent.mid(FILE_MAGIC_SIGNATURE.size() + 16);

    UniqPtrCipherContext cipherContext(EVP_CIPHER_CTX_new());
    if (!cipherContext)
        return false;

    std::vector<unsigned char> decryptedData(encryptedData.size() + EVP_MAX_BLOCK_LENGTH);
    int bytesProcessed = 0;
    int totalPlaintextLength = 0;

    if (!EVP_DecryptInit_ex(cipherContext.get(), EVP_aes_256_cbc(), nullptr,
                            reinterpret_cast<const unsigned char *>(decryptionKey.data()),
                            reinterpret_cast<const unsigned char *>(initializationVector.data())))
        return false;

    if (!EVP_DecryptUpdate(cipherContext.get(), decryptedData.data(), &bytesProcessed,
                           reinterpret_cast<const unsigned char *>(encryptedData.data()), encryptedData.size()))
        return false;
    totalPlaintextLength = bytesProcessed;

    if (!EVP_DecryptFinal_ex(cipherContext.get(), decryptedData.data() + bytesProcessed, &bytesProcessed))
        return false;
    totalPlaintextLength += bytesProcessed;

    decryptedData.resize(totalPlaintextLength);

    QFile outputFile(filePath);
    if (!outputFile.open(QIODevice::WriteOnly))
        return false;

    outputFile.write(reinterpret_cast<char *>(decryptedData.data()), decryptedData.size());
    outputFile.close();

    return true;
}