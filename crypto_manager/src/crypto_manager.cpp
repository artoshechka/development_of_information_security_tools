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

namespace
{

/// Сигнатура зашифрованного файла
static const QByteArray MAGIC = "ENCFILE1";

/// @brief Генерация криптографического ключа из пароля.
/// @param[in] password Пароль пользователя.
/// @return 32-байтовый ключ (SHA-256), подходящий для AES-256.
static QByteArray deriveKey(const QString &password)
{
    return QCryptographicHash::hash(password.toUtf8(), QCryptographicHash::Sha256);
}

} // namespace

CryptoManager &CryptoManager::Instance()
{
    static CryptoManager instance;
    return instance;
}

bool CryptoManager::EncryptFile(const QString &filePath, const QString &password)
{
    QFile file(filePath);

    if (!file.open(QIODevice::ReadOnly))
        return false;

    QByteArray data = file.readAll();
    file.close();

    // Проверка: уже зашифрован?
    if (data.startsWith(MAGIC))
        return false;

    QByteArray key = deriveKey(password);

    unsigned char iv[16];

    if (!RAND_bytes(iv, sizeof(iv)))
        return false;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (!ctx)
        return false;

    QByteArray encrypted(data.size() + 16, 0);

    int len = 0;
    int ciphertext_len = 0;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, reinterpret_cast<const unsigned char *>(key.data()), iv))
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (!EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char *>(encrypted.data()), &len,
                           reinterpret_cast<const unsigned char *>(data.data()), data.size()))
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    ciphertext_len = len;

    if (!EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char *>(encrypted.data()) + len, &len))
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    encrypted.resize(ciphertext_len);

    QFile outFile(filePath);

    if (!outFile.open(QIODevice::WriteOnly))
        return false;

    outFile.write(MAGIC);
    outFile.write(reinterpret_cast<char *>(iv), sizeof(iv));
    outFile.write(encrypted);

    outFile.close();

    return true;
}

bool CryptoManager::DecryptFile(const QString &filePath, const QString &password)
{
    QFile file(filePath);

    if (!file.open(QIODevice::ReadOnly))
        return false;

    QByteArray data = file.readAll();
    file.close();

    // Проверка: файл зашифрован?
    if (!data.startsWith(MAGIC))
        return false;

    QByteArray key = deriveKey(password);

    QByteArray iv = data.mid(MAGIC.size(), 16);
    QByteArray encrypted = data.mid(MAGIC.size() + 16);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (!ctx)
        return false;

    QByteArray decrypted(encrypted.size(), 0);

    int len = 0;
    int plaintext_len = 0;

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, reinterpret_cast<const unsigned char *>(key.data()),
                            reinterpret_cast<const unsigned char *>(iv.data())))
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (!EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char *>(decrypted.data()), &len,
                           reinterpret_cast<const unsigned char *>(encrypted.data()), encrypted.size()))
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    plaintext_len = len;

    if (!EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char *>(decrypted.data()) + len, &len))
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    decrypted.resize(plaintext_len);

    QFile outFile(filePath);

    if (!outFile.open(QIODevice::WriteOnly))
        return false;

    outFile.write(decrypted);

    outFile.close();

    return true;
}