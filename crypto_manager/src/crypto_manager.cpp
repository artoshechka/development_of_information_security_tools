/// @file
/// @brief Определение менеджера криптографических операций (Singleton).
/// @author Artemenko Anton

#include <src/crypto_manager.hpp>

#include <QByteArray>
#include <QCryptographicHash>
#include <QDebug>
#include <QFile>

namespace
{
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
    static CryptoManager Instance;
    return Instance;
}

bool CryptoManager::EncryptFile(const QString &filePath, const QString &password)
{
    QFile file(filePath);

    if (!file.open(QIODevice::ReadOnly))
        return false;

    QByteArray data = file.readAll();
    file.close();

    QByteArray key = deriveKey(password);

    QByteArray encrypted = data; // временно (заглушка)

    QString newFilePath = filePath + ".enc";
    QFile outFile(newFilePath);

    if (!outFile.open(QIODevice::WriteOnly))
        return false;

    outFile.write(encrypted);
    outFile.close();

    return true;
}

bool CryptoManager::DecryptFile(const QString &filePath, const QString &password)
{
    QFile file(filePath);

    if (!file.open(QIODevice::ReadOnly))
        return false;

    QByteArray encrypted = file.readAll();
    file.close();

    QByteArray key = deriveKey(password);

    QByteArray decrypted = encrypted; // временно (заглушка)

    QString newFilePath = filePath;
    newFilePath.chop(4); // удалить ".enc"

    QFile outFile(newFilePath);

    if (!outFile.open(QIODevice::WriteOnly))
        return false;

    outFile.write(decrypted);
    outFile.close();

    return true;
}