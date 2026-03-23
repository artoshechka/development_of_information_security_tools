/// @file
/// @brief Тесты OpenSSL-стратегии шифрования/дешифрования.
/// @author Artemenko Anton

#include <gtest/gtest.h>

#include <QTemporaryDir>
#include <src/crypto_primitives.hpp>
#include <src/openssl_crypto_strategy.hpp>
#include <test/test_utils.hpp>

TEST(OpenSslCryptoStrategyTest, EncryptDecryptRoundTrip)
{
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());

    const QString logPath = tempDir.path() + "/openssl.log";
    auto logger = CreateTestLogger(logPath);

    const QString filePath = tempDir.path() + "/payload.txt";
    const QByteArray source = "sensitive payload 123";
    WriteAllText(filePath, source);

    crypto_manager::OpenSslCryptoStrategy strategy(logger);

    ASSERT_TRUE(strategy.EncryptFile(filePath, "pwd"));

    const QString encryptedText = ReadAllText(filePath);
    EXPECT_FALSE(encryptedText.contains(QString::fromUtf8(source)));

    ASSERT_TRUE(strategy.DecryptFile(filePath, "pwd"));
    EXPECT_EQ(ReadAllText(filePath).toUtf8(), source);
}

TEST(OpenSslCryptoStrategyTest, EncryptRejectsAlreadyEncryptedFile)
{
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());

    const QString logPath = tempDir.path() + "/openssl.log";
    auto logger = CreateTestLogger(logPath);

    const QString filePath = tempDir.path() + "/payload.bin";
    WriteAllText(filePath, QByteArray("hello"));

    crypto_manager::OpenSslCryptoStrategy strategy(logger);

    ASSERT_TRUE(strategy.EncryptFile(filePath, "pwd"));
    EXPECT_FALSE(strategy.EncryptFile(filePath, "pwd"));
}

TEST(OpenSslCryptoStrategyTest, DecryptRejectsPlainFile)
{
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());

    const QString logPath = tempDir.path() + "/openssl.log";
    auto logger = CreateTestLogger(logPath);

    const QString filePath = tempDir.path() + "/plain.txt";
    WriteAllText(filePath, QByteArray("not encrypted"));

    crypto_manager::OpenSslCryptoStrategy strategy(logger);

    EXPECT_FALSE(strategy.DecryptFile(filePath, "pwd"));
}

TEST(OpenSslCryptoStrategyTest, DecryptFailsWithWrongPassword)
{
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());

    const QString logPath = tempDir.path() + "/openssl.log";
    auto logger = CreateTestLogger(logPath);

    const QString filePath = tempDir.path() + "/secret.txt";
    WriteAllText(filePath, QByteArray("secret"));

    crypto_manager::OpenSslCryptoStrategy strategy(logger);

    ASSERT_TRUE(strategy.EncryptFile(filePath, "correct"));
    EXPECT_FALSE(strategy.DecryptFile(filePath, "wrong"));
}

TEST(OpenSslCryptoStrategyTest, EncryptFailsForMissingInputFile)
{
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());

    const QString logPath = tempDir.path() + "/openssl.log";
    auto logger = CreateTestLogger(logPath);

    crypto_manager::OpenSslCryptoStrategy strategy(logger);

    EXPECT_FALSE(strategy.EncryptFile(tempDir.path() + "/missing.bin", "pwd"));
}

TEST(OpenSslCryptoStrategyTest, DecryptFailsForMissingInputFile)
{
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());

    const QString logPath = tempDir.path() + "/openssl.log";
    auto logger = CreateTestLogger(logPath);

    crypto_manager::OpenSslCryptoStrategy strategy(logger);

    EXPECT_FALSE(strategy.DecryptFile(tempDir.path() + "/missing.enc", "pwd"));
}

TEST(OpenSslCryptoStrategyTest, DecryptFailsForInvalidSaltSize)
{
    using namespace crypto_manager::crypto_primitives;

    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());

    const QString logPath = tempDir.path() + "/openssl.log";
    auto logger = CreateTestLogger(logPath);

    const QString filePath = tempDir.path() + "/broken_salt.bin";
    WriteAllText(filePath, kFileMagicSignature + QByteArray("short"));

    crypto_manager::OpenSslCryptoStrategy strategy(logger);

    EXPECT_FALSE(strategy.DecryptFile(filePath, "pwd"));
}

TEST(OpenSslCryptoStrategyTest, DecryptFailsForInvalidNonceSize)
{
    using namespace crypto_manager::crypto_primitives;

    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());

    const QString logPath = tempDir.path() + "/openssl.log";
    auto logger = CreateTestLogger(logPath);

    const QString filePath = tempDir.path() + "/broken_nonce.bin";
    QByteArray content = kFileMagicSignature;
    content.append(QByteArray(kPasswordSaltSize, 'S'));
    content.append(QByteArray("short_nonce"));
    WriteAllText(filePath, content);

    crypto_manager::OpenSslCryptoStrategy strategy(logger);

    EXPECT_FALSE(strategy.DecryptFile(filePath, "pwd"));
}

TEST(OpenSslCryptoStrategyTest, DecryptFailsForTooSmallEncryptedFile)
{
    using namespace crypto_manager::crypto_primitives;

    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());

    const QString logPath = tempDir.path() + "/openssl.log";
    auto logger = CreateTestLogger(logPath);

    const QString filePath = tempDir.path() + "/too_small.bin";
    QByteArray content = kFileMagicSignature;
    content.append(QByteArray(kPasswordSaltSize, 'S'));
    content.append(QByteArray(kAesGcmNonceSize, 'N'));
    WriteAllText(filePath, content);

    crypto_manager::OpenSslCryptoStrategy strategy(logger);

    EXPECT_FALSE(strategy.DecryptFile(filePath, "pwd"));
}

TEST(OpenSslCryptoStrategyTest, DecryptFailsForTruncatedAuthTag)
{
    using namespace crypto_manager::crypto_primitives;

    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());

    const QString logPath = tempDir.path() + "/openssl.log";
    auto logger = CreateTestLogger(logPath);

    const QString filePath = tempDir.path() + "/truncated_tag.bin";
    WriteAllText(filePath, QByteArray("secret"));

    crypto_manager::OpenSslCryptoStrategy strategy(logger);
    ASSERT_TRUE(strategy.EncryptFile(filePath, "pwd"));

    QFile file(filePath);
    ASSERT_TRUE(file.open(QIODevice::ReadOnly));
    QByteArray encrypted = file.readAll();
    file.close();

    ASSERT_GT(encrypted.size(), static_cast<int>(kAesGcmTagSize));
    encrypted.chop(kAesGcmTagSize - 1);
    WriteAllText(filePath, encrypted);

    EXPECT_FALSE(strategy.DecryptFile(filePath, "pwd"));
}
