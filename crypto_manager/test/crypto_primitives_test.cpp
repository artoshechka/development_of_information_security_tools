/// @file
/// @brief Тесты криптографических примитивов.
/// @author Artemenko Anton

#include <gtest/gtest.h>

#include <src/crypto_primitives.hpp>

using namespace crypto_manager::crypto_primitives;

TEST(CryptoPrimitivesTest, SecureClearClearsNonEmptyBuffer)
{
    QByteArray data("secret-data");
    ASSERT_FALSE(data.isEmpty());

    SecureClear(data);

    EXPECT_TRUE(data.isEmpty());
}

TEST(CryptoPrimitivesTest, SecureClearAcceptsEmptyBuffer)
{
    QByteArray data;

    SecureClear(data);

    EXPECT_TRUE(data.isEmpty());
}

TEST(CryptoPrimitivesTest, DeriveEncryptionKeyIsDeterministic)
{
    const QString password = "p@ssw0rd";
    const QByteArray salt("0123456789ABCDEF", kPasswordSaltSize);

    QByteArray keyA;
    QByteArray keyB;

    ASSERT_TRUE(DeriveEncryptionKey(password, salt, keyA));
    ASSERT_TRUE(DeriveEncryptionKey(password, salt, keyB));

    EXPECT_EQ(keyA.size(), kAesKeySize);
    EXPECT_EQ(keyB.size(), kAesKeySize);
    EXPECT_EQ(keyA, keyB);
}

TEST(CryptoPrimitivesTest, DeriveEncryptionKeyDependsOnSalt)
{
    const QString password = "p@ssw0rd";
    const QByteArray saltA("0123456789ABCDEF", kPasswordSaltSize);
    const QByteArray saltB("FEDCBA9876543210", kPasswordSaltSize);

    QByteArray keyA;
    QByteArray keyB;

    ASSERT_TRUE(DeriveEncryptionKey(password, saltA, keyA));
    ASSERT_TRUE(DeriveEncryptionKey(password, saltB, keyB));

    EXPECT_NE(keyA, keyB);
}
