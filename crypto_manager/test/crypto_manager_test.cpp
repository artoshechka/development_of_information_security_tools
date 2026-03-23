/// @file
/// @brief Тесты класса CryptoManager.
/// @author Artemenko Anton

#include <gtest/gtest.h>

#include <src/crypto_manager.hpp>
#include <test/test_utils.hpp>

namespace
{
class FakeCryptoStrategy final : public crypto_manager::ICryptoStrategy
{
   public:
    FakeCryptoStrategy(bool encryptResult, bool decryptResult)
        : encryptResult_(encryptResult), decryptResult_(decryptResult), encryptCalls_(0), decryptCalls_(0)
    {
    }

    bool EncryptFile(const QString& filePath, const QString& password) override
    {
        lastEncryptFilePath_ = filePath;
        lastEncryptPassword_ = password;
        ++encryptCalls_;
        return encryptResult_;
    }

    bool DecryptFile(const QString& filePath, const QString& password) override
    {
        lastDecryptFilePath_ = filePath;
        lastDecryptPassword_ = password;
        ++decryptCalls_;
        return decryptResult_;
    }

    bool encryptResult_;
    bool decryptResult_;
    int encryptCalls_;
    int decryptCalls_;
    QString lastEncryptFilePath_;
    QString lastEncryptPassword_;
    QString lastDecryptFilePath_;
    QString lastDecryptPassword_;
};
}  // namespace

TEST(CryptoManagerTest, EncryptDelegatesToStrategy)
{
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());

    const QString logPath = tempDir.path() + "/crypto_manager.log";
    auto logger = CreateTestLogger(logPath);

    auto strategy = std::make_unique<FakeCryptoStrategy>(true, false);
    auto* strategyRaw = strategy.get();

    crypto_manager::CryptoManager manager(std::move(strategy), logger);

    const bool result = manager.EncryptFile("/tmp/file.bin", "pwd");

    EXPECT_TRUE(result);
    EXPECT_EQ(strategyRaw->encryptCalls_, 1);
    EXPECT_EQ(strategyRaw->lastEncryptFilePath_, QString("/tmp/file.bin"));
    EXPECT_EQ(strategyRaw->lastEncryptPassword_, QString("pwd"));
}

TEST(CryptoManagerTest, EncryptReportsFailure)
{
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());

    const QString logPath = tempDir.path() + "/crypto_manager.log";
    auto logger = CreateTestLogger(logPath);

    auto strategy = std::make_unique<FakeCryptoStrategy>(false, true);
    auto* strategyRaw = strategy.get();

    crypto_manager::CryptoManager manager(std::move(strategy), logger);

    const bool result = manager.EncryptFile("/tmp/file.bin", "pwd");

    EXPECT_FALSE(result);
    EXPECT_EQ(strategyRaw->encryptCalls_, 1);
}

TEST(CryptoManagerTest, DecryptDelegatesToStrategyAndReportsFailure)
{
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());

    const QString logPath = tempDir.path() + "/crypto_manager.log";
    auto logger = CreateTestLogger(logPath);

    auto strategy = std::make_unique<FakeCryptoStrategy>(true, false);
    auto* strategyRaw = strategy.get();

    crypto_manager::CryptoManager manager(std::move(strategy), logger);

    const bool result = manager.DecryptFile("/tmp/file.enc", "badpwd");

    EXPECT_FALSE(result);
    EXPECT_EQ(strategyRaw->decryptCalls_, 1);
    EXPECT_EQ(strategyRaw->lastDecryptFilePath_, QString("/tmp/file.enc"));
    EXPECT_EQ(strategyRaw->lastDecryptPassword_, QString("badpwd"));
}
