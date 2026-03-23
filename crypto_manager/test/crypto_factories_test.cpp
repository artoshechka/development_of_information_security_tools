/// @file
/// @brief Тесты фабрик crypto_manager.
/// @author Artemenko Anton

#include <gtest/gtest.h>

#include <crypto_manager_factory.hpp>
#include <crypto_strategy_factory.hpp>
#include <test/test_utils.hpp>

namespace
{
class FakeCryptoStrategy final : public crypto_manager::ICryptoStrategy
{
   public:
    bool EncryptFile(const QString&, const QString&) override
    {
        return true;
    }

    bool DecryptFile(const QString&, const QString&) override
    {
        return true;
    }
};
}  // namespace

TEST(CryptoFactoriesTest, CreateCryptoManagerReturnsNullForNullStrategy)
{
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());

    const QString logPath = tempDir.path() + "/factories.log";
    auto logger = CreateTestLogger(logPath);

    auto manager = crypto_manager::CreateCryptoManager(nullptr, logger);

    EXPECT_EQ(manager, nullptr);
}

TEST(CryptoFactoriesTest, CreateCryptoManagerReturnsInstanceForValidStrategy)
{
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());

    const QString logPath = tempDir.path() + "/factories.log";
    auto logger = CreateTestLogger(logPath);

    auto manager = crypto_manager::CreateCryptoManager(std::make_unique<FakeCryptoStrategy>(), logger);

    ASSERT_NE(manager, nullptr);
    EXPECT_TRUE(manager->EncryptFile("a", "b"));
    EXPECT_TRUE(manager->DecryptFile("a", "b"));
}

TEST(CryptoFactoriesTest, CreateCryptoStrategyOpenSslReturnsInstance)
{
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());

    const QString logPath = tempDir.path() + "/factories.log";
    auto logger = CreateTestLogger(logPath);

    auto strategy = crypto_manager::CreateCryptoStrategy<crypto_manager::OpenSslTag>(logger);

    EXPECT_NE(strategy, nullptr);
}

TEST(CryptoFactoriesTest, GetCryptoManagerOpenSslReturnsInstance)
{
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());

    const QString logPath = tempDir.path() + "/factories.log";
    auto logger = CreateTestLogger(logPath);

    auto manager = crypto_manager::GetCryptoManager<crypto_manager::OpenSslTag>(logger);

    EXPECT_NE(manager, nullptr);
}
