/// @file
/// @brief Тесты класса AppSysLogger.
/// @author Artemenko Anton

#include <gtest/gtest.h>

#include <QTemporaryDir>
#include <app_sys_logger.hpp>
#include <test/test_utils.hpp>

TEST(AppSysLoggerTest, RespectsMinimalLogLevel)
{
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());

    const QString logPath = tempDir.path() + "/sys.log";

    logger::AppSysLogger logger(logger::LogOutput::File);
    logger.SetSettings(logger::LoggerSettings(logPath, logger::LogLevel::Error, logger::LogOutput::File));

    logger.Log(logger::LogLevel::Info, "skip me", "a.cpp", 10, "A");
    logger.Log(logger::LogLevel::Error, "keep me", "b.cpp", 11, "B");

    const QString content = ReadAllText(logPath);
    EXPECT_TRUE(content.contains("[APP-SYS]"));
    EXPECT_TRUE(content.contains("[ERROR]"));
    EXPECT_TRUE(content.contains("keep me"));
    EXPECT_FALSE(content.contains("skip me"));
}

TEST(AppSysLoggerTest, WritesMessageWhenSourceInfoIsMissing)
{
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());

    const QString logPath = tempDir.path() + "/sys-no-src.log";

    logger::AppSysLogger logger(logger::LogOutput::File);
    logger.SetSettings(logger::LoggerSettings(logPath, logger::LogLevel::Trace, logger::LogOutput::File));

    logger.Log(logger::LogLevel::Trace, "no source", nullptr, 0, nullptr);

    const QString content = ReadAllText(logPath);
    EXPECT_TRUE(content.contains("[APP-SYS]"));
    EXPECT_TRUE(content.contains("[TRACE]"));
    EXPECT_TRUE(content.contains("no source"));
}
