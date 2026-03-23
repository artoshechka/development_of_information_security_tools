/// @file
/// @brief Тесты класса AppLogger.
/// @author Artemenko Anton

#include <gtest/gtest.h>

#include <QTemporaryDir>
#include <app_logger.hpp>
#include <test/test_utils.hpp>

TEST(AppLoggerTest, WritesFormattedMessageWithSourceInfo)
{
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());

    const QString logPath = tempDir.path() + "/app.log";

    logger::AppLogger logger(logger::LogOutput::File);
    logger.SetSettings(logger::LoggerSettings(logPath, logger::LogLevel::Debug, logger::LogOutput::File));

    logger.Log(logger::LogLevel::Info, "hello", "input.cpp", 42, "DoWork");

    const QString content = ReadAllText(logPath);
    EXPECT_TRUE(content.contains("[APP]"));
    EXPECT_TRUE(content.contains("[INFO]"));
    EXPECT_TRUE(content.contains("input.cpp:42"));
    EXPECT_TRUE(content.contains("DoWork"));
    EXPECT_TRUE(content.contains("hello"));
}

TEST(AppLoggerTest, WritesMessageWhenSourceInfoIsMissing)
{
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());

    const QString logPath = tempDir.path() + "/app-no-src.log";

    logger::AppLogger logger(logger::LogOutput::File);
    logger.SetSettings(logger::LoggerSettings(logPath, logger::LogLevel::Trace, logger::LogOutput::File));

    logger.Log(logger::LogLevel::Trace, "no source", nullptr, 0, nullptr);

    const QString content = ReadAllText(logPath);
    EXPECT_TRUE(content.contains("[APP]"));
    EXPECT_TRUE(content.contains("[TRACE]"));
    EXPECT_TRUE(content.contains("no source"));
}
