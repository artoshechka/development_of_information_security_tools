/// @file
/// @brief Тесты класса ThreadSafeLogger.
/// @author Artemenko Anton

#include <gtest/gtest.h>

#include <QDir>
#include <QFileInfo>
#include <QTemporaryDir>
#include <app_logger.hpp>
#include <test/test_utils.hpp>

TEST(ThreadSafeLoggerTest, SkipsMessagesBelowThreshold)
{
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());

    const QString logPath = tempDir.path() + "/level.log";

    logger::AppLogger logger(logger::LogOutput::File);
    logger.SetSettings(logger::LoggerSettings(logPath, logger::LogLevel::Error, logger::LogOutput::File));

    logger.Log(logger::LogLevel::Info, "ignored", "a.cpp", 1, "A");
    logger.Log(logger::LogLevel::Fatal, "written", "b.cpp", 2, "B");

    const QString content = ReadAllText(logPath);
    EXPECT_FALSE(content.contains("ignored"));
    EXPECT_TRUE(content.contains("written"));
}

TEST(ThreadSafeLoggerTest, CreatesParentDirectoryForLogFile)
{
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());

    const QString nestedDir = tempDir.path() + "/a/b/c";
    const QString logPath = nestedDir + "/created.log";

    logger::AppLogger logger(logger::LogOutput::File);
    logger.SetSettings(logger::LoggerSettings(logPath, logger::LogLevel::Trace, logger::LogOutput::File));
    logger.Log(logger::LogLevel::Info, "mkdir", "x.cpp", 3, "X");

    EXPECT_TRUE(QFileInfo::exists(logPath));
    const QString content = ReadAllText(logPath);
    EXPECT_TRUE(content.contains("mkdir"));
}

TEST(ThreadSafeLoggerTest, ReturnsWhenFilePathIsEmpty)
{
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());

    logger::AppLogger logger(logger::LogOutput::File);
    logger.SetSettings(logger::LoggerSettings(QString(), logger::LogLevel::Trace, logger::LogOutput::File));
    logger.Log(logger::LogLevel::Info, "ignored", "x.cpp", 3, "X");

    QDir dir(tempDir.path());
    EXPECT_TRUE(dir.entryList(QDir::Files).isEmpty());
}

TEST(ThreadSafeLoggerTest, ReturnsWhenFileCannotBeOpened)
{
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());

    logger::AppLogger logger(logger::LogOutput::File);
    logger.SetSettings(logger::LoggerSettings(tempDir.path(), logger::LogLevel::Trace, logger::LogOutput::File));
    logger.Log(logger::LogLevel::Info, "cannot-open-dir", "x.cpp", 3, "X");

    EXPECT_TRUE(QFileInfo(tempDir.path()).isDir());
}

TEST(ThreadSafeLoggerTest, SetSettingsSwitchesOutputFile)
{
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());

    const QString firstPath = tempDir.path() + "/first.log";
    const QString secondPath = tempDir.path() + "/second.log";

    logger::AppLogger logger(logger::LogOutput::File);
    logger.SetSettings(logger::LoggerSettings(firstPath, logger::LogLevel::Trace, logger::LogOutput::File));
    logger.Log(logger::LogLevel::Info, "first", "a.cpp", 1, "A");

    logger.SetSettings(logger::LoggerSettings(secondPath, logger::LogLevel::Trace, logger::LogOutput::File));
    logger.Log(logger::LogLevel::Info, "second", "b.cpp", 2, "B");

    const QString firstContent = ReadAllText(firstPath);
    const QString secondContent = ReadAllText(secondPath);

    EXPECT_TRUE(firstContent.contains("first"));
    EXPECT_FALSE(firstContent.contains("second"));
    EXPECT_TRUE(secondContent.contains("second"));
}

TEST(ThreadSafeLoggerTest, UsesUnknownLevelForUnexpectedEnumValue)
{
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());

    const QString logPath = tempDir.path() + "/unknown.log";

    logger::AppLogger logger(logger::LogOutput::File);
    logger.SetSettings(logger::LoggerSettings(logPath, logger::LogLevel::Trace, logger::LogOutput::File));

    const auto unknownLevel = static_cast<logger::LogLevel>(999);
    logger.Log(unknownLevel, "unknown-level", "u.cpp", 9, "U");

    const QString content = ReadAllText(logPath);
    EXPECT_TRUE(content.contains("[UNKNOWN]"));
}

TEST(ThreadSafeLoggerTest, WritesToConsoleForConsoleOutput)
{
    logger::AppLogger logger(logger::LogOutput::Console);
    logger.SetSettings(logger::LoggerSettings(std::nullopt, logger::LogLevel::Trace, logger::LogOutput::Console));

    testing::internal::CaptureStdout();
    logger.Log(logger::LogLevel::Debug, "console-debug", "c.cpp", 12, "C");
    const std::string output = testing::internal::GetCapturedStdout();

    EXPECT_NE(output.find("[DEBUG]"), std::string::npos);
    EXPECT_NE(output.find("console-debug"), std::string::npos);
}
