/// @file
/// @brief Тесты класса LogEntryStream.
/// @author Artemenko Anton

#include <gtest/gtest.h>

#include <QTemporaryDir>
#include <app_logger.hpp>
#include <logger_macros.hpp>
#include <src/log_entry_stream.hpp>
#include <test/test_utils.hpp>

TEST(LogEntryStreamTest, FlushesMessageOnDestruction)
{
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());

    const QString logPath = tempDir.path() + "/stream.log";

    auto logger = std::make_shared<logger::AppLogger>(logger::LogOutput::File);
    logger->SetSettings(logger::LoggerSettings(logPath, logger::LogLevel::Trace, logger::LogOutput::File));

    LogWarning(logger) << "part_1 " << 123 << " part_2";

    const QString content = ReadAllText(logPath);
    EXPECT_TRUE(content.contains("[WARNING]"));
    EXPECT_TRUE(content.contains("part_1 123 part_2"));
    EXPECT_TRUE(content.contains("log_entry_stream_test.cpp"));
}

TEST(LogEntryStreamTest, DoesNothingForNullLogger)
{
    logger::detail::LogEntryStream stream(nullptr, logger::LogLevel::Info, "test.cpp", 1, "f");
    stream << "message";
}
