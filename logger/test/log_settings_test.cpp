/// @file
/// @brief Тесты структуры LoggerSettings.
/// @author Artemenko Anton

#include <gtest/gtest.h>

#include <log_settings.hpp>

TEST(LogSettingsTest, StoresProvidedValues)
{
    const logger::LoggerSettings settings(QString("/tmp/a.log"), logger::LogLevel::Warning, logger::LogOutput::File);

    ASSERT_TRUE(settings.logFilePath_.has_value());
    EXPECT_EQ(settings.logFilePath_.value(), QString("/tmp/a.log"));
    EXPECT_EQ(settings.logLevel_, logger::LogLevel::Warning);
    EXPECT_EQ(settings.output_, logger::LogOutput::File);
}

TEST(LogSettingsTest, UsesDefaultValues)
{
    const logger::LoggerSettings settings;

    EXPECT_FALSE(settings.logFilePath_.has_value());
    EXPECT_EQ(settings.logLevel_, logger::LogLevel::Debug);
    EXPECT_EQ(settings.output_, logger::LogOutput::Console);
}
