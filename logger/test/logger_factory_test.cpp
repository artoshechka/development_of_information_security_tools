/// @file
/// @brief Тесты фабрики logger::GetLogger.
/// @author Artemenko Anton

#include <gtest/gtest.h>

#include <logger_factory.hpp>

TEST(LoggerFactoryTest, ReturnsSingletonInstances)
{
    auto appA = logger::GetLogger<logger::AppLoggerTag>();
    auto appB = logger::GetLogger<logger::AppLoggerTag>();

    auto sysA = logger::GetLogger<logger::AppSysLoggerTag>();
    auto sysB = logger::GetLogger<logger::AppSysLoggerTag>();

    EXPECT_EQ(appA.get(), appB.get());
    EXPECT_EQ(sysA.get(), sysB.get());
    EXPECT_NE(appA.get(), sysA.get());
}

TEST(LoggerFactoryTest, ConfiguresDefaultSettings)
{
    auto app = logger::GetLogger<logger::AppLoggerTag>();
    const logger::LoggerSettings appSettings = app->GetSettings();

    ASSERT_TRUE(appSettings.logFilePath_.has_value());
    EXPECT_EQ(appSettings.logFilePath_.value(), QString("logs/app.log"));
    EXPECT_EQ(appSettings.logLevel_, logger::LogLevel::Debug);
    EXPECT_EQ(appSettings.output_, logger::LogOutput::Console);

    auto sys = logger::GetLogger<logger::AppSysLoggerTag>();
    const logger::LoggerSettings sysSettings = sys->GetSettings();

    ASSERT_TRUE(sysSettings.logFilePath_.has_value());
    EXPECT_EQ(sysSettings.logFilePath_.value(), QString("logs/error.log"));
    EXPECT_EQ(sysSettings.logLevel_, logger::LogLevel::Error);
    EXPECT_EQ(sysSettings.output_, logger::LogOutput::File);
}
