/// @file
/// @brief Вспомогательные функции для тестов crypto_manager.
/// @author Artemenko Anton

#ifndef CRYPTO_MANAGER_TEST_TEST_UTILS_HPP
#define CRYPTO_MANAGER_TEST_TEST_UTILS_HPP

#include <gtest/gtest.h>

#include <QFile>
#include <QTemporaryDir>
#include <app_logger.hpp>
#include <memory>

inline QString ReadAllText(const QString& filePath)
{
    QFile file(filePath);
    EXPECT_TRUE(file.open(QIODevice::ReadOnly | QIODevice::Text));
    return QString::fromUtf8(file.readAll());
}

inline void WriteAllText(const QString& filePath, const QByteArray& content)
{
    QFile file(filePath);
    EXPECT_TRUE(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
    EXPECT_EQ(file.write(content), content.size());
}

inline std::shared_ptr<logger::ILogger> CreateTestLogger(const QString& logPath)
{
    auto logger = std::make_shared<logger::AppLogger>(logger::LogOutput::File);
    logger->SetSettings(logger::LoggerSettings(logPath, logger::LogLevel::Trace, logger::LogOutput::File));
    return logger;
}

#endif  // CRYPTO_MANAGER_TEST_TEST_UTILS_HPP
