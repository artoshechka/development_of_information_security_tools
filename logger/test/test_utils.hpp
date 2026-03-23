/// @file
/// @brief Вспомогательные функции для тестов logger.
/// @author Artemenko Anton

#ifndef LOGGER_TEST_TEST_UTILS_HPP
#define LOGGER_TEST_TEST_UTILS_HPP

#include <gtest/gtest.h>

#include <QFile>
#include <QString>

inline QString ReadAllText(const QString& filePath)
{
    QFile file(filePath);
    EXPECT_TRUE(file.open(QIODevice::ReadOnly | QIODevice::Text));
    return QString::fromUtf8(file.readAll());
}

#endif  // LOGGER_TEST_TEST_UTILS_HPP
