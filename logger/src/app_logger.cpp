/// @file
/// @brief Определение логгера приложения
/// @author Artemenko Anton

#include <QDateTime>
#include <QFileInfo>
#include <app_logger.hpp>

using logger::AppLogger;
using logger::LogLevel;

AppLogger::AppLogger(LogOutput output) : ThreadSafeLogger("APP", output)
{
}

AppLogger::~AppLogger() = default;

QString AppLogger::FormatMessage(LogLevel level, const QString& message, const char* file, int line,
                                 const char* function) const
{
    QString timestamp = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss.zzz");
    QString logLevel = ThreadSafeLogger::LogLevelToString(level);

    QString fileInfo;
    if (file != nullptr)
    {
        QFileInfo fi(file);
        fileInfo = QString("%1:%2").arg(fi.fileName()).arg(line);
    }

    QString functionInfo;
    if (function != nullptr)
    {
        functionInfo = QString::fromUtf8(function);
    }

    return QString("[%1] [%2] [%3] %4 - %5 - %6")
        .arg(timestamp)
        .arg(componentName_)
        .arg(logLevel)
        .arg(fileInfo)
        .arg(functionInfo)
        .arg(message);
}
