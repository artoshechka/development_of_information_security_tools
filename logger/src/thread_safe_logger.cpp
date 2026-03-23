/// @file
/// @brief Реализация потокобезопасного базового логгера
/// @author Artemenko Anton

#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <iostream>
#include <thread_safe_logger.hpp>

using logger::LogLevel;
using logger::ThreadSafeLogger;

ThreadSafeLogger::ThreadSafeLogger(const QString& componentName, LogOutput output)
    : componentName_(componentName), settings_(QString(), LogLevel::Debug, output)
{
}

ThreadSafeLogger::~ThreadSafeLogger()
{
    if (logFile_.isOpen())
    {
        logFile_.close();
    }
}

void ThreadSafeLogger::SetSettings(const logger::LoggerSettings& settings)
{
    QMutexLocker locker(&syncMutex_);

    settings_ = settings;

    if (logFile_.isOpen())
    {
        logFile_.close();
    }
}

logger::LoggerSettings ThreadSafeLogger::GetSettings() const
{
    QMutexLocker locker(&syncMutex_);
    return settings_;
}

QString ThreadSafeLogger::LogLevelToString(LogLevel level)
{
    switch (level)
    {
        case LogLevel::Trace:
            return "TRACE";
        case LogLevel::Debug:
            return "DEBUG";
        case LogLevel::Info:
            return "INFO";
        case LogLevel::Warning:
            return "WARNING";
        case LogLevel::Error:
            return "ERROR";
        case LogLevel::Fatal:
            return "FATAL";
        default:
            return "UNKNOWN";
    }
}

void ThreadSafeLogger::Log(LogLevel level, const QString& message, const char* file, int line, const char* function)
{
    QMutexLocker locker(&syncMutex_);

    if (level < settings_.logLevel_)
    {
        return;
    }

    const QString logEntry = FormatMessage(level, message, file, line, function);

    if (settings_.output_ == LogOutput::Console)
    {
        std::cout << logEntry.toStdString() << std::endl;
    } else if (settings_.output_ == LogOutput::File)
    {
        if (!settings_.logFilePath_.has_value() || settings_.logFilePath_->isEmpty())
        {
            return;
        }

        const QString& logFilePath = settings_.logFilePath_.value();
        if (!logFile_.isOpen())
        {
            logFile_.setFileName(logFilePath);

            QDir dir(QFileInfo(logFilePath).absolutePath());
            if (!dir.exists())
            {
                dir.mkpath(".");
            }

            if (!logFile_.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text))
            {
                return;
            }

            textStream_.setDevice(&logFile_);
            textStream_.setCodec("UTF-8");
        }

        textStream_ << logEntry << Qt::endl;
        textStream_.flush();
    }
}