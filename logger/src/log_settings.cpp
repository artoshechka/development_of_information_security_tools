/// @file
/// @brief Реализация настроек логгера
/// @author Artemenko Anton

#include <log_settings.hpp>

#include <optional>

namespace logger
{

LoggerSettings::LoggerSettings(const std::optional<QString> &logFilePath, LogLevel logLevel, LogOutput output)
    : logFilePath_(logFilePath), logLevel_(logLevel), output_(output)
{
}

} // namespace logger
