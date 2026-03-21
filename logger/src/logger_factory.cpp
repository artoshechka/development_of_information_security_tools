/// @file
/// @brief Определение фабричных функций singleton-логгеров
/// @author Artemenko Anton

#include <logger_factory.hpp>

#include <app_logger.hpp>
#include <app_sys_logger.hpp>

namespace logger
{
namespace
{
template <typename TLoggerImpl> std::shared_ptr<ILogger> CreateAndConfigureLogger(const QString &logPath)
{
    auto instance = std::make_shared<TLoggerImpl>();
    instance->SetSettings(LoggerSettings(logPath, LogLevel::Debug, LogOutput::Console));
    return instance;
}
} // namespace

template <> std::shared_ptr<ILogger> GetLogger<AppLoggerTag>()
{
    static std::shared_ptr<ILogger> logger = [] {
        return CreateAndConfigureLogger<AppLogger>("logs/app.log");
    }();

    return logger;
}

template <> std::shared_ptr<ILogger> GetLogger<AppSysLoggerTag>()
{
    static std::shared_ptr<ILogger> logger = [] {
        auto instance = std::make_shared<AppSysLogger>(LogOutput::File);
        instance->SetSettings(LoggerSettings(QString("logs/error.log"), LogLevel::Error, LogOutput::File));
        return std::shared_ptr<ILogger>(std::move(instance));
    }();

    return logger;
}

} // namespace logger
