/// @file
/// @brief Определение фабричных функций singleton-логгеров
/// @author Artemenko Anton

#include <app_logger.hpp>
#include <app_sys_logger.hpp>
#include <logger_factory.hpp>

namespace logger
{
namespace
{
template <typename TLoggerImpl>
std::shared_ptr<ILogger> CreateAndConfigureLogger(const QString& logPath)
{
    auto instance = std::make_shared<TLoggerImpl>();
    instance->SetSettings(LoggerSettings(logPath, LogLevel::Debug, LogOutput::Console));
    return instance;
}

std::shared_ptr<ILogger> CreateAppLogger()
{
    return CreateAndConfigureLogger<AppLogger>("logs/app.log");
}

std::shared_ptr<ILogger> CreateAppSysLogger()
{
    auto instance = std::make_shared<AppSysLogger>(LogOutput::File);
    instance->SetSettings(LoggerSettings(QString("logs/error.log"), LogLevel::Error, LogOutput::File));
    return std::shared_ptr<ILogger>(std::move(instance));
}
}  // namespace

template <>
std::shared_ptr<ILogger> GetLogger<AppLoggerTag>()
{
    static std::shared_ptr<ILogger> logger;
    if (logger == nullptr)
    {
        logger = CreateAppLogger();
    }

    return logger;
}

template <>
std::shared_ptr<ILogger> GetLogger<AppSysLoggerTag>()
{
    static std::shared_ptr<ILogger> logger;
    if (logger == nullptr)
    {
        logger = CreateAppSysLogger();
    }

    return logger;
}

}  // namespace logger
