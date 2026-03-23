/// @file
/// @brief Фабричные функции для singleton-логгеров
/// @author Artemenko Anton
#ifndef GUID_32ddf2a4_eb2e_4d0f_b5b2_6f6b683f7ae0
#define GUID_32ddf2a4_eb2e_4d0f_b5b2_6f6b683f7ae0

#include <ilogger.hpp>
#include <log_settings.hpp>
#include <memory>

namespace logger
{
/// @brief Fwd decl тега логгера приложения для фабрики
struct AppLoggerTag;

/// @brief Fwd decl тега системного логгера приложения для фабрики
struct AppSysLoggerTag;

/// @brief Получить singleton-логгер по типу тега
/// @tparam TLoggerTag Тип тега логгера
/// @return Умный указатель на логгер
template <typename TLoggerTag>
std::shared_ptr<ILogger> GetLogger();

/// @brief Специализация фабрики для логгера приложения
template <>
std::shared_ptr<ILogger> GetLogger<AppLoggerTag>();

/// @brief Специализация фабрики для системного логгера приложения
template <>
std::shared_ptr<ILogger> GetLogger<AppSysLoggerTag>();

}  // namespace logger

#endif  // GUID_32ddf2a4_eb2e_4d0f_b5b2_6f6b683f7ae0
