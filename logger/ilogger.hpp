/// @file
/// @brief Объявление интерфейса логгера
/// @author Artemenko Anton
#ifndef GUID_76731180_6258_4b6b_b2a7_4ef2b0039d4d
#define GUID_76731180_6258_4b6b_b2a7_4ef2b0039d4d

#include <log_levels.hpp>
#include <log_settings.hpp>

#include <QString>

namespace logger
{
/// @brief Интерфейс логгера
class ILogger
{
  public:
    /// @brief Виртуальный деструктор интерфейса
    virtual ~ILogger() = default;

    /// @brief Установить все настройки логгера одним вызовом
    /// @param[in] settings Набор настроек логгера
    virtual void SetSettings(const LoggerSettings &settings) = 0;

    /// @brief Получить текущие настройки логгера
    /// @return Текущие настройки
    virtual LoggerSettings GetSettings() const = 0;

    /// @brief Записать сообщение в лог
    /// @param[in] level Уровень логирования
    /// @param[in] message Текст сообщения
    /// @param[in] file Имя файла
    /// @param[in] line Номер строки
    /// @param[in] function Имя функции
    virtual void Log(LogLevel level, const QString &message, const char *file = nullptr, int line = 0,
                     const char *function = nullptr) = 0;
};

} // namespace logger

#endif // GUID_76731180_6258_4b6b_b2a7_4ef2b0039d4d
