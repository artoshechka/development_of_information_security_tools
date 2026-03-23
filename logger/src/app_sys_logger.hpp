/// @file
/// @brief Объявление системного логгера приложения
/// @author Artemenko Anton
#ifndef GUID_77e191a9_8f61_44f4_a864_4f88b7e81fd6
#define GUID_77e191a9_8f61_44f4_a864_4f88b7e81fd6

#include <thread_safe_logger.hpp>

namespace logger
{
/// @brief Системный логгер внутренних подсистем приложения
class AppSysLogger final : public ThreadSafeLogger
{
   public:
    /// @brief Конструктор системного логгера
    /// @param[in] output Режим вывода логов
    explicit AppSysLogger(LogOutput output = LogOutput::File);

    /// @brief Деструктор системного логгера
    ~AppSysLogger() override;

   private:
    /// @brief Сформировать строку сообщения лога
    /// @param[in] level Уровень логирования
    /// @param[in] message Текст сообщения
    /// @param[in] file Имя файла
    /// @param[in] line Номер строки
    /// @param[in] function Имя функции
    /// @return Отформатированное сообщение
    QString FormatMessage(LogLevel level, const QString& message, const char* file, int line,
                          const char* function) const override;
};

}  // namespace logger

#endif  // GUID_77e191a9_8f61_44f4_a864_4f88b7e81fd6