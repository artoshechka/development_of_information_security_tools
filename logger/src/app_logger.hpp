/// @file
/// @brief Объявление логгера приложения
/// @author Artemenko Anton
#ifndef GUID_14f30de6_d704_49d2_a2d5_649fb7c41a3b
#define GUID_14f30de6_d704_49d2_a2d5_649fb7c41a3b

#include <thread_safe_logger.hpp>

namespace logger
{
/// @brief Логгер приложения
class AppLogger final : public ThreadSafeLogger
{
  public:
    /// @brief Конструктор логгера приложения
    /// @param[in] output Режим вывода логов (по умолчанию консоль)
    explicit AppLogger(LogOutput output = LogOutput::Console);

    /// @brief Деструктор логгера приложения
    ~AppLogger() override;

  private:
    /// @brief Сформировать сообщение для записи
    /// @param[in] level Уровень логирования
    /// @param[in] message Текст сообщения
    /// @param[in] file Имя файла
    /// @param[in] line Номер строки
    /// @param[in] function Имя функции
    /// @return Отформатированное сообщение
    QString FormatMessage(LogLevel level, const QString &message, const char *file, int line,
                          const char *function) const override;
};

} // namespace logger

#endif // GUID_14f30de6_d704_49d2_a2d5_649fb7c41a3b
