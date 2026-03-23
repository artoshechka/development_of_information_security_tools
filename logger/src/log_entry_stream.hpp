/// @file
/// @brief Объявление потокового helper'а для макросов логирования
/// @author Artemenko Anton
#ifndef GUID_8b9db8a0_64a9_4a28_a8e2_ef99f9a87516
#define GUID_8b9db8a0_64a9_4a28_a8e2_ef99f9a87516

#include <QString>
#include <QTextStream>
#include <ilogger.hpp>
#include <memory>

namespace logger
{
namespace detail
{
/// @brief Вспомогательный потоковый объект для макросов вида LogDebug(ptr) << "message"
class LogEntryStream final
{
   public:
    /// @brief Конструктор потокового сообщения
    /// @param[in] logger Умный указатель на целевой логгер
    /// @param[in] level Уровень логирования
    /// @param[in] file Имя файла
    /// @param[in] line Номер строки
    /// @param[in] function Имя функции
    LogEntryStream(std::shared_ptr<ILogger> logger, LogLevel level, const char* file, int line, const char* function);

    /// @brief Деструктор, автоматически отправляет собранное сообщение в логгер
    ~LogEntryStream();

    template <typename T>
    LogEntryStream& operator<<(const T& value)
    {
        stream_ << value;
        return *this;
    }

   private:
    std::shared_ptr<ILogger> logger_;  ///< Умный указатель на целевой логгер
    LogLevel level_;                   ///< Уровень логирования сообщения
    const char* file_;                 ///< Имя файла источника
    int line_;                         ///< Номер строки источника
    const char* function_;             ///< Имя функции источника
    QString message_;                  ///< Буфер формируемого сообщения
    QTextStream stream_;               ///< Поток формирования сообщения через operator<<
};

}  // namespace detail
}  // namespace logger

#endif  // GUID_8b9db8a0_64a9_4a28_a8e2_ef99f9a87516
