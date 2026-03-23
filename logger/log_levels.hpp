/// @file
/// @brief Объявление уровней логирования
/// @author Artemenko Anton
#ifndef GUID_7f71c29a_8f1f_41dc_bbd2_2406bd48a72b
#define GUID_7f71c29a_8f1f_41dc_bbd2_2406bd48a72b

namespace logger
{
/// @brief Уровни логирования
enum class LogLevel {
    Trace,    ///< Трассировка
    Debug,    ///< Отладка
    Info,     ///< Информация
    Warning,  ///< Предупреждение
    Error,    ///< Ошибка
    Fatal     ///< Фатальная ошибка
};

}  // namespace logger

#endif  // GUID_7f71c29a_8f1f_41dc_bbd2_2406bd48a72b