/// @file
/// @brief Объявление класса для рекурсивного обхода директорий.
/// @author Artemenko Anton
#ifndef GUID_A9769D40_774C_4FF9_A4A3_8FF1912B4011
#define GUID_A9769D40_774C_4FF9_A4A3_8FF1912B4011

#include <QFileInfo>
#include <QSet>
#include <QString>
#include <QTextStream>
#include <QVector>
#include <ilogger.hpp>
#include <memory>

namespace recursive_stepper
{

/// @brief Псевдоним для контейнера путей к файлам.
using FileSystemIndex = QVector<QString>;

/// @brief Класс, реализующий рекурсивный обход директорий.
class RecursiveStepper
{
   public:
    /// @brief Конструктор.
    /// @param[in] dirPath Путь к директории, с которой начинается обход.
    /// @param[in] logger Логгер для системных ошибок.
    RecursiveStepper(const QString& dirPath, const std::shared_ptr<logger::ILogger>& logger) noexcept;

    /// @brief Строит индекс файловой системы.
    /// @return Список путей ко всем найденным файлам.
    FileSystemIndex BuildIndex() const;

   private:
    QString dirPath_;  ///< Путь к директории, с которой начинается обход.
    std::shared_ptr<logger::ILogger> logger_;
};

}  // namespace recursive_stepper

#endif  // GUID_A9769D40_774C_4FF9_A4A3_8FF1912B4011