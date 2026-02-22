/// @file
/// @brief Объявление класса для рекурсивного обхода директорий
/// @author Artemenko Anton
#ifndef GUID_A9769D40_774C_4FF9_A4A3_8FF1912B4011
#define GUID_A9769D40_774C_4FF9_A4A3_8FF1912B4011

#include <QFileInfo>
#include <QMap>
#include <QSet>
#include <QString>
#include <QTextStream>

namespace recursive_stepper
{

/// @brief Структура индекса файловой системы
struct FilesystemIndex
{
    QMap<QString, QFileInfo>
        files;                 ///< Карта файловой системы, где ключ - путь до файла, а значение - информация о файле
    QSet<QString> directories; ///< Множество директорий, найденных в процессе обхода
};

/// @brief Класс, реализующий рекурсивный обход директорий
class RecursiveStepper
{
  public:
    /// @brief Базовый конструктор
    /// @param[in] dirPath путь до директории для начала обхода
    RecursiveStepper(const QString &dirPath) noexcept;

    /// @brief Построить индекс файловой системы
    /// @return Индекс файловой системы
    FilesystemIndex BuildIndex() const;

    /// @brief Вывести построенную карту файловой системы
    /// @param[in] index индекс файловой системы
    /// @param[in,out] stream поток для вывода
    void PrintIndex(const FilesystemIndex &index, QTextStream &stream) const;

  private:
    QString dirPath_; ///< Путь до директории для начала обхода
};

} // namespace recursive_stepper

#endif // GUID_A9769D40_774C_4FF9_A4A3_8FF1912B4011