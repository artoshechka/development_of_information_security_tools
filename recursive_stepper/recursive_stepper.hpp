/// @file
/// @brief Объявление класса для рекурсивного обхода директорий
/// @author Artemenko Anton
#pragma once
#ifndef GUID_A9769D40_774C_4FF9_A4A3_8FF1912B4011
#define GUID_A9769D40_774C_4FF9_A4A3_8FF1912B4011

#include <QFileInfo>
#include <QSet>
#include <QString>
#include <QTextStream>
#include <QVector>

namespace recursive_stepper
{

/// @brief Переопределение для вектора путей до файлов
using FileSystemIndex = QVector<QString>;

/// @brief Класс, реализующий рекурсивный обход директорий
class RecursiveStepper
{
  public:
    /// @brief Базовый конструктор
    /// @param[in] dirPath путь до директории для начала обхода
    RecursiveStepper(const QString &dirPath) noexcept;

    /// @brief Построить индекс файловой системы
    /// @return Индекс файловой системы
    FileSystemIndex BuildIndex() const;

  private:
    QString dirPath_; ///< Путь до директории для начала обхода
};

} // namespace recursive_stepper

#endif // GUID_A9769D40_774C_4FF9_A4A3_8FF1912B4011