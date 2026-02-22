/// @file
/// @brief Определение класса для рекурсивного обхода директорий
/// @author Artemenko Anton
#include <recursive_stepper.hpp>

#include <QDateTime>
#include <QDirIterator>

using recursive_stepper::FilesystemIndex;
using recursive_stepper::RecursiveStepper;

namespace
{

/// @brief Преобразовать размер файла (B, KB, MB, GB, TB)
/// @param[in] nSize размер файла в байтах
/// @return строка с размером файла в удобном для чтения виде
QString FileSizeConverter(qint64 nSize)
{
    constexpr char suffixes[] = "BKMGT";

    int order = 0;
    double size = static_cast<double>(nSize);

    while (size >= 1024.0 && order < 4)
    {
        size /= 1024.0;
        ++order;
    }

    return QString::number(size, 'f', 2) + suffixes[order];
}

/// @brief Вывести строковое представление атрибутов файла
/// @details Функция проверяет свойства файла и записывает в поток соответствующие символы:
///          R — файл доступен для чтения,
///          W — файл доступен для записи,
///          H — файл скрытый,
///          E — файл является исполняемым.
/// @param[in] info информация о файле
/// @param[in,out] stream поток вывода для записи атрибутов
void PrintAttributes(const QFileInfo &info, QTextStream &stream)
{
    if (info.isReadable())
        stream << "R";
    if (info.isWritable())
        stream << "W";
    if (info.isHidden())
        stream << "H";
    if (info.isExecutable())
        stream << "E";
}

} // namespace

RecursiveStepper::RecursiveStepper(const QString &dirPath) noexcept : dirPath_(std::move(dirPath))
{
}

FilesystemIndex RecursiveStepper::BuildIndex() const
{
    FilesystemIndex index;

    QDirIterator it(dirPath_, QDir::AllEntries | QDir::NoDotAndDotDot, QDirIterator::Subdirectories);

    while (it.hasNext())
    {
        it.next();

        QFileInfo info = it.fileInfo();

        if (info.isDir())
        {
            index.directories.insert(info.absoluteFilePath());
        }
        else
        {
            index.files.insert(info.absoluteFilePath(), info);
        }
    }

    return index;
}

void RecursiveStepper::PrintIndex(const FilesystemIndex &index, QTextStream &stream) const
{
    for (const auto &dirPath : index.directories)
    {
        QFileInfo info(dirPath);

        stream << "Dir: | " << info.fileName() << " | " << FileSizeConverter(info.size()) << " | "
               << info.lastModified().toString() << " | ";

        PrintAttributes(info, stream);

        stream << "\n";
    }

    for (auto it = index.files.begin(); it != index.files.end(); ++it)
    {
        const QFileInfo &info = it.value();

        stream << "File: | " << info.fileName() << " | " << FileSizeConverter(info.size()) << " | "
               << info.lastModified().toString() << " | ";

        PrintAttributes(info, stream);

        stream << "\n";
    }
}