/// @file
/// @brief Определение класса для рекурсивного обхода директорий
/// @author Artemenko Anton
#include <recursive_stepper.hpp>

#include <QDateTime>
#include <QDirIterator>

using recursive_stepper::FilesystemIndex;
using recursive_stepper::RecursiveStepper;

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

        if (info.isFile())
        {
            index.append(info.absoluteFilePath());
        }
    }

    return index;
}