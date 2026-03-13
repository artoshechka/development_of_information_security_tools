/// @file
/// @brief Определение класса для рекурсивного обхода директорий
/// @author Artemenko Anton
#include <recursive_stepper.hpp>

#include <QDateTime>
#include <QDirIterator>

using recursive_stepper::FileSystemIndex;
using recursive_stepper::RecursiveStepper;

RecursiveStepper::RecursiveStepper(const QString &dirPath) noexcept : dirPath_(std::move(dirPath))
{
}

FileSystemIndex RecursiveStepper::BuildIndex() const
{
    FileSystemIndex index;

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