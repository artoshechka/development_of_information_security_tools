/// @file
/// @brief Определение класса для рекурсивного обхода директорий
/// @author Artemenko Anton
#include <recursive_stepper.hpp>

#include <logger_macros.hpp>

#include <QDateTime>
#include <QDir>
#include <QDirIterator>

using recursive_stepper::FileSystemIndex;
using recursive_stepper::RecursiveStepper;

RecursiveStepper::RecursiveStepper(const QString &dirPath, const std::shared_ptr<logger::ILogger> &logger) noexcept
    : dirPath_(std::move(dirPath)), logger_(logger)
{
}

FileSystemIndex RecursiveStepper::BuildIndex() const
{
    FileSystemIndex index;

    if (!QDir(dirPath_).exists())
    {
        LogError(logger_) << "RecursiveStepper target directory does not exist: " << dirPath_;
        return index;
    }

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