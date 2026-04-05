/// @file
/// @brief Определение класса для рекурсивного обхода директорий
/// @author Artemenko Anton
#include <QDateTime>
#include <QDir>
#include <QDirIterator>
#include <logger_macros.hpp>
#include <recursive_stepper.hpp>

#ifdef _WIN32
#include <windows.h>
#elif defined(__APPLE__)
#include <sys/stat.h>
#else
#include <sys/stat.h>
#endif

using recursive_stepper::FileSystemIndex;
using recursive_stepper::RecursiveStepper;

RecursiveStepper::RecursiveStepper(const QString& dirPath, const std::shared_ptr<logger::ILogger>& logger) noexcept
    : dirPath_(std::move(dirPath)), logger_(logger)
{
}

bool RecursiveStepper::ShouldSkipFile(const QFileInfo& fileInfo) const
{
    // Пропускаем скрытые файлы (работает на всех платформах)
    if (fileInfo.isHidden())
    {
        LogWarning(logger_) << "Skipping hidden file: " << fileInfo.absoluteFilePath();
        return true;
    }

    if (fileInfo.size() == 0)
    {
        LogWarning(logger_) << "Skipping empty file: " << fileInfo.absoluteFilePath();
        return true;
    }

    const QString suffix = fileInfo.suffix().toLower();

    // Пропускаем ярлыки
    if (suffix == "lnk" ||      // Windows shortcuts
        suffix == "desktop" ||  // Linux desktop files
        suffix == "app")        // macOS applications
    {
        LogWarning(logger_) << "Skipping shortcut/application file: " << fileInfo.absoluteFilePath();
        return true;
    }

    // Пропускаем системные файлы
#ifdef _WIN32
    const DWORD attributes = GetFileAttributesW(reinterpret_cast<const wchar_t*>(fileInfo.absoluteFilePath().utf16()));
    if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_SYSTEM))
    {
        LogWarning(logger_) << "Skipping system file: " << fileInfo.absoluteFilePath();
        return true;
    }
#else
    if (suffix == "sys" || suffix == "o" || suffix == "so")
    {
        LogWarning(logger_) << "Skipping system file: " << fileInfo.absoluteFilePath();
        return true;
    }
#endif

    return false;
}

FileSystemIndex RecursiveStepper::GetPaths() const
{
    FileSystemIndex paths;

    if (!QDir(dirPath_).exists())
    {
        LogError(logger_) << "RecursiveStepper target directory does not exist: " << dirPath_;
        return paths;
    }

    QDirIterator it(dirPath_, QDir::AllEntries | QDir::NoDotAndDotDot, QDirIterator::Subdirectories);

    while (it.hasNext())
    {
        it.next();

        QFileInfo info = it.fileInfo();

        if (info.isFile() && !ShouldSkipFile(info))
        {
            paths.append(info.absoluteFilePath());
        }
    }

    return paths;
}