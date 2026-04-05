/// @file
/// @brief Тесты модуля recursive_stepper.
/// @author Artemenko Anton

#include <gtest/gtest.h>

#include <QDir>
#include <QFile>
#include <QTemporaryDir>
#include <logger_factory.hpp>
#include <recursive_stepper.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

namespace
{
QString CreateFileWithContent(const QString& path, const QString& content = "test")
{
    QFile file(path);
    EXPECT_TRUE(file.open(QIODevice::WriteOnly | QIODevice::Text));
    file.write(content.toUtf8());
    file.close();
    return QFileInfo(path).absoluteFilePath();
}

#ifdef _WIN32
void SetFileAsSystem(const QString& filePath)
{
    SetFileAttributesW(reinterpret_cast<const wchar_t*>(filePath.utf16()),
                       FILE_ATTRIBUTE_SYSTEM | GetFileAttributesW(reinterpret_cast<const wchar_t*>(filePath.utf16())));
}
#endif
}  // namespace

TEST(RecursiveStepperTest, GetPathsReturnsAllFilesRecursively)
{
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());

    QDir root(tempDir.path());
    ASSERT_TRUE(root.mkpath("dir_1"));
    ASSERT_TRUE(root.mkpath("dir_2/dir_2_1"));

    const QString file1 = CreateFileWithContent(root.filePath("root.txt"));
    const QString file2 = CreateFileWithContent(root.filePath("dir_1/a.txt"));
    const QString file3 = CreateFileWithContent(root.filePath("dir_2/dir_2_1/b.txt"));

    auto logger = logger::GetLogger<logger::AppSysLoggerTag>();
    recursive_stepper::RecursiveStepper stepper(tempDir.path(), logger);

    const recursive_stepper::FileSystemIndex index = stepper.GetPaths();

    EXPECT_EQ(index.size(), 3);
    EXPECT_TRUE(index.contains(file1));
    EXPECT_TRUE(index.contains(file2));
    EXPECT_TRUE(index.contains(file3));
}

TEST(RecursiveStepperTest, GetPathsReturnsEmptyForMissingDirectory)
{
    auto logger = logger::GetLogger<logger::AppSysLoggerTag>();
    recursive_stepper::RecursiveStepper stepper("/path/that/does/not/exist", logger);

    const recursive_stepper::FileSystemIndex index = stepper.GetPaths();

    EXPECT_TRUE(index.isEmpty());
}

TEST(RecursiveStepperTest, GetPathsReturnsEmptyForExistingDirectoryWithoutFiles)
{
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());

    QDir root(tempDir.path());
    ASSERT_TRUE(root.mkpath("empty/subdir"));

    auto logger = logger::GetLogger<logger::AppSysLoggerTag>();
    recursive_stepper::RecursiveStepper stepper(tempDir.path(), logger);

    const recursive_stepper::FileSystemIndex index = stepper.GetPaths();

    EXPECT_TRUE(index.isEmpty());
}

TEST(RecursiveStepperTest, GetPathsSkipsHiddenFiles)
{
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());

    QDir root(tempDir.path());
    const QString visibleFile = CreateFileWithContent(root.filePath("visible.txt"));
    const QString hiddenFilePath = root.filePath(".hidden");

    QFile hiddenFile(hiddenFilePath);
    ASSERT_TRUE(hiddenFile.open(QIODevice::WriteOnly));
    hiddenFile.write("hidden");
    hiddenFile.close();

    auto logger = logger::GetLogger<logger::AppSysLoggerTag>();
    recursive_stepper::RecursiveStepper stepper(tempDir.path(), logger);

    const recursive_stepper::FileSystemIndex index = stepper.GetPaths();

    EXPECT_EQ(index.size(), 1);
    EXPECT_TRUE(index.contains(visibleFile));
    EXPECT_FALSE(index.contains(QFileInfo(hiddenFilePath).absoluteFilePath()));
}

TEST(RecursiveStepperTest, GetPathsSkipsShortcutFiles)
{
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());

    QDir root(tempDir.path());
    const QString regularFile = CreateFileWithContent(root.filePath("regular.txt"));
    const QString lnkFile = CreateFileWithContent(root.filePath("shortcut.lnk"));
    const QString desktopFile = CreateFileWithContent(root.filePath("app.desktop"));

    auto logger = logger::GetLogger<logger::AppSysLoggerTag>();
    recursive_stepper::RecursiveStepper stepper(tempDir.path(), logger);

    const recursive_stepper::FileSystemIndex index = stepper.GetPaths();

    EXPECT_EQ(index.size(), 1);
    EXPECT_TRUE(index.contains(regularFile));
    EXPECT_FALSE(index.contains(QFileInfo(lnkFile).absoluteFilePath()));
    EXPECT_FALSE(index.contains(QFileInfo(desktopFile).absoluteFilePath()));
}

TEST(RecursiveStepperTest, GetPathsSkipsSystemFiles)
{
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());

    QDir root(tempDir.path());
    const QString regularFile = CreateFileWithContent(root.filePath("regular.txt"));
    const QString sysFile = CreateFileWithContent(root.filePath("system.sys"));
    const QString objFile = CreateFileWithContent(root.filePath("object.o"));

    auto logger = logger::GetLogger<logger::AppSysLoggerTag>();
    recursive_stepper::RecursiveStepper stepper(tempDir.path(), logger);

    const recursive_stepper::FileSystemIndex index = stepper.GetPaths();

    EXPECT_EQ(index.size(), 1);
    EXPECT_TRUE(index.contains(regularFile));
    EXPECT_FALSE(index.contains(QFileInfo(sysFile).absoluteFilePath()));
    EXPECT_FALSE(index.contains(QFileInfo(objFile).absoluteFilePath()));
}

TEST(RecursiveStepperTest, GetPathsMixedFilesAndDirectories)
{
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());

    QDir root(tempDir.path());
    ASSERT_TRUE(root.mkpath("subdir"));

    const QString file1 = CreateFileWithContent(root.filePath("file1.txt"));
    const QString file2 = CreateFileWithContent(root.filePath("subdir/file2.txt"));
    const QString file3 = CreateFileWithContent(root.filePath("subdir/.hidden"));

    QFile hiddenFile(root.filePath("subdir/.hidden"));
    hiddenFile.open(QIODevice::WriteOnly);
    hiddenFile.write("hidden");
    hiddenFile.close();

    auto logger = logger::GetLogger<logger::AppSysLoggerTag>();
    recursive_stepper::RecursiveStepper stepper(tempDir.path(), logger);

    const recursive_stepper::FileSystemIndex index = stepper.GetPaths();

    EXPECT_EQ(index.size(), 2);
    EXPECT_TRUE(index.contains(file1));
    EXPECT_TRUE(index.contains(file2));
    EXPECT_FALSE(index.contains(QFileInfo(root.filePath("subdir/.hidden")).absoluteFilePath()));
}
