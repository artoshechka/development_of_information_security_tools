/// @file
/// @brief Тесты модуля recursive_stepper.
/// @author Artemenko Anton

#include <gtest/gtest.h>

#include <QDir>
#include <QFile>
#include <QTemporaryDir>
#include <logger_factory.hpp>
#include <recursive_stepper.hpp>

namespace
{
QString CreateFileWithContent(const QString& path)
{
    QFile file(path);
    EXPECT_TRUE(file.open(QIODevice::WriteOnly | QIODevice::Text));
    file.write("test");
    file.close();
    return QFileInfo(path).absoluteFilePath();
}
}  // namespace

TEST(RecursiveStepperTest, BuildIndexReturnsAllFilesRecursively)
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

    const recursive_stepper::FileSystemIndex index = stepper.BuildIndex();

    EXPECT_EQ(index.size(), 3);
    EXPECT_TRUE(index.contains(file1));
    EXPECT_TRUE(index.contains(file2));
    EXPECT_TRUE(index.contains(file3));
}

TEST(RecursiveStepperTest, BuildIndexReturnsEmptyForMissingDirectory)
{
    auto logger = logger::GetLogger<logger::AppSysLoggerTag>();
    recursive_stepper::RecursiveStepper stepper("/path/that/does/not/exist", logger);

    const recursive_stepper::FileSystemIndex index = stepper.BuildIndex();

    EXPECT_TRUE(index.isEmpty());
}

TEST(RecursiveStepperTest, BuildIndexReturnsEmptyForExistingDirectoryWithoutFiles)
{
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());

    QDir root(tempDir.path());
    ASSERT_TRUE(root.mkpath("empty/subdir"));

    auto logger = logger::GetLogger<logger::AppSysLoggerTag>();
    recursive_stepper::RecursiveStepper stepper(tempDir.path(), logger);

    const recursive_stepper::FileSystemIndex index = stepper.BuildIndex();

    EXPECT_TRUE(index.isEmpty());
}
