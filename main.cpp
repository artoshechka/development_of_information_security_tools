#include <recursive_stepper.hpp>

#include <QCoreApplication>

using recursive_stepper::RecursiveStepper;

/// @brief Точка входа в программу.
/// @param argc количество аргументов командной строки
/// @param argv массив аргументов командной строки
/// @return код завершения приложения
int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    QTextStream cin(stdin);
    QTextStream cout(stdout);

    QString path;

    if (argc > 1)
        path = argv[1];
    else
    {
        cout << "Enter directory path: ";
        cout.flush();
        path = cin.readLine();
    }

    RecursiveStepper stepper(path);

    auto index = stepper.BuildIndex();

    stepper.PrintIndex(index, cout);

    return 0;
}