cmake_minimum_required(VERSION 3.16)

project(logger LANGUAGES CXX)

find_package(QT NAMES Qt5 REQUIRED COMPONENTS Core)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core)

add_library(${PROJECT_NAME} STATIC
    src/app_logger.cpp
    src/app_sys_logger.cpp
    src/log_entry_stream.cpp
    src/logger_factory.cpp
    src/log_settings.cpp
    src/thread_safe_logger.cpp
)

target_include_directories(${PROJECT_NAME}
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(${PROJECT_NAME}
    PUBLIC
        Qt${QT_VERSION_MAJOR}::Core
)

create_test(
    logger_test
    test/app_logger_test.cpp
    test/app_sys_logger_test.cpp
    test/log_entry_stream_test.cpp
    test/logger_factory_test.cpp
    test/log_settings_test.cpp
    test/thread_safe_logger_test.cpp
    LINK_LIBS
        ${PROJECT_NAME}
)
