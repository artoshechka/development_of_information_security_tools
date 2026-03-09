cmake_minimum_required(VERSION 3.16)
project(crypto_manager LANGUAGES CXX)

add_library(${PROJECT_NAME} STATIC
    src/crypto_manager.cpp
    src/crypto_manager_factory.cpp
)

find_package(OpenSSL REQUIRED)
find_package(QT NAMES Qt5 REQUIRED COMPONENTS Core)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core)

target_include_directories(${PROJECT_NAME}
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(${PROJECT_NAME}
    PRIVATE
        Qt${QT_VERSION_MAJOR}::Core
        OpenSSL::SSL OpenSSL::Crypto
)
