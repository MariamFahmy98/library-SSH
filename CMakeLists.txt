cmake_minimum_required(VERSION 3.10)

project(SecureCopy)

find_library(HAVE_SSH NAMES ssh)

add_executable(${PROJECT_NAME} main.c)

if (HAVE_SSH)
    target_link_libraries(${PROJECT_NAME} ssh)
endif()

add_subdirectory(source)

target_include_directories(${PROJECT_NAME} PUBLIC include)

target_link_directories(${PROJECT_NAME} PRIVATE source)

target_link_libraries(${PROJECT_NAME} ssh-library)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)