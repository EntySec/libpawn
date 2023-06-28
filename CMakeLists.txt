cmake_minimum_required(VERSION 3.0.0)
project(libpawn VERSION 1.0.0)

option(USE_DEBUG "Build in debug mode" OFF)

if (USE_DEBUG)
    add_definitions(-DDEBUG=1)
endif()

include_directories(include)

if (DEFINED ENV{ARCH})
    set(ARCH $ENV{ARCH})
else()
    set(ARCH "x64")
endif()

include_directories("include/${ARCH}/")

add_library(pawn STATIC src/pawn.c src/exec.c src/log.c)
set_property(TARGET pawn PROPERTY POSITION_INDEPENDENT_CODE ON)
set_target_properties(pawn PROPERTIES OUTPUT_NAME "pawn")

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
