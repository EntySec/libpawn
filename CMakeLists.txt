#
# MIT License
#
# Copyright (c) 2020-2023 EntySec
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

cmake_minimum_required(VERSION 3.0.0)
project(libpawn VERSION 1.0.0)

option(DEBUG "Build in debug mode" OFF)
set(ARCH x64 CACHE STRING "Architecture to build for")

if (DEBUG)
    add_compile_definitions(DEBUG)
endif()

include_directories(include)

if(CMAKE_SYSTEM_NAME STREQUAL Darwin)
    set(FILE macho)
    add_compile_definitions(MACHO)
    add_compile_options(-Wno-deprecated)

elseif(CMAKE_SYSTEM_NAME STREQUAL Windows)
    set(FILE pe)
    add_compile_definitions(PE)

else()
    set(FILE elf)
    add_compile_definitions(ELF)
endif()

include_directories(include/${FILE})
include_directories(include/${FILE}/${ARCH}/)

file(GLOB PAWN_SOURCES src/${FILE}/*.c)
add_library(pawn STATIC ${PAWN_SOURCES} src/log.c)

set_property(TARGET pawn PROPERTY C_STANDART 99)
set_property(TARGET pawn PROPERTY POSITION_INDEPENDENT_CODE ON)

set_target_properties(pawn PROPERTIES OUTPUT_NAME pawn)

install(FILES include/pawn.h DESTINATION include)
install(TARGETS pawn)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
