cmake_minimum_required(VERSION 3.15)
project(pb_split C)

# 默认 Release (未显式指定构建类型时)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_library(pb_split SHARED pb_split.c)

target_compile_features(pb_split PRIVATE c_std_11)

if(MSVC)
    target_compile_options(pb_split PRIVATE /O2 /W4)
else()
    target_compile_options(pb_split PRIVATE -O2 -Wall -fvisibility=hidden)
endif()

# 统一命名: 三端都输出 libpb_split.{dylib|so|dll}, 与 pb_split.py 的加载名一致
set_target_properties(pb_split PROPERTIES
    PREFIX "lib"
    C_STANDARD 11)

# 产物直接输出到本目录, pb_split.py 就地加载
set_target_properties(pb_split PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR})
