# pb_split 便捷构建 (Unix); Windows 建议走 CMakeLists.txt
#
#   make          直接调编译器构建当前平台动态库
#   make cmake    走 CMake 构建 (输出相同)
#   make clean    清理
#
# 产物: libpb_split.dylib (macOS) / libpb_split.so (Linux) / libpb_split.dll (Windows)

UNAME := $(shell uname)

ifeq ($(UNAME), Darwin)
    TARGET := libpb_split.dylib
    CC     ?= clang
else
    TARGET := libpb_split.so
    CC     ?= gcc
endif

CFLAGS  ?= -O2 -Wall
SOFLAGS := -shared -fPIC -fvisibility=hidden

.PHONY: all clean cmake

all: $(TARGET)

$(TARGET): pb_split.c
	$(CC) $(CFLAGS) $(SOFLAGS) -o $@ $<

cmake:
	cmake -S . -B build && cmake --build build

clean:
	rm -f $(TARGET)
	rm -rf build
