cmake_minimum_required(VERSION 3.28)
project(Gimmick C)

set(CMAKE_C_STANDARD 23)

add_executable(Gimmick gimmick.c
        gimmick.h
        example/main.c
)

target_include_directories(Gimmick PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
