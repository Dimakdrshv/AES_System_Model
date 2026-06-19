cmake_minimum_required(VERSION 3.22)

project(aes_model C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_executable(aes_model
    src/main.c
    src/aes_transformation.c
    src/aes_key_expansion.c
    src/aes_math.c
    src/aes.c
)

target_include_directories(aes_model PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_options(aes_model PRIVATE
    -Wall
    -Wextra
)