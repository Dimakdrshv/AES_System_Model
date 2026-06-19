cmake_minimum_required(VERSION 3.22)

project(aes_model C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(AES_KEY_SIZE "128" CACHE STRING "AES key size: 128, 192, or 256")
set_property(CACHE AES_KEY_SIZE PROPERTY STRINGS 128 192 256)

if(AES_KEY_SIZE STREQUAL "128")
    set(AES_NK 4)
    set(AES_NR 10)
elseif(AES_KEY_SIZE STREQUAL "192")
    set(AES_NK 6)
    set(AES_NR 12)
elseif(AES_KEY_SIZE STREQUAL "256")
    set(AES_NK 8)
    set(AES_NR 14)
else()
    message(FATAL_ERROR "Unsupported AES_KEY_SIZE=${AES_KEY_SIZE}")
endif()

set(AES_SOURCES
    src/aes_transformation.c
    src/aes_key_expansion.c
    src/aes_math.c
    src/aes.c
)

add_executable(aes_model
    src/main.c
    ${AES_SOURCES}
)

target_include_directories(aes_model PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_definitions(aes_model PRIVATE
    Nk=${AES_NK}
    Nr=${AES_NR}
)

target_compile_options(aes_model PRIVATE
    -Wall
    -Wextra
)

enable_testing()

function(add_aes_test test_name nk nr)
    add_executable(${test_name}
        test/test_aes.c
        ${AES_SOURCES}
    )

    target_include_directories(${test_name} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )

    target_compile_definitions(${test_name} PRIVATE
        Nk=${nk}
        Nr=${nr}
    )

    target_compile_options(${test_name} PRIVATE
        -Wall
        -Wextra
    )

    add_test(NAME ${test_name} COMMAND ${test_name})
endfunction()

add_aes_test(aes_test_128 4 10)
add_aes_test(aes_test_192 6 12)
add_aes_test(aes_test_256 8 14)