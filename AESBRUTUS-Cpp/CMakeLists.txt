cmake_minimum_required(VERSION 3.8)
project(aes_breaker)

set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static-libstdc++ -static")
set(CMAKE_CXX_STANDARD 17)

include_directories(C:\\OpenSSL-Win32\\include\\)
link_directories(C:\\OpenSSL-Win32\\lib\\)

set(SOURCE_FILES main.cpp base64.cpp base64.h)
add_executable(aes_breaker ${SOURCE_FILES})

target_link_libraries(aes_breaker libcrypto libssl openssl)