cmake_minimum_required(VERSION 3.0)
project(cssmh)

add_compile_options(-g -m32 -Wall -Wextra)
add_link_options(-m32)

set(INJECTOR_DIR ${PROJECT_SOURCE_DIR}/injector)
file(GLOB_RECURSE INJECTOR_SRC ${INJECTOR_DIR}/*.c)
add_executable(injector ${INJECTOR_SRC})
target_compile_definitions(injector PUBLIC TARGET_PROCESS="hl2_linux" LIBNAME="libcssmh.so")

set(CSSMH_DIR ${PROJECT_SOURCE_DIR}/cssmh)
file(GLOB_RECURSE CSSMH_SRC ${CSSMH_DIR}/*.cpp)
add_library(cssmh SHARED ${CSSMH_SRC})
target_compile_options(cssmh PUBLIC -static-libstdc++)
