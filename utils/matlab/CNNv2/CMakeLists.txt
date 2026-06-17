cmake_minimum_required(VERSION 3.20)
project(cnnv2_local_edge_impulse C CXX ASM)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT DEFINED CORE_DIR)
    message(FATAL_ERROR "Define CORE_DIR with -DCORE_DIR=<edge impulse export dir>")
endif()

get_filename_component(CORE_DIR_ABS "${CORE_DIR}" ABSOLUTE)
if(NOT EXISTS "${CORE_DIR_ABS}/edge-impulse-sdk")
    message(FATAL_ERROR "CORE_DIR does not look like an Edge Impulse C++ export: ${CORE_DIR_ABS}")
endif()

add_executable(app tools/local_runner.cpp)
target_include_directories(app PRIVATE "${CORE_DIR_ABS}")
add_subdirectory("${CORE_DIR_ABS}" edge_impulse_model)

target_compile_definitions(app PRIVATE
    EIDSP_SIGNAL_C_FN_POINTER=1
    EI_PORTING_POSIX=1
)

target_compile_options(app PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-Wno-deprecated-declarations>
    $<$<COMPILE_LANGUAGE:CXX>:-Wno-unused-parameter>
)
