cmake_minimum_required(VERSION 3.10)

project(r2pay VERSION 0.1.0 LANGUAGES CXX)

# ===============================================================
# External **compiled** projects: QBDI
# ===============================================================

list(APPEND CMAKE_MODULE_PATH "<QBDI BUILD PATH>")
include(QBDIExport)

# ===============================================================
# CCache option
# ===============================================================

find_program(CCACHE_FOUND ccache)
message(STATUS "ccache: ${QBDI_CCACHE}")

if (CCACHE_FOUND AND QBDI_CCACHE)
  set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
  set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK    ccache)
endif()

# ===============================================================
# Error settings
# ===============================================================

add_library(error_settings INTERFACE)
target_compile_options(
  error_settings
  INTERFACE
    $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<CXX_COMPILER_ID:Clang>>:-Wall -Wextra -Wfatal-errors>
    $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<CXX_COMPILER_ID:GNU>>:-Wall -Wextra -Wfatal-errors>
)

# ===============================================================
# Custom features
# ===============================================================

add_library(features_settings INTERFACE)
target_compile_options(
  features_settings
  INTERFACE
    $<$<COMPILE_LANGUAGE:CXX>:
      -fno-rtti
      -fno-exceptions
      -fdata-sections
      -ffunction-sections
      -fvisibility-inlines-hidden
      -fvisibility=hidden
    >
)

# ===============================================================
# CMake default config information
# ===============================================================

message(STATUS "CMAKE_HOST_SYSTEM:          ${CMAKE_HOST_SYSTEM}")
message(STATUS "CMAKE_BUILD_TYPE:           " ${CMAKE_BUILD_TYPE})
message(STATUS "CMAKE_CXX_COMPILER:         " ${CMAKE_CXX_COMPILER})
message(STATUS "CMAKE_CXX_COMPILER_ID:      " ${CMAKE_CXX_COMPILER_ID})
message(STATUS "CMAKE_CXX_COMPILER_VERSION: " ${CMAKE_CXX_COMPILER_VERSION})
message(STATUS "CMAKE_CXX_FLAGS:            " ${CMAKE_CXX_FLAGS})
message(STATUS "CMAKE_MODULE_PATH:          " ${CMAKE_MODULE_PATH})
message(STATUS "CMAKE_CURRENT_SOURCE_DIR:   " ${CMAKE_CURRENT_SOURCE_DIR})
message(STATUS "CMAKE_CURRENT_BINARY_DIR:   " ${CMAKE_CURRENT_BINARY_DIR})
message(STATUS "CMAKE_EXE_LINKER_FLAGS:     " ${CMAKE_EXE_LINKER_FLAGS})
message(STATUS "CMAKE_INSTALL_PREFIX:       " ${CMAKE_INSTALL_PREFIX})
message(STATUS "CMAKE_MODULE_PATH:          " ${CMAKE_MODULE_PATH})
message(STATUS "CMAKE_PREFIX_PATH:          " ${CMAKE_PREFIX_PATH})
message(STATUS "PROJECT_NAME:               " ${PROJECT_NAME})

# ===============================================================
# Target setup
# ===============================================================

add_executable(${PROJECT_NAME}
  src/main.cpp
)
target_compile_features(${PROJECT_NAME} INTERFACE cxx_std_17)
target_link_libraries(${PROJECT_NAME} PUBLIC
  QBDI_shared
  error_settings features_settings
  log
  z
  spdlog
)

set_target_properties(${PROJECT_NAME} PROPERTIES LINK_WHAT_YOU_USE ON)
set_target_properties(${PROJECT_NAME} PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_include_directories(${PROJECT_NAME}
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_BINARY_DIR}/
)

target_link_options(${PROJECT_NAME}
  PUBLIC
    -rdynamic
    -Wl,-rpath=/data/local/tmp
    -Wl,--gc-sections
)

# ===============================================================
# adb interaction
# ===============================================================
add_custom_target(push
  COMMAND
    adb push ${CMAKE_CURRENT_SOURCE_DIR}/lib/libnative-lib.so /data/local/tmp
  COMMAND
    adb push $<TARGET_FILE:${PROJECT_NAME}> /data/local/tmp
  DEPENDS ${PROJECT_NAME}
)

add_custom_target(run
  COMMAND
    adb shell /data/local/tmp/${PROJECT_NAME}
  COMMENT "Running /data/local/tmp/${PROJECT_NAME}"
  DEPENDS push
)



