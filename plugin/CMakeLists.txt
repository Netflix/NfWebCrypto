#
# Copyright 2013 Netflix, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

cmake_minimum_required (VERSION 2.8)

# Version file
# FIXME: pull version numbers from env vars first
set(Plugin_VERSION_MAJOR "2")
set(Plugin_VERSION_MINOR "5")
set(Plugin_VERSION_MICRO "0")
configure_file (
  "${PROJECT_SOURCE_DIR}/plugin/Version.h.in"
  "${PROJECT_BINARY_DIR}/Version.h"
)
include_directories (${PROJECT_BINARY_DIR})   # Version.h lands in the binary tree

    set(LIBNAME "nfwebcrypto")
    # For the .info file
    set(SOPATH "lib${LIBNAME}.so")
    set(PLUGIN_NAME "NfWebCrypto")
    set(DESCRIPTION "Provider for W3C Web Crypto API")
    set(MIME_TYPES "application/x-ppapi-nfwebcrypto")
    # end .info file

include_directories(${PROJECT_SOURCE_DIR})

# PPAPI
#add_subdirectory(ppapi)
include_directories(${NACL_SDK_ROOT}/include)

# Sources
set(PLUGIN_SOURCES
    Base32.cpp
    BackgroundDispatcher.cpp
    BrowserConsoleLog.cpp
    MainThreadUtil.cpp
    NativeBridge.cpp
    PpInstance.cpp
    PpModule.cpp
)

#add_library(plugin SHARED ${PLUGIN_SOURCES})
add_executable(plugin ${PLUGIN_SOURCES})

target_link_libraries(plugin base cadcrypto ${NACL_SDK_ROOT}/toolchain/linux_pnacl/sdk/lib/libppapi.a ${NACL_SDK_ROOT}/lib/pnacl/Debug/libppapi_cpp.a)

# name the .so file
set_target_properties(plugin PROPERTIES OUTPUT_NAME "${LIBNAME}")

# set up for final copies
set(FINAL_OUTPUT_DIR ${CMAKE_BINARY_DIR}/plugin)
get_target_property(BIN_NAME plugin LOCATION)
set(INFO_FILE_IN nfwebcrypto.info)
set(INFO_FILE_OUT ${LIBNAME}.info)

# copy/edit the cadmium.info file from source dir template to bin dir result
set(CMAKE_VERSION_STRING "${Plugin_VERSION_MAJOR}.${Plugin_VERSION_MINOR}.${Plugin_VERSION_MICRO}" CACHE STRING "version")
execute_process(COMMAND "date" "+%Y" OUTPUT_VARIABLE DATESTR)
string(REGEX REPLACE "(\r?\n)+$" "" DATESTR "${DATESTR}")
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/${INFO_FILE_IN} ${CMAKE_CURRENT_BINARY_DIR}/${INFO_FILE_OUT})

# copy all final files to the same output location
add_custom_command(
    TARGET plugin
    POST_BUILD
    COMMAND ${NACL_SDK_ROOT}/toolchain/linux_pnacl/bin/pnacl-finalize ${BIN_NAME} -o ${BIN_NAME}.pexe
    COMMENT "Finalize to ${BIN_NAME}.pexe"
)
