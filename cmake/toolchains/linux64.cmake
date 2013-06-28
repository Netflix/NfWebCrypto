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

# Settings specific to desktop linux amd64 builds
# Choose this leaf file by specifying it as the cmake toolchain file

get_filename_component(TOOLCHAIN_DIR ${CMAKE_CURRENT_LIST_FILE} PATH)
include("${TOOLCHAIN_DIR}/common/linux_common.cmake")

# Have to put all variable setting inside a context to work around cmake's
# appending behavior
if(NOT FOO_FLAGS)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m64" CACHE STRING "CFLAGS" FORCE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m64" CACHE STRING "CXXFLAGS" FORCE)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -m64" CACHE STRING "LDFLAGS" FORCE)
    # Once already appended, don't append again
    set(FOO_FLAGS TRUE CACHE BOOLEAN "." FORCE)
endif()
