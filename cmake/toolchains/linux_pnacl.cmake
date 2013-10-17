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

# The name of the target operating system
SET(CMAKE_SYSTEM_NAME Linux)

# Compile flags
SET(CMAKE_C_FLAGS_DEBUG "-O0 -g -Wl,-O2" CACHE STRING "CMAKE_C_FLAGS_DEBUG")
SET(CMAKE_CXX_FLAGS_DEBUG ${CMAKE_C_FLAGS_DEBUG} CACHE STRING "CMAKE_CXX_FLAGS_DEBUG")
SET(CMAKE_C_FLAGS_RELEASE "-s -O2 -Wl,-O2" CACHE STRING "CMAKE_C_FLAGS_RELEASE")
SET(CMAKE_CXX_FLAGS_RELEASE ${CMAKE_C_FLAGS_RELEASE} CACHE STRING "CMAKE_CXX_FLAGS_RELEASE")

# Which compilers to use for C and C++
SET(CMAKE_C_COMPILER ${NACL_SDK_ROOT}/toolchain/linux_pnacl/bin/pnacl-clang)
SET(CMAKE_CXX_COMPILER ${NACL_SDK_ROOT}/toolchain/linux_pnacl/bin/pnacl-clang++)
set(CMAKE_AR "${NACL_SDK_ROOT}/toolchain/linux_pnacl/bin/pnacl-ar" CACHE FILEPATH "Archiver")
SET(_CMAKE_TOOLCHAIN_PREFIX pnacl)

# here is the target environment located
SET(CMAKE_FIND_ROOT_PATH ${NACL_SDK_ROOT}/toolchain/linux_pnacl)

# adjust the default behaviour of the FIND_XXX() commands:
# search headers and libraries in the target environment, search
# programs in the host environment
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_REQUIRED_INCLUDES "${NACL_SDK_ROOT}/include")
include_directories(${NACL_SDK_ROOT}/include)


