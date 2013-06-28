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

# The settings in this file are common to ALL builds

# Common compiler flags
set(COMMON_CFLAGS "-fpic -Wall -fmessage-length=0 -Wchar-subscripts -fvisibility=hidden")
set(COMMON_CXXFLAGS "${COMMON_CFLAGS} -fno-exceptions -fno-rtti -DGTEST_HAS_RTTI=0")

if (NOT CMAKE_BUILD_TYPE MATCHES "Gentoo")
    # Default compiler flags
    set(CMAKE_C_FLAGS "${COMMON_CFLAGS}" CACHE STRING "CFLAGS")
    set(CMAKE_CXX_FLAGS "${COMMON_CXXFLAGS}" CACHE STRING "CXXFLAGS")

    # Debug compiler flags
    set(CMAKE_C_FLAGS_DEBUG "-O0 -g -DBUILD_DEBUG" CACHE STRING "CMAKE_C_FLAGS_DEBUG")
    set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g -DBUILD_DEBUG" CACHE STRING "CMAKE_CXX_FLAGS_DEBUG")

    # Linker flags. Explicit stdc++ is required for ARM builds for some reason.
    set(LDD_NO_EXECSTACK "-Wl,-z -Wl,noexecstack")
    set(CMAKE_EXE_LINKER_FLAGS "-ldl -lrt -lstdc++ ${LDD_NO_EXECSTACK}" CACHE STRING "LDFLAGS")
endif()
