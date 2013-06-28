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

include_directories(${PROJECT_SOURCE_DIR})

# gtest
add_subdirectory(gtest/gtest-1.6.0)
include_directories(gtest/gtest-1.6.0/include)

# name the executable
set(TEST_EXE test)

add_executable(test
    CadmiumCrypto_test.cpp)

target_link_libraries(${TEST_EXE} cadcrypto base gtest_main)

# If we are building for desktop linux, run the tests as part of the build
if(NOT CMAKE_TOOLCHAIN_FILE MATCHES ".*cros.*")
    add_custom_command(TARGET ${TEST_EXE} POST_BUILD COMMAND ${TEST_EXE} . "unit test")
endif()
