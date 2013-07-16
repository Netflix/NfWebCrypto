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

# The settings in this file are common to ALL desktop linux builds
# This file is included by leaf files linux[32|64].cmake

get_filename_component(TOOLCHAIN_DIR ${CMAKE_CURRENT_LIST_FILE} PATH)
include("${TOOLCHAIN_DIR}/common.cmake")

# NOTE: SECRET_SYSTEM_KEY should be changed for actual deployments.
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DSECRET_SYSTEM_KEY=iIniW9SVpZKlXGmbrgrJG9uxy7HtCNJsDM5IXS24eCI=")

# Toolchain paths - for desktop linux we just use the system tools
set(CMAKE_C_COMPILER "gcc")
set(CMAKE_CXX_COMPILER "g++")
