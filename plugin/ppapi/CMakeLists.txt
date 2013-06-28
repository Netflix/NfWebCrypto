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

cmake_minimum_required( VERSION 2.8 )

include_directories(.)

set(PPAPI_DIR ppapi)

set(PPAPI_SOURCES
        ${PPAPI_DIR}/cpp/core.cc
        ${PPAPI_DIR}/cpp/file_io.cc
        ${PPAPI_DIR}/cpp/file_ref.cc
        ${PPAPI_DIR}/cpp/file_system.cc
        ${PPAPI_DIR}/cpp/input_event.cc
        ${PPAPI_DIR}/cpp/instance.cc
        ${PPAPI_DIR}/cpp/instance_handle.cc
        ${PPAPI_DIR}/cpp/module.cc
        ${PPAPI_DIR}/cpp/ppp_entrypoints.cc
        ${PPAPI_DIR}/cpp/resource.cc
        ${PPAPI_DIR}/cpp/url_loader.cc
        ${PPAPI_DIR}/cpp/url_response_info.cc
        ${PPAPI_DIR}/cpp/var.cc
        ${PPAPI_DIR}/cpp/dev/scriptable_object_deprecated.cc
        ${PPAPI_DIR}/cpp/private/flash_device_id.cc
        ${PPAPI_DIR}/cpp/private/instance_private.cc
        ${PPAPI_DIR}/cpp/private/var_private.cc
        ${PPAPI_DIR}/cpp/view.cc
        ${PPAPI_DIR}/utility/threading/lock.cc
)

add_library(ppapi ${PPAPI_SOURCES})
