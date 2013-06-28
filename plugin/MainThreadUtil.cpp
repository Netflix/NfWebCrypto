/*
 *
 *  Copyright 2013 Netflix, Inc.
 *
 *     Licensed under the Apache License, Version 2.0 (the "License");
 *     you may not use this file except in compliance with the License.
 *     You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *     Unless required by applicable law or agreed to in writing, software
 *     distributed under the License is distributed on an "AS IS" BASIS,
 *     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *     See the License for the specific language governing permissions and
 *     limitations under the License.
 *
 */
#include "MainThreadUtil.h"
#include <cassert>
#include <ppapi/c/pp_errors.h>
#include <ppapi/cpp/completion_callback.h>
#include <ppapi/cpp/module.h>

bool isMainThread()
{
    return pp::Module::Get()->core()->IsMainThread();
}

void callOnMain(PP_CompletionCallback_Func func, void* user_data)
{
    assert(!isMainThread());
    pp::CompletionCallback cb(func, user_data);
    callOnMain(cb);
}

void callOnMain(pp::CompletionCallback cb)
{
    pp::Module::Get()->core()->CallOnMainThread(0, cb, PP_OK);
}

void callOnCorrectThread(PP_CompletionCallback_Func func, void* user_data)
{
    if(isMainThread())
        func(user_data, PP_OK);
    else
        callOnMain(func, user_data);
}
