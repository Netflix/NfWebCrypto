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
#include "BrowserConsoleLog.h"
#include <cassert>
#include <ppapi/c/pp_errors.h>
#include <ppapi/cpp/module.h>
#include <ppapi/cpp/var.h>
#include "MainThreadUtil.h"

using namespace std;

namespace {

void LogToBrowserConsoleFromMain(PP_Instance instance, PP_LogLevel level,
        const pp::Var& value)
{
    assert(isMainThread());
    const PPB_Console* console = reinterpret_cast<const PPB_Console*>(
            pp::Module::Get()->GetBrowserInterface(PPB_CONSOLE_INTERFACE));
    if (!console)
        return;
    console->Log(instance, level, value.pp_var());
}

struct LogMessage
{
    LogMessage(PP_Instance instance, PP_LogLevel level, const char *const str)
    :   instance(instance)
    ,   level(level)
    ,   str(str)
    {
        assert(str);
    }
    const PP_Instance instance;
    const PP_LogLevel level;
    const string str;
};

void LogToBrowserCallback(void* user_data, int32_t result)
{
    assert(result == PP_OK);  (void)result;
    assert(isMainThread());
    LogMessage * const msg = static_cast<LogMessage * const>(user_data);
    assert(msg);
    LogToBrowserConsoleFromMain(msg->instance, msg->level, msg->str);
    delete msg;
}

}  // namespace

namespace cadmium
{

void LogToBrowserConsole(PP_Instance instance, PP_LogLevel level,
        const char * const str)
{
    assert(str);
    if (isMainThread())
        LogToBrowserConsoleFromMain(instance, level, str);
    else
        callOnMain(&LogToBrowserCallback, new LogMessage(instance, level, str));
}

} // namespace cadmium
