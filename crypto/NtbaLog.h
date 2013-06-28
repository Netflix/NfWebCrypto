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
#ifndef __NTBALOG_H__
#define __NTBALOG_H__

#include <stdio.h>
#include <base/DebugUtil.h>

namespace cadmium {
namespace crypto {

#if defined(BUILD_DEBUG)
class FunctionScope
{
public:
    FunctionScope(const char *func) : mFunc(func)
    {
        DLOG() << "Function entered " << mFunc << "()" << std::endl;
    }
    ~FunctionScope()
    {
        DLOG() << "Function returned " << mFunc << "()" << std::endl;
    }
private:
    const char *mFunc;
};
#endif

#define MAX_LOG_STR_LEN 256
#define log_out(fmt, args...)                               \
do {                                                        \
    char log_out_buf[MAX_LOG_STR_LEN];                      \
    snprintf(log_out_buf, MAX_LOG_STR_LEN-1, fmt, ##args);  \
    DLOG() << log_out_buf << std::endl;                     \
} while(0)

#define log_info(...) log_out("[INFO]" __VA_ARGS__);
#define log_err(...) log_out("[ERROR]" __VA_ARGS__);
#define log_err_call(...) log_out("[ERROR]" __VA_ARGS__);
#define log_err_malloc(...) log_out("[ERROR]" __VA_ARGS__);
#define log_trace(...) log_out("[TRACE]" __VA_ARGS__);
#ifdef BUILD_DEBUG
#define log_function_scope() FunctionScope funcScope(__FUNCTION__)
#else
#define log_function_scope()
#endif
#define log_dbg(...) log_out("[DEBUG]" __VA_ARGS__);
#define log_ver(...) log_out("[VERBOSE]" __VA_ARGS__);


#define MAX_ERRNO_STR_LEN 256
#define log_errno(errno) \
    char buf[MAX_ERRNO_STR_LEN]; \
    if(strerror_r(en, buf, MAX_ERRNO_STR_LEN)) \
        log_err_call("strerror_r()"); \
    else \
        log_err("errno description: %s",buf)

}} // cadmium::crypto

#endif  /* __NTBALOG_H__ */
