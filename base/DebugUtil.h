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
#ifndef DEBUGUTIL_H_
#define DEBUGUTIL_H_
#include <iostream>
#include <string>

namespace cadmium {
namespace base {

// Useful debug logging macros adapted from Chromium, mostly from base/logging.h.

// Used to prevent warnings about unused parameters.
#define UNUSED_PARAMETER(x) (void)(x)

// This class is used to explicitly ignore values in the conditional logging
// macros.  This avoids compiler warnings like "value computed is not used", etc.
class LogMessageVoidify
{
public:
    LogMessageVoidify() {}
    // This must be an operator with precedence lower than << but higher than ?:
    void operator&(std::ostream&) {}
};

// Helper macro which avoids evaluating the arguments to a stream if the
// condition doesn't hold.
#define LAZY_STREAM(stream, condition) !(condition) ? (void) 0 : cadmium::base::LogMessageVoidify() & (stream)
#define DLOG() LAZY_STREAM(std::cout, DLOG_IS_ON())

// A very basic mechanism for outputting useful info in debug builds
#ifdef NDEBUG
#define DLOG_IS_ON() false
#else
#define DLOG_IS_ON() true
#endif

//#define DEBUG_SCOPELOG
#ifdef DEBUG_SCOPELOG

class ScopePrinter
{
public:
    ScopePrinter(std::string s) : scopeName(s) {DLOG() << scopeName << " enter" << std::endl;}
    ~ScopePrinter() {DLOG() << scopeName << " exit" << std::endl;}
private:
    const std::string scopeName;
};
#define FUNCTIONSCOPELOG cadmium::base::ScopePrinter scopePrinter(__PRETTY_FUNCTION__)

#else

#define FUNCTIONSCOPELOG

#endif

inline std::string truncateLong(const std::string& in)
{
    const size_t kTruncLen = 64;
    return (in.size() < kTruncLen) ? in : in.substr(0, kTruncLen) + "...";
}

}}   // namespace cadmium::base

#endif /* DEBUGUTIL_H_ */
