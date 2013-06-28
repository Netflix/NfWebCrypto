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
#ifndef ScopedMutex_h
#define ScopedMutex_h

#include "Noncopyable.h"
#include "Mutex.h"

namespace cadmium {
namespace base {

class ScopedMutex : private Noncopyable
{
public:
    explicit ScopedMutex(Mutex& mutex) : mutex_(mutex) {mutex_.lock();}
    ~ScopedMutex() {mutex_.unlock();}
private:
    Mutex& mutex_;
};

}} // namespace netflix::base

#endif
