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
#include "Mutex.h"
#include <pthread.h>
#include <assert.h>

namespace cadmium {
namespace base {

Mutex::Mutex()
{
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&m_lock, &attr);
    pthread_mutexattr_destroy(&attr);
}

Mutex::~Mutex()
{
    pthread_mutex_destroy(&m_lock);
}

bool Mutex::lock()
{
    int ret = 0;
    ret = pthread_mutex_lock(&m_lock);
    if (ret != 0)
    {
        assert(false);
        return(false);
    }
    return true;
}

bool Mutex::unlock()
{
    const int ret = pthread_mutex_unlock(&m_lock);
    if (ret != 0)
    {
        assert(false);
        return false;
    }
    return true;
}

}}  // namespace cadmium::base
