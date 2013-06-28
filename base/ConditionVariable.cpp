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
#include "ConditionVariable.h"
#include <sys/time.h>
#include <errno.h>
#include <time.h>   // POSIX defines timespec here
#include <pthread.h>

namespace cadmium {
namespace base {

namespace {

const uint64_t kMsPerSecond = 1000;
const uint64_t kUsPerMs = 1000;
const uint64_t kMsPerSec = 1000;
const uint64_t kNsPerMs = 1000 * 1000;

} // namespace anonymous

ConditionVariable::ConditionVariable()
{
    pthread_cond_init(&m_cond, NULL);
}

ConditionVariable::~ConditionVariable()
{
    pthread_cond_destroy(&m_cond);
}

void ConditionVariable::signal()
{
    pthread_cond_signal(&m_cond);
}

void ConditionVariable::broadcast()
{
    pthread_cond_broadcast(&m_cond);
}

ConditionVariable::Error ConditionVariable::wait(Mutex& mutex, uint64_t timeoutMs)
{
    Error ret = OK;

    int rv = 0;
    if (timeoutMs == 0) {
        rv = pthread_cond_wait(&m_cond, &mutex.m_lock);
    } else {
        struct timeval now;
        gettimeofday(&now, 0);

        struct timespec timeout;

        // convert to ms
        const uint64_t nowMs = now.tv_sec * kMsPerSecond + now.tv_usec / kUsPerMs;
        const uint64_t thenMs = nowMs + timeoutMs;

        // Now generate the timeout value for pthread_cond_timeout
        timeout.tv_sec = thenMs / kMsPerSec;
        timeout.tv_nsec = (thenMs - (timeout.tv_sec * kMsPerSec)) * kNsPerMs;

        rv = pthread_cond_timedwait(&m_cond, &mutex.m_lock, &timeout);
    }

    if (rv == EINVAL) {
        ret = BAD_PARM;
    } else if (rv == ETIMEDOUT) {
        return TIMEDOUT;
    } else if (rv == EPERM) {
        ret = BAD_ACCESS;
    }

    return ret;
}

}}  // namespace cadmium::base

