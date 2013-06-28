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
#include "SimpleThread.h"
#include <pthread.h>

namespace
{

void* runThread(void* void_data)
{
    cadmium::base::SimpleThread * pInst = static_cast<cadmium::base::SimpleThread*>(void_data);
    pInst->threadFunc();
    return NULL;
}

}   // anonymous namespace


namespace cadmium { namespace base
{

SimpleThread::SimpleThread() : thread_(0)
{
}

SimpleThread::~SimpleThread()
{
    join();
}

bool SimpleThread::start()
{
    if (thread_)
      return false;
    return (pthread_create(&thread_, NULL, &runThread, this) == 0);
}

bool SimpleThread::join()
{
    if (!thread_)
        return false;
    void* retval;
    int result = pthread_join(thread_, &retval);
    thread_ = 0;
    return (result == 0);
}

// static
pthread_t SimpleThread::selfId()
{
    return pthread_self();
}

}} // namespace cadmium::base
