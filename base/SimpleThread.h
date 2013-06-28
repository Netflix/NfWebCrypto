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
#ifndef SIMPLETHREAD_H_
#define SIMPLETHREAD_H_
#include <sys/types.h>
#include "Noncopyable.h"

namespace cadmium { namespace base
{

class SimpleThread : private Noncopyable
{
public:
    SimpleThread();
    virtual ~SimpleThread();
    bool start();
    bool join();
    virtual void threadFunc() {}
    static pthread_t selfId(); // static pthread utility func; used by OpenSSLLib
private:
    pthread_t thread_;
};

}} // namespace cadmium::base

#endif /* SIMPLETHREAD_H_ */
