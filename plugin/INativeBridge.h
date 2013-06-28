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
#ifndef INATIVEBRIDGE_H_
#define INATIVEBRIDGE_H_
#include <string>

namespace cadmium
{

class INativeBridge
{
public:
    virtual ~INativeBridge() {}
    virtual void handleMessage(const std::string& message) = 0;
    virtual void postMessage(const std::string& message) = 0;
    virtual void sendReady(int errCode) = 0;
};

}  // namespace cadmium


#endif // INATIVEBRIDGE_H_
