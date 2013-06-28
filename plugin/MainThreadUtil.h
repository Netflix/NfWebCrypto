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
#ifndef MAIN_THREAD_UTIL_H_
#define MAIN_THREAD_UTIL_H_

#include <stdint.h>
#include <ppapi/cpp/completion_callback.h>

// Returns true if running on the main thread.
bool isMainThread();

// Calls func on the main thread with user_data parameter.
void callOnMain(PP_CompletionCallback_Func func, void* user_data);

// Executes callback object on main thread
void callOnMain(pp::CompletionCallback cb);

// Calls func on the main thread if necessary.
// If this is the main thread, calls func directly. Otherwise, uses CallOnMain
// to call fun on the main thread.
// Use when the calling code could be called form the main or a worker thread.
void callOnCorrectThread(PP_CompletionCallback_Func func, void* user_data);

#endif  // MAIN_THREAD_UTIL_H_
