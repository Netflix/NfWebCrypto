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

/**
 * @file tr1.h C++ Technical Report 1 abstraction header.
 *
 * This file provides an abstraction to the C++ TR1 extensions.
 */
#ifndef TR1_H
#define TR1_H

#include <memory>

#if defined(__CWCC__) && defined(RVL)
using std::tr1::shared_ptr;
using std::tr1::weak_ptr;
using std::tr1::static_pointer_cast;
using std::tr1::enable_shared_from_this;
/* GCC 4 supplies std::tr1, but SN does not */
#elif __GNUC__ >= 4 && !defined(__SNC__)
#include <tr1/memory>
using std::tr1::shared_ptr;
using std::tr1::weak_ptr;
using std::tr1::static_pointer_cast;
using std::tr1::enable_shared_from_this;
#elif defined(__EDG__)
#include <boost/shared_ptr.hpp>
#include <boost/weak_ptr.hpp>
#include <boost/pointer_cast.hpp>
#include <boost/enable_shared_from_this.hpp>
namespace std
{
    namespace tr1
    {
        using boost::shared_ptr;
        using boost::weak_ptr;
        using boost::static_pointer_cast;
        using boost::enable_shared_from_this;
    }
}
using boost::shared_ptr;
using boost::weak_ptr;
using boost::static_pointer_cast;
using boost::enable_shared_from_this;
#else
#include <boost/shared_ptr.hpp>
#include <boost/weak_ptr.hpp>
namespace std
{
    namespace tr1
    {
        using boost::shared_ptr;
        using boost::weak_ptr;
        using boost::static_pointer_cast;
    }
}
using boost::shared_ptr;
using boost::weak_ptr;
using boost::static_pointer_cast;
using boost::enable_shared_from_this;
#endif

#endif

