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
#ifndef CADMIUMERRORS_H_
#define CADMIUMERRORS_H_
#include <string>

namespace cadmium
{

enum CadErr
{
    CAD_ERR_OK = 0,
    CAD_ERR_BADARG,
    CAD_ERR_KEYDERIVE,
    CAD_ERR_NOMETHOD,
    CAD_ERR_BADKEYINDEX,
    CAD_ERR_BADENCODING, // 5
    CAD_ERR_BADKEYNAME,
    CAD_ERR_LOSTKEY,
    CAD_ERR_STORE,
    CAD_ERR_CIPHERERROR,
    CAD_ERR_BADIV,    // 10
    CAD_ERR_DHERROR,
    CAD_ERR_UNKNOWN,
    CAD_ERR_NOT_INITIALIZED,
    CAD_ERR_NOT_IMPLEMENTED,
    CAD_ERR_BADCONTEXTNAME,
    CAD_ERR_HMACERROR,
    CAD_ERR_REGISTERED,
    CAD_ERR_REGERROR,
    CAD_ERR_UNKNOWN_ALGO,
    CAD_ERR_UNSUPPORTED_KEY_ENCODING,
    CAD_ERR_KEYGEN,
    CAD_ERR_ALREADY_INITIALIZED,
    CAD_ERR_INTERNAL,
    CAD_ERR_KEY_USAGE,
    CAD_ERR_END     // sentinel, do not use
};

extern const char * CadErrStr[];

}


#endif /* CADMIUMERRORS_H_ */
