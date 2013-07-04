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
#include "CadmiumErrors.h"

namespace cadmium
{

const char * CadErrStr[CAD_ERR_END] =
{
        "no error", // CAD_ERR_OK
        "bad or missing parameter", // CAD_ERR_BADARG
        "key derivation failure", // CAD_ERR_KEYDERIVE
        "no method with that name", // CAD_ERR_NOMETHOD
        "invalid key or dh session handle", // CAD_ERR_BADKEYINDEX
        "invalid base64 encoding", // CAD_ERR_BADENCODING
        "invalid key name", // CAD_ERR_BADKEYNAME
        "corrupt key", // CAD_ERR_LOSTKEY
        "persistent store error", // CAD_ERR_STORE
        "cipher error", // CAD_ERR_CIPHERERROR
        "invalid iv data", // CAD_ERR_BADIV
        "diffie-hellman error", // CAD_ERR_DHERROR
        "uknown error", // CAD_ERR_UNKNOWN
        "not initialized", //CAD_ERR_NOT_INITIALIZED
        "unimplemented method", //CAD_ERR_NOT_IMPLEMENTED
        "no context with that name",  // CAD_ERR_BADCONTEXTNAME
        "hmac error", // CAD_ERR_HMACERROR
        "context is already registered", //CAD_ERR_REGISTERED
        "registration error", // CAD_ERR_REGERROR
        "unknown algorithm", // CAD_ERR_UNKNOWN_ALGO
        "unsupported key encoding", // CAD_ERR_UNSUPPORTED_KEY_ENCODING
        "key generation failure", // CAD_ERR_KEYGEN
        "already initialized",  // CAD_ERR_ALREADY_INITIALIZED
        "unspecified internal error",    //CAD_ERR_INTERNAL
        "disallowed key usage", //CAD_ERR_KEY_USAGE
};

}   // namespace cadmium
