#
# Copyright 2013 Netflix, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

cmake_minimum_required(VERSION 2.8)

include_directories(${PROJECT_SOURCE_DIR})

#add_subdirectory(test)

set(CRYPTO_SOURCES
    AesCbcCipher.cpp
    AesGcmCipher.cpp
    AesKeyWrapper.cpp
    BigNum.cpp
    CadmiumCrypto.cpp
    CadmiumCryptoImpl.cpp
    DiffieHellmanContext.cpp
    DigestAlgo.cpp
    Digester.cpp
    Key.cpp
    OpenSSLLib.cpp
    HMAC.cpp
    NtbaUtil.cpp
    OpenSSLException.cpp
    Pbkdf2.cpp
    Random.cpp
    RandTable.cpp
    RsaContext.cpp
    SampleKeyProvision.cpp
    #netflixInternalSecret/SecretKeyProvision.cpp
)

add_library(cadcrypto ${CRYPTO_SOURCES})

# DONT CHECK THIS LINE IN!
#set(CMAKE_PREFIX_PATH "/usr/local/openssl-1.0.1e_dbg")
find_package(OpenSSL)

include_directories(${OPENSSL_INCLUDE_DIR})
target_link_libraries (cadcrypto ${OPENSSL_CRYPTO_LIBRARY})
