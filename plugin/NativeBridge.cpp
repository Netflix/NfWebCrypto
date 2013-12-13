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
#include "NativeBridge.h"
#include <ppapi/cpp/private/instance_private.h>
#include <base/CadmiumErrors.h>
#include <base/DebugUtil.h>
#include <base/JSONFormatter.h>
#include <base/Variant.h>
#include <crypto/CadmiumCrypto.h>
#include "MainThreadUtil.h"
#include "Version.h"

using namespace std;

namespace cadmium
{

using namespace base;
using namespace crypto;

namespace   // anonymous
{

typedef vector<unsigned char> Vuc;

inline void setSuccess(cadmium::base::VariantMap& returnVarMap)
{
    returnVarMap["success"] = true;
    returnVarMap["errorMessage"] = "";
    returnVarMap["errorCode"] = cadmium::CAD_ERR_OK;
}

vector<CadmiumCrypto::KeyUsage> toKeyUsageVec(const VariantArray& keyUsageVarAry)
{
    vector<CadmiumCrypto::KeyUsage> keyUsageVec;
    for (VariantArray::const_iterator it = keyUsageVarAry.begin(); it != keyUsageVarAry.end(); ++it)
    {
        string keyUsageStr = it->string();
        if (keyUsageStr == "encrypt")
            keyUsageVec.push_back(CadmiumCrypto::ENCRYPT);
        else if (keyUsageStr == "decrypt")
            keyUsageVec.push_back(CadmiumCrypto::DECRYPT);
        else if (keyUsageStr == "sign")
            keyUsageVec.push_back(CadmiumCrypto::SIGN);
        else if (keyUsageStr == "verify")
            keyUsageVec.push_back(CadmiumCrypto::VERIFY);
        else if (keyUsageStr == "derive")
            keyUsageVec.push_back(CadmiumCrypto::DERIVE);
        else if (keyUsageStr == "wrap")
            keyUsageVec.push_back(CadmiumCrypto::WRAP);
        else if (keyUsageStr == "unwrap")
            keyUsageVec.push_back(CadmiumCrypto::UNWRAP);
    }
    return keyUsageVec;
}

VariantArray toKeyUsageVarAry(vector<CadmiumCrypto::KeyUsage>& keyUsageVec)
{
    VariantArray keyUsageVarAry;
    for (vector<CadmiumCrypto::KeyUsage>::const_iterator it = keyUsageVec.begin(); it != keyUsageVec.end(); ++it)
        keyUsageVarAry.push_back(toString(*it));
    return keyUsageVarAry;
}

CadmiumCrypto::KeyFormat stringToKeyFormat(const string& format)
{
    if (format == "raw")
        return CadmiumCrypto::RAW;
    else if (format == "pkcs8")
        return CadmiumCrypto::PKCS8;
    else if (format == "spki")
        return CadmiumCrypto::SPKI;
    else if (format == "jwk")
        return CadmiumCrypto::JWK;
    else
        return CadmiumCrypto::INVALID_KEYFORMAT;
}

// The Web Crypto spec allows algorithm to be either a simple string or an
// object. This function parses this variance and returns a normalized object,
// which makes the logic that uses the algorithm much easier. The result of this
// function is a Variant that represents the following javascript structure:
// {
//      type:   int, a member of the enum CadmiumCrypto::Algorithm
//      params: object, algorithm-specific parameters, can be omitted
// }
// TBD: This is also were the "algorithm normalizing rules" will go
bool parseAlgorithmObj(const Variant& algVar, Variant& outVar); // forward decl
bool getAlgorithmObj(const Variant& inVar, Variant& outVar, const string& name = "algorithm")
{
    if (!inVar.contains(name))
    {
        // special case for un/wrapKey(), where null alg is allowed
        outVar = Variant(); // null in, null out
        return true;
    }
    if (inVar[name].isString())
    {
        return parseAlgorithmObj(inVar.mapValue<string>(name), outVar);
    }
    else if (inVar[name].isMap())
    {
        return parseAlgorithmObj(inVar.mapValue<VariantMap>(name), outVar);
    }
    else if (inVar[name].isNull())
    {
        // special case for un/wrapKey(), where null alg is allowed
        outVar = Variant(); // null in, null out
        return true;
    }
    else
    {
        DLOG() << "getAlgorithmObj: unrecognized algorithm format\n";
        return false;
    }
}

bool parseAlgorithmObj(const Variant& algVar, Variant& outVar)
{
    bool success = true;
    string algNameStr;
    Variant paramsVar;
    if (algVar.isString())
    {
        algNameStr = algVar.string();
        success = true;
    }
    else if (algVar.isMap())
    {
        algNameStr = algVar.mapValue<string>("name", &success);
        if (!success)
            DLOG() << "getAlgorithmObj: unable to extract name from algorithm object\n";
        if (algVar.contains("params"))
            paramsVar = algVar.mapValue<VariantMap>("params");  // optional
    }
    const CadmiumCrypto::Algorithm algo = toAlgorithm(algNameStr);
    if (algo == CadmiumCrypto::INVALID_ALGORITHM)
    {
        DLOG() << "getAlgorithmObj: invalid algorithm\n";
        success = false;
    }
    // special case: the params object sometimes contains a 'hash' algorithm object
    if (paramsVar.contains("hash"))
    {
        Variant tmpAlgVar;
        success = getAlgorithmObj(paramsVar, tmpAlgVar, "hash");
        if (!success)
            DLOG() << "getAlgorithmObj: invalid nested algorithm\n";
        if (!tmpAlgVar.isNull())
            paramsVar["hash"] = tmpAlgVar;
    }
    outVar["name"]   = algNameStr;
    if (!paramsVar.isNull())
        outVar["params"] = paramsVar;
    return success;
}


bool checkHash(const Variant& algObj)
{
    if (algObj["params"].isNull())
    {
        DLOG() << "checkHash: algorithm missing params\n";
        return false;
    }
    if (algObj["params"]["hash"].isNull())
    {
        DLOG() << "checkHash: algorithm->params missing hash\n";
        return false;
    }
    if (!algObj["params"]["hash"].contains("name"))
    {
        DLOG() << "checkHash: algorithm->params->hash alg missing type\n";
        return false;
    }
    const CadmiumCrypto::Algorithm hashType =
        toAlgorithm(algObj["params"]["hash"]["name"].string());
    if (!isAlgorithmSha(hashType))
    {
        DLOG() << "checkHash: require inner hash to be SHA\n";
        return false;
    }
    return true;
}

string thinJsonMessage(const string& in)
{
    Variant var = Variant::fromJSON(in.c_str());
    if (var.contains("argsObj"))
    {
        Variant argsObj = var["argsObj"];
        if (argsObj.contains("buffer"))
            argsObj["buffer"] = truncateLong(argsObj["buffer"].string());
        if (argsObj.contains("signature"))
            argsObj["signature"] = truncateLong(argsObj["signature"].string());
        if (argsObj.contains("iv"))
            argsObj["iv"] = truncateLong(argsObj["iv"].string());
        if (argsObj.contains("keyData"))
            argsObj["keyData"] = truncateLong(argsObj["keyData"].string());
        var["argsObj"] = argsObj;
    }
    if (var.contains("payload"))
    {
        Variant payloadObj = var["payload"];
        if (payloadObj.contains("buffer"))
            payloadObj["buffer"] = truncateLong(payloadObj["buffer"].string());
        var["payload"] = payloadObj;
    }

    return var.toJSON();
}

}   // anonymous namespace

NativeBridge::NativeBridge(pp::InstancePrivate * pInstance, CadmiumCrypto * cadmiumCrypto)
:   pInstance_(pInstance)
,   cadmiumCrypto_(cadmiumCrypto)
,   callbackFactory_(this)
{
    FUNCTIONSCOPELOG;
    assert(pInstance_);
    assert(cadmiumCrypto_);

    // Fill the function dispatch table. These are the javascript methods that
    // can be handled by invoke().
    jsFunctionMap_["digest"]      = &NativeBridge::digest;
    jsFunctionMap_["import"]      = &NativeBridge::importKey;
    jsFunctionMap_["export"]      = &NativeBridge::exportKey;
    jsFunctionMap_["encrypt"]     = &NativeBridge::encrypt;
    jsFunctionMap_["decrypt"]     = &NativeBridge::decrypt;
    jsFunctionMap_["sign"]        = &NativeBridge::sign;
    jsFunctionMap_["verify"]      = &NativeBridge::verify;
    jsFunctionMap_["generate"]    = &NativeBridge::generate;
    jsFunctionMap_["derive"]      = &NativeBridge::derive;
    jsFunctionMap_["unwrapKey"]   = &NativeBridge::unwrapKey;
    jsFunctionMap_["wrapKey"]     = &NativeBridge::wrapKey;
    jsFunctionMap_["getDeviceId"] = &NativeBridge::getDeviceId;
    jsFunctionMap_["getKeyByName"]= &NativeBridge::getKeyByName;
}

NativeBridge::~NativeBridge()
{
    FUNCTIONSCOPELOG;
}

void NativeBridge::handleMessage(const std::string& message)
{
    FUNCTIONSCOPELOG;
    DLOG() << "================================================================================\n";
    DLOG() << "NativeBridge::handleMessage(): " << thinJsonMessage(message) << endl;
    invoke(Variant::fromJSON(message.c_str()));
}

void NativeBridge::postMessage(const std::string& message)
{
    FUNCTIONSCOPELOG;
    pp::CompletionCallback cb =
        callbackFactory_.NewCallback(&NativeBridge::postMessageCb, message);
    if (!isMainThread())
        callOnMain(cb);
    else
        cb.Run(0);
}

void NativeBridge::sendReady(int errCode)
{
    // This is a special message that indicates the plugin is ready for
    // business. It has the following structure:
    // {
    //     method:          'ready'
    //     idx:             -1 (not used)
    //     success:         true if no errCode=CAD_ERR_OK, false otherwise
    //     errorMessage:    string, error message
    //     errorCode:       errCode
    //     payload:         {'compat': Array of API version numbers this class
    //                                 is compatible with}
    // }
    VariantMap msgVar;
    msgVar["method"] = "ready";
    msgVar["idx"] = -1;   // this message does not have use index
    msgVar["success"] = (errCode==CAD_ERR_OK);
    msgVar["errorMessage"] = CadErrStr[errCode];
    msgVar["errorCode"] = errCode;
    VariantArray compatList;
    compatList.push_back(Variant("1"));
    VariantMap varMap;
    varMap["compat"] = compatList;
    stringstream version;
    version << Plugin_VERSION_MAJOR << "." << Plugin_VERSION_MINOR;
    varMap["version"] = version.str();
    msgVar["payload"] = Variant(varMap);
    send(msgVar);
}

void NativeBridge::invoke(const Variant& request)
{
    FUNCTIONSCOPELOG;

    // Every invoke request has the following structure:
    // {
    //     method:      string, method name
    //     idx:         string, command identifier, used by javascript to match
    //                    a method call to callback received
    //     argsObj:     object, optional method arguments
    // },
    //
    // Every invoke request results in a callback with the following structure:
    // {
    //     method:          string, name of calling method
    //     idx:             string, idx of calling method
    //     success:         boolean, method execute success
    //     errorMessage:    string, a text description of the error if success
    //                        equals false
    //     errorCode:       number, a numeric error code if success equals false
    //     payload:         object, any data returned by the method or empty

    // --> method
    const string method(request.mapValue<string>("method"));
    DLOG() << "NativeBridge::invoke() " << method << endl;

    // There is a special internal message to reseed PRNG entropy which does not
    // follow the form above, and no callback should be sent back. Catch and
    // process this message here.
    // Its format is
    // {
    //      method:     string, "addEntropy"
    //      data:       string, entropy bytes, base64-encoded
    // }
    if (method == "addEntropy")
    {
        const string data64(request.mapValue<string>("data"));
        DLOG() << "\tdata: " << truncateLong(data64) << endl;
        if (!data64.empty())
            cadmiumCrypto_->addEntropy(data64);
        return;
    }

    // --> idx
    // once we have an index we can issue callbacks
    const string cmdIndex(request.mapValue<string>("idx"));
    if (cmdIndex.empty())
    {
        // No cmdIndex means that we can't even invoke the callback. Can't do
        // much here besides assert.
        DLOG() << "NativeBridge::invoke(): missing \"idx\" field\n" << endl;
        assert(false);
        return;
    }

    // no method at this point is an error
    if (method.empty())
    {
        sendError(cmdIndex, CAD_ERR_BADARG);
        return;
    }

    // --> argsObj
    Variant args(request.mapValue<VariantMap>("argsObj"));

    // Initialize the data to be returned in the callback to javascript
    VariantMap returnVarMap;
    returnVarMap["method"] = method;
    returnVarMap["idx"] = cmdIndex;
    returnVarMap["success"] = false;
    returnVarMap["errorMessage"] = "unknown error";
    returnVarMap["errorCode"] = CAD_ERR_UNKNOWN;
    returnVarMap["payload"] = VariantMap();

    // Do we know this method?
    JsFunctionMap::const_iterator iter = jsFunctionMap_.find(method);
    if (iter == jsFunctionMap_.end())
    {
        DLOG() << "NrdDpiNativeBridge::invoke() error UNKNOWN method\n";
        sendError(cmdIndex, CAD_ERR_NOMETHOD);
        return;
    }

    // Dispatch it! All results land in returnVarMap
    const JsMethodPtr jsMethodPtr = iter->second;
    if (!(this->*(jsMethodPtr))(cmdIndex, args, returnVarMap))
        return;

    // Send the results back to javascript with the callback
    send(returnVarMap);
}

bool NativeBridge::digest(const string& cmdIndex, Variant& argsVar,
        VariantMap& returnVarMap)
{
    // ------------ digest --------------
    // Compute a digest on the input data
    // Input:
    //     argsObj: {
    //         algorithm: object (only SHA algorithms accepted)
    //         buffer: base64-encoded data to digest
    //     }
    // Output:
    //     payload: {
    //         buffer: base64-encoded digest of input buffer
    //     }

    // extract normalized algorithm object
    Variant algObj;
    if (!getAlgorithmObj(argsVar, algObj))
    {
        sendError(cmdIndex, CAD_ERR_UNKNOWN_ALGO);  // FIXME: better error
        return false;
    }
    const CadmiumCrypto::Algorithm algType = toAlgorithm(algObj["name"].string());

    // parameter check
    DLOG() << "\talgorithm " << toString(algType) << endl;
    if (!isAlgorithmSha(algType))
    {
        DLOG() << "NativeBridge::digest: require SHA algorithm\n";
        sendError(cmdIndex, CAD_ERR_UNKNOWN_ALGO);
        return false;
    }
    string data64;
    if (!getVal<string>(argsVar, "buffer", cmdIndex, data64))
        return false;
    DLOG() << "\tbuffer: " << truncateLong(data64) << endl;

    // compute the digest
    string digestStr64;
    CadErr err = cadmiumCrypto_->digest(algType, data64, digestStr64);
    if (isError(err, cmdIndex))
        return false;
    DLOG() << "\tresult: " << digestStr64 << endl;

    // return the result
    returnVarMap["payload"]["buffer"] = digestStr64;
    setSuccess(returnVarMap);

    return true;
}

bool NativeBridge::importKey(const string& cmdIndex, Variant& argsVar,
        VariantMap& returnVarMap)
{
    // ------------ import --------------
    // Import a key into the key store
    // Input:
    //     argsObj: {
    //         format:      string; the format of keyData, "raw" or "jwk", "pkcs8", "spki"
    //         keyData:     string; the key data, base64-encoded
    //         algorithm:   object; the algorithm used to generate the key
    //         extractable: boolean; whether or not the raw keying material
    //                        may be exported by the application (optional)
    //         keyUsage:   Array of strings from the set "encrypt", "decrypt",
    //                        "sign", "verify", "derive"; indicates what
    //                        operations may be used with this key (optional)
    //     }
    // Output:
    //     payload: {
    //         handle:      the handle of this key in the key store
    //         type:        string; one of "secret", "public", "private"
    //         extractable: string; same as input if present else false
    //         algorithm:   object; name of the input algorithm
    //         keyUsage:   Array of strings; same as input if present else empty
    //     }

    // get format
    string format;
    if (!getVal<string>(argsVar, "format", cmdIndex, format))
        return false;
    DLOG() << "\tformat: " << format << endl;
    const CadmiumCrypto::KeyFormat keyFormat = stringToKeyFormat(format);
    if (keyFormat == CadmiumCrypto::INVALID_KEYFORMAT)
    {
        DLOG() << "NativeBridge::importKey: unrecognized format specifier\n";
        sendError(cmdIndex, CAD_ERR_BADARG);
        return false;
    }

    // get keyData
    string keyData;
    if (!getVal<string>(argsVar, "keyData", cmdIndex, keyData))
        return false;
    DLOG() << "\tkeyData: " << truncateLong(keyData) << endl;

    // get algorithm, do not fail if not present since some codepaths offer a fallback
    Variant algObj;
    getAlgorithmObj(argsVar, algObj);
    const CadmiumCrypto::Algorithm algType = toAlgorithm(algObj["name"].string());
    DLOG() << "\talgorithm: " << toString(algType) << endl;

    // get (optional) extractable; if not present default to false
    bool extractable;
    if (!getVal<bool>(argsVar, "extractable", cmdIndex, extractable, false))
        extractable = false;
    DLOG() << "\textractable: " << (extractable ? "true" : "false") << endl;

    // get (optional) keyUsage; if not present leave empty
    bool isFound;
    VariantArray keyUsageVarAry = argsVar.mapValue<VariantArray>("keyUsage", &isFound);
    vector<CadmiumCrypto::KeyUsage> keyUsageVec;
    if (isFound)
        keyUsageVec = toKeyUsageVec(keyUsageVarAry);
    DLOG() << "\tkeyUsage: " << toString(keyUsageVec) << endl;

    // import the key
    uint32_t keyHandle;
    CadErr err = cadmiumCrypto_->importKey(keyFormat, keyData, algObj,
            extractable, keyUsageVec, keyHandle);
    if (isError(err, cmdIndex))
        return false;
    DLOG() << "\tkeyHandle: " << keyHandle << endl;

    // Make the final output key object
    VariantMap keyVarMap;
    if (!keyHandleToKeyVarMap(keyHandle, keyVarMap))
    {
        sendError(cmdIndex, CAD_ERR_INTERNAL);  // FIXME better error
        return false;
    }

    DLOG() << "\timported key: " << Variant(keyVarMap).toJSON() << endl;

    // return the result
    returnVarMap["payload"] = keyVarMap;
    setSuccess(returnVarMap);

    return true;
}

bool NativeBridge::exportKey(const string& cmdIndex, Variant& argsVar,
        VariantMap& returnVarMap)
{
    // ------------ export --------------
    // Export a key from the key store. Only keys that are marked
    // extractable may be exported.
    // Input:
    //     argsObj: {
    //         keyHandle: the handle of the key in the key store
    //         format:    string; the desired output format
    //     }
    // Output:
    //     payload: {
    //         buffer:     string; the key data, base64-encoded
    //     }

    // get key handle
    int keyHandle;
    if (!getVal<int>(argsVar, "keyHandle", cmdIndex, keyHandle))
        return false;
    DLOG() << "\tkeyHandle: " << keyHandle << endl;

    // get format
    string format;
    if (!getVal<string>(argsVar, "format", cmdIndex, format))
        return false;
    DLOG() << "\tformat: " << format << endl;
    const CadmiumCrypto::KeyFormat keyFormat = stringToKeyFormat(format);
    if (keyFormat == CadmiumCrypto::INVALID_KEYFORMAT)
    {
        DLOG() << "NativeBridge::importKey: unrecognized format specifier\n";
        sendError(cmdIndex, CAD_ERR_BADARG);
        return false;
    }

    // extract the key
    string keyData;
    CadErr err = cadmiumCrypto_->exportKey(keyHandle, keyFormat, keyData);
    if (isError(err, cmdIndex))
        return false;

    returnVarMap["payload"]["buffer"] = keyData;
    setSuccess(returnVarMap);

    return true;
}

bool NativeBridge::encrypt(const string& cmdIndex, Variant& argsVar,
        VariantMap& returnVarMap)
{
    // ------------ encrypt --------------
    argsVar["doEncrypt"] = true;
    return encryptDecrypt(cmdIndex, argsVar, returnVarMap);
}

bool NativeBridge::decrypt(const string& cmdIndex, Variant& argsVar,
        VariantMap& returnVarMap)
{
    // ------------ decrypt --------------
    argsVar["doEncrypt"] = false;
    return encryptDecrypt(cmdIndex, argsVar, returnVarMap);
}

bool NativeBridge::encryptDecrypt(const string& cmdIndex, Variant& argsVar,
        VariantMap& returnVarMap)
{
    // Encrypt or Decrypt a block of data
    // Input:
    //     argsObj: {
    //         algorithm: object; the encryption algorithm name, "RSAES-PKCS1-v1_5" only
    //         -- or --
    //         algorithm: {
    //             name:    string; the encryption algorithm name, "AES-CBC"
    //             params: {
    //                 iv:  string; the initialization vector, base64-encoded
    //             }
    //         }
    //         -- or --
    //         algorithm: {
    //             name:    string; the encryption algorithm name, "AES-GCM" only
    //             params: {
    //                 iv:  string; the initialization vector, base64-encoded
    //                 additionalData: string; additional authentication data to include, base64-encoded
    //                 tagLength: string; desired length of the authentication tag. May be 0 - 128.
    //             }
    //         }
    //         keyHandle: string, the handle of the key to use
    //         buffer:    string, the data to encrypt, base64-encoded
    //     }
    // Output:
    //     payload: {
    //         buffer:    string, the ciphertext, base64-encoded
    //     }

    // get algorithm
    Variant algObj;
    if (!getAlgorithmObj(argsVar, algObj))
    {
        sendError(cmdIndex, CAD_ERR_UNKNOWN_ALGO);  // FIXME: better error
        return false;
    }
    const CadmiumCrypto::Algorithm algType = toAlgorithm(algObj["name"].string());
    DLOG() << "\talgorithm: " << toString(algType) << endl;

    // get key handle
    int keyHandle;
    if (!getVal<int>(argsVar, "keyHandle", cmdIndex, keyHandle))
        return false;
    DLOG() << "\tkeyHandle: " << keyHandle << endl;

    // get data to encrypt
    string dataStr64;
    if (!getVal<string>(argsVar, "buffer", cmdIndex, dataStr64))
        return false;
    DLOG() << "\tbuffer: " << truncateLong(dataStr64) << endl;

    bool doEncrypt;
    getVal<bool>(argsVar, "doEncrypt", cmdIndex, doEncrypt);
    string resultData64;
    if (algType == CadmiumCrypto::RSAES_PKCS1_V1_5 || algType == CadmiumCrypto::RSA_OAEP)
    {
        // do the operation
        CadErr err;
        if (doEncrypt)
            err = cadmiumCrypto_->rsaCrypt(keyHandle, dataStr64, CadmiumCrypto::DOENCRYPT, resultData64);
        else
            err = cadmiumCrypto_->rsaCrypt(keyHandle, dataStr64, CadmiumCrypto::DODECRYPT, resultData64);
        if (isError(err, cmdIndex))
            return false;
    }
    else if (algType == CadmiumCrypto::AES_CBC || algType == CadmiumCrypto::AES_GCM)
    {
        // get initialization vector
        if (!algObj.contains("params") && !algObj["params"].contains("iv"))
        {
            DLOG() << "ERROR: algorithm missing iv algorithm param\n";
            sendError(cmdIndex, CAD_ERR_UNKNOWN_ALGO);  // FIXME: better error
            return false;
        }
        string ivStr64;
        if (!getVal<string>(algObj["params"], "iv", cmdIndex, ivStr64))
            return false;
        DLOG() << "\tiv: " << truncateLong(ivStr64) << endl;

        if (algType == CadmiumCrypto::AES_CBC)
        {
            // do the operation
            CadErr err =
                cadmiumCrypto_->aesCbc(keyHandle, ivStr64, dataStr64,
                    doEncrypt ? CadmiumCrypto::DOENCRYPT : CadmiumCrypto::DODECRYPT,
                    resultData64);
            if (isError(err, cmdIndex))
                return false;
        }
        else // algType == CadmiumCrypto::AES_GCM
        {
            // get the additional authentication data
            string aadStr64;
            if (!getVal<string>(algObj["params"], "additionalData", cmdIndex, aadStr64))
            {
                DLOG() << "ERROR: algorithm missing additionalData algorithm param\n";
                sendError(cmdIndex, CAD_ERR_UNKNOWN_ALGO);  // FIXME: better error
                return false;
            }
            DLOG() << "\tadditionalData: " << truncateLong(aadStr64) << endl;

            // get the taglength
            int taglenBytes;
            if (!getVal<int>(algObj["params"], "tagLength", cmdIndex, taglenBytes))
            {
                DLOG() << "ERROR: algorithm missing tagLength algorithm param\n";
                sendError(cmdIndex, CAD_ERR_UNKNOWN_ALGO);  // FIXME: better error
                return false;
            }
            if (taglenBytes < 0 || taglenBytes > 128)
            {
                DLOG() << "ERROR: taglength outside valid range\n";
                sendError(cmdIndex, CAD_ERR_BADARG);  // FIXME: better error
                return false;
            }
            DLOG() << "\ttaglength: " << taglenBytes << endl;

            // do the operation
            // Note: authentication tag is the last taglenBytes of resultData
            // (encrypt), or dataStr (encrypt)
            CadErr err =
                cadmiumCrypto_->aesGcm(keyHandle, ivStr64, dataStr64, aadStr64,
                    taglenBytes, doEncrypt ? CadmiumCrypto::DOENCRYPT : CadmiumCrypto::DODECRYPT,
                    resultData64);
            if (isError(err, cmdIndex))
                return false;
        }
    }
    else
    {
        sendError(cmdIndex, CAD_ERR_UNKNOWN_ALGO);
        return false;
    }

    // return the result
    returnVarMap["payload"]["buffer"] = resultData64;
    setSuccess(returnVarMap);

    return true;
}

bool NativeBridge::sign(const string& cmdIndex, Variant& argsVar,
        VariantMap& returnVarMap)
{
    argsVar["doSign"] = true;
    return signVerify(cmdIndex, argsVar, returnVarMap);
}

bool NativeBridge::verify(const string& cmdIndex, Variant& argsVar,
        VariantMap& returnVarMap)
{
    argsVar["doSign"] = false;
    return signVerify(cmdIndex, argsVar, returnVarMap);
}

bool NativeBridge::signVerify(const string& cmdIndex, Variant& argsVar,
        VariantMap& returnVarMap)
{
    // ------------ sign / verify --------------
    // Sign a block of data with a specific algorithm using the provided key
    // Input:
    //     argsObj: {
    //         algorithm: {
    //             name:    string; the sign algorithm name, only "HMAC" for now
    //             params: {
    //                 hash:  algorithm; the inner hash function to use
    //             }
    //         }
    //         keyHandle: string, the handle of the key to use
    //         buffer:    string, the data to sign, base64-encoded
    //     }
    //
    // Output:
    // --- sign
    //     payload: {
    //         buffer:    string, the signature, base64-encoded
    //     }
    // --- verify
    // Output:
    //     payload: bool, true if verified

    // extract normalized algorithm object
    Variant algObj;
    if (!getAlgorithmObj(argsVar, algObj))
    {
        sendError(cmdIndex, CAD_ERR_UNKNOWN_ALGO);  // FIXME: better error
        return false;
    }

    // check algorithm
    const CadmiumCrypto::Algorithm algType = toAlgorithm(algObj["name"].string());
    DLOG() << "\talgorithm " << toString(algType) << endl;
    if ( (algType != CadmiumCrypto::HMAC) && (algType != CadmiumCrypto::RSASSA_PKCS1_V1_5) )
    {
        DLOG() << "NativeBridge::signVerify: require HMAC or RSASSA_PKCS1_V1_5 algorithm\n";
        sendError(cmdIndex, CAD_ERR_UNKNOWN_ALGO);
        return false;
    }

    // check inner hash algorithm
    if (!checkHash(algObj))
    {
        sendError(cmdIndex, CAD_ERR_UNKNOWN_ALGO);
        return false;
    }
    const CadmiumCrypto::Algorithm hashType =
        toAlgorithm(algObj["params"]["hash"]["name"].string());

    // get key handle
    int keyHandle;
    if (!getVal<int>(argsVar, "keyHandle", cmdIndex, keyHandle))
        return false;
    DLOG() << "\tkeyHandle: " << keyHandle << endl;

    // get the data
    string dataStr64;
    getVal<string>(argsVar, "buffer", cmdIndex, dataStr64, false);
    DLOG() << "\tbuffer: " << truncateLong(dataStr64) << endl;

    if (argsVar.mapValue<bool>("doSign"))
    {
        return doSign(cmdIndex, keyHandle, algType, hashType, dataStr64, returnVarMap);
    }
    else
    {
        // get the signature
        string sigStr64;
        if (!getVal<string>(argsVar, "signature", cmdIndex, sigStr64))
            return false;
        DLOG() << "\tsignature: " << truncateLong(sigStr64) << endl;
        return doVerify(cmdIndex, keyHandle, algType, hashType, dataStr64, sigStr64, returnVarMap);
    }
}

bool NativeBridge::doSign(const string& cmdIndex, int keyHandle,
        CadmiumCrypto::Algorithm algType, CadmiumCrypto::Algorithm hashType,
        const string& dataStr64, VariantMap& returnVarMap)
{
    // compute the signature
    string sigStr64;
    CadErr err = CAD_ERR_OK;
    if (algType == CadmiumCrypto::HMAC)
        err = cadmiumCrypto_->hmac(keyHandle, hashType, CadmiumCrypto::SIGN, dataStr64, sigStr64);
    else if (algType == CadmiumCrypto::RSASSA_PKCS1_V1_5)
        err = cadmiumCrypto_->rsaSign(keyHandle, hashType, dataStr64, sigStr64);
    else
        assert(false);
    if (isError(err, cmdIndex))
        return false;

    DLOG() << "\tresult signature: " << sigStr64 << endl;
    returnVarMap["payload"]["buffer"] = sigStr64;
    setSuccess(returnVarMap);

    return true;
}

bool NativeBridge::doVerify(const string& cmdIndex, int keyHandle,
        CadmiumCrypto::Algorithm algType, CadmiumCrypto::Algorithm hashType,
        const string& dataStr64, const string& sigStr64,
        VariantMap& returnVarMap)
{
    bool isVerified = false;
    if (algType == CadmiumCrypto::HMAC)
    {
        // compute the HMAC
        string hashStr64;
        CadErr err = cadmiumCrypto_->hmac(keyHandle, hashType, CadmiumCrypto::VERIFY, dataStr64, hashStr64);
        if (isError(err, cmdIndex))
            return false;
        isVerified = (hashStr64 == sigStr64);
        DLOG() << "\tcomputed signature: " << hashStr64 << (isVerified ? "" : " does not") << " match\n";
    }
    else if (algType == CadmiumCrypto::RSASSA_PKCS1_V1_5)
    {
        CadErr err = cadmiumCrypto_->rsaVerify(keyHandle, hashType, dataStr64, sigStr64, isVerified);
        if (isError(err, cmdIndex))
            return false;
    }
    else
        assert(false);

    returnVarMap["payload"] = isVerified;
    setSuccess(returnVarMap);

    return true;
}

bool NativeBridge::generate(const string& cmdIndex, Variant& argsVar,
        VariantMap& returnVarMap)
{
    // {"format":null,"keyData":null,"algorithm":{"name":"RSASSA-PKCS1-v1_5","params":{"modulusLength":512,"publicExponent":"AQAB"}}}

    // ------------ generate --------------
    // Generate key(s)
    // Input:
    //     argsObj: {
    //         algorithm: {
    //             name:    string; the algorithm for which this key will be used
    //             params:  object; algorithm-specific parameters
    //         }
    //         extractable: boolean; whether or not the raw keying material
    //                        may be exported by the application (optional)
    //         keyUsage:   Array of strings from the set "encrypt", "decrypt",
    //                        "sign", "verify", "derive"; indicates what
    //                        operations may be used with this key (optional)
    //     }
    // Output:
    //     payload: {
    //         publicKey: {
    //             handle:      the handle of this key in the key store
    //             type:        string; "public"
    //             extractable: string; same as input if present else false
    //             algorithm:   object; name of the input algorithm
    //             keyUsage:   Array of strings; same as input if present else empty
    //         }
    //         privateKey: {
    //             handle:      the handle of this key in the key store
    //             type:        string; "private"
    //             extractable: string; same as input if present else false
    //             algorithm:   object; name of the input algorithm
    //             keyUsage:   Array of strings; same as input if present else empty
    //         }

    // extract normalized algorithm object
    Variant algObj;
    if (!getAlgorithmObj(argsVar, algObj))
    {
        sendError(cmdIndex, CAD_ERR_UNKNOWN_ALGO);  // FIXME: better error
        return false;
    }
    const CadmiumCrypto::Algorithm algType = toAlgorithm(algObj["name"].string());

    // All algorithms besides the special SYSTEM alg must have a params field
    if (algType != CadmiumCrypto::SYSTEM && !algObj.contains("params"))
    {
        DLOG() << "NativeBridge::generate: algorithm missing 'params' field\n";
        sendError(cmdIndex, CAD_ERR_UNKNOWN_ALGO);  // FIXME: better error
        return false;
    }

    // get (optional) extractable; if not present default to false
    bool extractable;
    if (!getVal<bool>(argsVar, "extractable", cmdIndex, extractable, false))
        extractable = false;
    DLOG() << "\textractable: " << boolalpha << extractable << noboolalpha << endl;

    // get (optional) keyUsage; if not present leave empty
    bool isFound;
    VariantArray keyUsageVarAry = argsVar.mapValue<VariantArray>("keyUsage", &isFound);
    vector<CadmiumCrypto::KeyUsage> keyUsageVec;
    if (isFound)
        keyUsageVec = toKeyUsageVec(keyUsageVarAry);
    DLOG() << "\tkeyUsage: " << toString(keyUsageVec) << endl;

    if (isAlgorithmRsa(algType) || isAlgorithmDh(algType))
    {
        // Do the key generation
        uint32_t pubKeyHandle;
        uint32_t privKeyHandle;
        CadErr err;
        if (isAlgorithmDh(algType))
        {
            DLOG() << "\tDH generate key pair\n";
            err = cadmiumCrypto_->dhKeyGen(algObj, extractable, keyUsageVec,
                pubKeyHandle, privKeyHandle);
        }
        else
        {
            DLOG() << "\tRSA generate key pair\n";
            err = cadmiumCrypto_->rsaKeyGen(algObj, extractable, keyUsageVec,
                pubKeyHandle, privKeyHandle);
        }
        if (isError(err, cmdIndex))
            return false;

        // Make the final output public and private key objects
        VariantMap publicKey;
        if (!keyHandleToKeyVarMap(pubKeyHandle, publicKey))
        {
            sendError(cmdIndex, CAD_ERR_INTERNAL);  // FIXME better error
            return false;
        }
        VariantMap privateKey;
        if (!keyHandleToKeyVarMap(privKeyHandle, privateKey))
        {
            sendError(cmdIndex, CAD_ERR_INTERNAL);  // FIXME better error
            return false;
        }
        returnVarMap["payload"]["publicKey"]   = publicKey;
        returnVarMap["payload"]["privateKey"]  = privateKey;
    }
    else if (isAlgorithmAes(algType) || isAlgorithmHmac(algType))
    {
        // for HMAC, additionally validate we have an innner hash specified
        if (isAlgorithmHmac(algType))
        {
            // check inner hash algorithm
            if (!checkHash(algObj))
            {
                sendError(cmdIndex, CAD_ERR_UNKNOWN_ALGO);
                return false;
            }
        }

        // generate a random key
        uint32_t keyHandle;
        CadErr err = cadmiumCrypto_->symKeyGen(algObj, extractable, keyUsageVec,
                keyHandle);
        if (isError(err, cmdIndex))
            return false;

        // make the final output key object
        VariantMap keyObj;
        if (!keyHandleToKeyVarMap(keyHandle, keyObj))
        {
            sendError(cmdIndex, CAD_ERR_INTERNAL);  // FIXME better error
            return false;
        }
        returnVarMap["payload"] = keyObj;
    }
    else if (algType == CadmiumCrypto::SYSTEM)
    {
        uint32_t keyHandle;
        CadErr err = cadmiumCrypto_->getSystemKeyHandle(keyHandle);
        if (isError(err, cmdIndex))
            return false;
        VariantMap keyObj;
        if (!keyHandleToKeyVarMap(keyHandle, keyObj))
        {
            sendError(cmdIndex, CAD_ERR_INTERNAL);  // FIXME better error
            return false;
        }
        returnVarMap["payload"] = keyObj;
    }
    else
        assert(false);  // should never get here

    setSuccess(returnVarMap);
    return true;
}

bool NativeBridge::derive(const string& cmdIndex, Variant& argsVar,
        VariantMap& returnVarMap)
{
    // return createKeyOp(  null,    null, algorithm, extractable, keyUsage, baseKeyHandle, derivedKeyAlgorithm, null)
    // var createKeyOp = (format, keyData, algorithm, extractable, keyUsage, baseKey, derivedKeyType,      key)

    // ------------ deriveKey --------------
    // Derive a key. Only used for Diffie-Hellman second phase for now
    // Input:
    //     argsObj: {
    //         algorithm:   object; contains algorithm info required to derive
    //                      the key
    //         baseKeyHandle: string, the handle of the key associated with the
    //                        key derivation
    //         derivedAlgorithm: object; contains the algorithm info to be
    //                              associated with the derived key
    //         extractable: boolean; the extractable value to be applied to the
    //                       derived key (optional)
    //         keyUsage:   Array of strings from the set "encrypt", "decrypt",
    //                        "sign", "verify", "derive"; indicates what
    //                        operations may be used with the derived key (optional)
    //     }
    // Output:
    //     payload: {
    //         handle:      the handle of the derived key in the key store
    //         type:        string; one of "secret", "public", "private"
    //         algorithm:   object; set to input derivedKeyAlgorithm
    //         extractable: boolean; set to input extractable
    //         keyUsage:   Array of strings; set to input keyUsage
    //     }

    // extract normalized algorithm object and validate
    Variant algObj;
    if (!getAlgorithmObj(argsVar, algObj))
    {
        sendError(cmdIndex, CAD_ERR_UNKNOWN_ALGO);  // FIXME: better error
        return false;
    }
    const CadmiumCrypto::Algorithm algType = toAlgorithm(algObj["name"].string());
    if (!isAlgorithmDh(algType))
    {
        DLOG() << "NativeBridge::derive: algorithm must be DH\n";
        sendError(cmdIndex, CAD_ERR_UNKNOWN_ALGO);  // FIXME: better error
        return false;
    }
    if (!algObj.contains("params") || !algObj["params"].contains("public"))
    {
        DLOG() << "NativeBridge::derive: algorithm missing params or params:public\n";
        sendError(cmdIndex, CAD_ERR_UNKNOWN_ALGO);  // FIXME: better error
        return false;
    }

    // extract the peer public key raw data
    const string peerKeyStr64 = algObj["params"]["public"].string();
    if (peerKeyStr64.empty())
    {
        DLOG() << "NativeBridge::derive: missing peer key data\n";
        sendError(cmdIndex, CAD_ERR_INTERNAL);  // FIXME: better error
        return false;
    }
    DLOG() << "\tpeer key = " << peerKeyStr64 << endl;

    // get baseKeyHandle
    int baseKeyHandle;
    if (!getVal<int>(argsVar, "baseKeyHandle", cmdIndex, baseKeyHandle))
        return false;
    DLOG() << "\tbaseKeyHandle: " << baseKeyHandle << endl;

    // extract normalized derivedKeyAlgorithm object
    Variant derivedAlgObj;
    if (!getAlgorithmObj(argsVar, derivedAlgObj, "derivedAlgorithm"))
    {
        sendError(cmdIndex, CAD_ERR_UNKNOWN_ALGO);  // FIXME: better error
        return false;
    }
    const CadmiumCrypto::Algorithm derivedAlgType = toAlgorithm(derivedAlgObj.mapValue<string>("name"));
    DLOG() << "\talgorithm for derived key = " << toString(derivedAlgType) << endl;

    // get (optional) derived extractable; if not present default to false
    bool extractable;
    if (!getVal<bool>(argsVar, "extractable", cmdIndex, extractable, false))
        extractable = false;
    DLOG() << "\textractable for derived key: " << boolalpha << extractable << noboolalpha << endl;

    // get (optional) derived keyUsage; if not present leave empty
    bool isFound;
    VariantArray keyUsageVarAry = argsVar.mapValue<VariantArray>("keyUsage", &isFound);
    vector<CadmiumCrypto::KeyUsage> keyUsageVec;
    if (isFound)
        keyUsageVec = toKeyUsageVec(keyUsageVarAry);
    DLOG() << "\tkeyUsage for derived key: " << toString(keyUsageVec) << endl;

    // do the key derive
    uint32_t keyHandle;
    CadErr err = cadmiumCrypto_->dhDerive(baseKeyHandle, peerKeyStr64,
            derivedAlgObj, extractable, keyUsageVec, keyHandle);
    if (isError(err, cmdIndex))
        return false;

    // make the final output key object from the new key in the store
    VariantMap keyObj;
    if (!keyHandleToKeyVarMap(keyHandle, keyObj))
    {
        sendError(cmdIndex, CAD_ERR_INTERNAL);  // FIXME better error
        return false;
    }
    returnVarMap["payload"] = keyObj;

    setSuccess(returnVarMap);
    return true;
}

bool NativeBridge::unwrapKey(const string& cmdIndex, Variant& argsVar,
        VariantMap& returnVarMap)
{
    // return createKeyOp(  null, jweKeyData, algorithm, extractable,     usage,    null,           null, wrappingKey);
    // var createKeyOp = (format,    keyData, algorithm, extractable, keyUsage, baseKey, derivedKeyType,         key)

    // ------------ unwrapKey --------------
    // Unwrap a wrapped key
    // Input:
    //     argsObj: {
    //         keyData:     string; JWE Compact Serialization, base64 encoded
    //         keyHandle:   string, the handle of the key with which to decrypt
    //                      the Content Master Key
    //         algorithm:   object; in case the unwrapped JWK does not have an
    //                      'alg' field, use this, otherwise ignore (optional)
    //         extractable: boolean; in case the unwrapped JWK does not have an
    //                      'extractable field, use this, otherwise ignore
    //                      (optional)
    //         keyUsage:   Array of strings from the set "encrypt", "decrypt",
    //                      "sign", "verify", "derive"; in case the unwrapped
    //                      JDK does not have a 'use' field, use this, otherwise
    //                      ignore (optional)
    //     }
    // Output:
    //     payload: {
    //         handle:      the handle of the unwrapped key in the key store
    //         type:        string; one of "secret", "public", "private"
    //         algorithm:   object; set to the value inside the wrapped key
    //         extractable: string; resolved between input value and value inside
    //                        the wrapped key
    //         keyUsage:   Array of strings; resolved between input value and value
    //                        inside the wrapped key
    //     }

    // get key handle
    int keyHandle;
    if (!getVal<int>(argsVar, "keyHandle", cmdIndex, keyHandle))
        return false;
    DLOG() << "\tkeyHandle: " << keyHandle << endl;

    // get keyData
    string keyDataStr;
    if (!getVal<string>(argsVar, "keyData", cmdIndex, keyDataStr))
        return false;
    DLOG() << "\tkeyData: " << truncateLong(keyDataStr) << endl;

    // get (optional) algorithm
    Variant algObj;
    if (!getAlgorithmObj(argsVar, algObj))
    {
        sendError(cmdIndex, CAD_ERR_UNKNOWN_ALGO);
        return false;
    }
    // this API allows a null object for the algorithm
    if (algObj.isNull())
        DLOG() << "\talgorithm: null\n";
    else
        DLOG() << "\talgorithm: " << toString(toAlgorithm(algObj["name"].string())) << endl;

    // get (optional) extractable; if not present default to false
    bool extractable;
    if (!getVal<bool>(argsVar, "extractable", cmdIndex, extractable, false))
        extractable = false;
    DLOG() << "\textractable: " << boolalpha << extractable << noboolalpha << endl;

    // get (optional) keyUsage; if not present leave empty
    bool isFound;
    VariantArray keyUsageVarAry = argsVar.mapValue<VariantArray>("keyUsage", &isFound);
    vector<CadmiumCrypto::KeyUsage> keyUsageVec;
    if (isFound)
        keyUsageVec = toKeyUsageVec(keyUsageVarAry);
    DLOG() << "\tkeyUsage: " << toString(keyUsageVec) << endl;

    uint32_t unwrappedKeyHandle;
    CadErr err = cadmiumCrypto_->unwrapJwe(keyDataStr, keyHandle, algObj,
            extractable, keyUsageVec, unwrappedKeyHandle);
    if (isError(err, cmdIndex))
        return false;

    // Make the final output key object
    VariantMap keyVarMap;
    if (!keyHandleToKeyVarMap(unwrappedKeyHandle, keyVarMap))
    {
        sendError(cmdIndex, CAD_ERR_INTERNAL);  // FIXME better error
        return false;
    }

    // return the result
    returnVarMap["payload"] = keyVarMap;
    setSuccess(returnVarMap);

    return true;
}

bool NativeBridge::wrapKey(const string& cmdIndex, Variant& argsVar,
        VariantMap& returnVarMap)
{
    // return createKeyOp('wrapKey', null,   null,    wrappingAlgorithm, null,        null,      keyToWrap, null,           wrappingKey);
    // var createKeyOp = (type,      format, keyData, algorithm,         extractable, keyUsage, baseKey,   derivedKeyType, key        )

    // Wrap an existing key
    // Input:
    //     argsObj: {
    //         algorithm: object; the algorithm with which to wrap the baseKey
    //         baseKeyHandle: string, the handle of the key that will be wrapped
    //         keyHandle: string, The handle of the key to wrap the baseKey with.
    //             This algorithm associated with this key must match the
    //             'algorithm' parameter.
    //     }
    // Output:
    //     payload: {
    //         buffer: string; JWE Compact Serialization of the wrapped key,
    //             base64 encoded
    //     }

    // get (optional) algorithm
    Variant wrappingAlgoObj;
    if (!getAlgorithmObj(argsVar, wrappingAlgoObj))
    {
        sendError(cmdIndex, CAD_ERR_UNKNOWN_ALGO);
        return false;
    }
    // this API allows a null object for the algorithm
    if (wrappingAlgoObj.isNull())
        DLOG() << "\talgorithm: null\n";
    else
        DLOG() << "\talgorithm: " << toString(toAlgorithm(wrappingAlgoObj["name"].string())) << endl;

    // get handle of the wrapping key
    int wrappingKeyHandle;
    if (!getVal<int>(argsVar, "keyHandle", cmdIndex, wrappingKeyHandle))
        return false;
    DLOG() << "\twrap-or key handle: " << wrappingKeyHandle << endl;

    // get handle of the key to be wrapped
    int toBeWrappedKeyHandle;
    if (!getVal<int>(argsVar, "baseKeyHandle", cmdIndex, toBeWrappedKeyHandle))
        return false;
    DLOG() << "\twrap-ee key handle: " << toBeWrappedKeyHandle << endl;

    string wrappedKeyJcs;
    CadErr err = cadmiumCrypto_->wrapJwe(toBeWrappedKeyHandle, wrappingKeyHandle,
            wrappingAlgoObj, CadmiumCrypto::A128GCM, wrappedKeyJcs);
    if (isError(err, cmdIndex))
        return false;

    // return the result
    returnVarMap["payload"]["buffer"] = wrappedKeyJcs;
    setSuccess(returnVarMap);

    return true;
}

bool NativeBridge::getDeviceId(const string& cmdIndex, Variant& argsVar,
        VariantMap& returnVarMap)
{
    // Return this device's ID string
    // Input:
    //     argsObj: {<empty>}
    // Output:
    //     payload: {
    //         buffer: string; deviceId
    //     }

    string deviceIdStr;
    CadErr err = cadmiumCrypto_->getDeviceId(deviceIdStr);
    if (isError(err, cmdIndex))
        return false;
    returnVarMap["payload"]["buffer"] = deviceIdStr;
    setSuccess(returnVarMap);
    return true;
}

bool NativeBridge::getKeyByName(const string& cmdIndex, Variant& argsVar,
        VariantMap& returnVarMap)
{
    // return createKeyOp('getKeyByName', null,   null,    null,      null,        null,     null,    null,           null, keyName);
    // var createKeyOp = (type,           format, keyData, algorithm, extractable, keyUsage, baseKey, derivedKeyType, key,  keyName)

    // Return a pre-provisioned NamedKey. Fails if the named key is not present.
    // Input:
    //     argsObj: {
    //         keyName: string; the name of the pre-provisioned key
    //     }
    // Output:
    //     payload: {
    //         handle:      the handle of the derived key in the key store
    //         type:        string; one of "secret", "public", "private"
    //         algorithm:   object; set to input derivedKeyAlgorithm
    //         extractable: boolean; set to input extractable
    //         keyUsage:    Array of strings; set to input keyUsage
    //         name:        A local identifier for the key, same as input
    //         id:          A global identifier associated with the key, base64-encoded.
    //                        Usually this is something like an ESN.
    //     }

    // get the input key name
    string name;;
    if (!getVal<string>(argsVar, "keyName", cmdIndex, name))
        return false;
    DLOG() << "\tname: " << name << endl;

    // get the handle and metadata of this named key
    uint32_t keyHandle;
    string metadata;
    CadErr err = cadmiumCrypto_->getKeyByName(name, keyHandle, metadata);
    if (isError(err, cmdIndex))
        return false;

    // build a NamedKey object
    VariantMap keyObj;
    if (!keyHandleToKeyVarMap(keyHandle, keyObj))
    {
        sendError(cmdIndex, CAD_ERR_INTERNAL);  // FIXME better error
        return false;
    }
    keyObj["name"] = name;
    keyObj["id"] = metadata;

    // return the result
    returnVarMap["payload"] = keyObj;
    setSuccess(returnVarMap);
    return true;
}

template <typename T>
bool NativeBridge::getVal(const Variant& args, const char * varName,
        const string& cmdIndex, T& out, bool doSendErr)
{
    bool isFound;
    out = args.mapValue<T>(varName, &isFound);
    if (!isFound && doSendErr)
        sendError(cmdIndex, CAD_ERR_BADARG);
    return isFound;
}

bool NativeBridge::isError(uint32_t errCode, const string& cmdIndex)
{
    if (errCode != CAD_ERR_OK)
    {
        sendError(cmdIndex, errCode);
        return true;
    }
    return false;
}

void NativeBridge::sendError(const string& cmdIndex, uint32_t errCode)
{
    VariantMap variantMap;
    variantMap["idx"] = cmdIndex;
    variantMap["success"] = false;
    variantMap["errorMessage"] = CadErrStr[errCode];
    variantMap["errorCode"] = errCode;
    variantMap["payload"] = VariantMap();
    send(variantMap);
}

void NativeBridge::send(const Variant& data)
{
    FUNCTIONSCOPELOG;
    JSONFormatter jsonFormatter;
    string serializedMsg = jsonFormatter.format(data);
    postMessage(serializedMsg);
}

void NativeBridge::postMessageCb(int32_t /*result*/, const string& json)
{
    FUNCTIONSCOPELOG;
    assert(isMainThread());
    DLOG() << "NativeBridge::postMessage(): " << thinJsonMessage(json) << endl;
    pInstance_->PostMessage(pp::Var(json));
}

bool NativeBridge::keyHandleToKeyVarMap(uint32_t keyHandle, VariantMap& keyVarMap)
{
    CadmiumCrypto::KeyType keyType;
    bool extractable;
    Variant algVar;
    std::vector<CadmiumCrypto::KeyUsage> keyUsageVec;
    CadErr err = cadmiumCrypto_->getKeyInfo(keyHandle, keyType, extractable, algVar, keyUsageVec);
    if (err != CAD_ERR_OK)
        return false;
    keyVarMap["handle"]      = keyHandle;
    keyVarMap["type"]        = toString(keyType);
    keyVarMap["extractable"] = extractable;
    keyVarMap["algorithm"]   = algVar;
    keyVarMap["keyUsage"]    = toKeyUsageVarAry(keyUsageVec);
    return true;
}

} // namespace cadmium
