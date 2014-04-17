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

(function (window) {
    'use strict';

    var nfCrypto = {subtle: {}};
    var nfCryptokeys = {};
    
    var nfOldCrypto = window.nfCrypto;
    var nfOldCryptokeys = window.nfCryptokeys;
    
    if (nfOldCrypto && nfOldCrypto.subtle) {
        window.nfCrypto = nfCrypto;
    }
    if (nfOldCryptokeys) {
        window.nfCryptokeys = nfCryptokeys;
    }

    nfCrypto.subtle.digest = function (algorithm, buffer) {
        return new Promise(function(resolve, reject) {
            var op = nfOldCrypto.subtle.digest(algorithm, buffer);
            op.oncomplete = function (e) {
                resolve(e.target.result);
            };
            op.onerror = function (e) {
                reject(new TypeError);
            };
        })
    }

    nfCrypto.subtle.importKey = function (format, keyData, algorithm, extractable, keyUsage) {
        return new Promise(function(resolve, reject) {
            var op = nfOldCrypto.subtle.importKey(format, keyData, algorithm, extractable, keyUsage);
            op.oncomplete = function (e) {
                resolve(e.target.result);
            };
            op.onerror = function (e) {
                reject(new TypeError);
            };
        })
    };

    nfCrypto.subtle.exportKey = function (format, key) {
        return new Promise(function(resolve, reject) {
            var op = nfOldCrypto.subtle.exportKey(format, key);
            op.oncomplete = function (e) {
                var res = e.target.result;
                resolve(res);
            };
            op.onerror = function (e) {
                reject(new TypeError);
            };
        })
    };

    nfCrypto.subtle.encrypt = function (algorithm, key, buffer) {
        return new Promise(function(resolve, reject) {
            var op = nfOldCrypto.subtle.encrypt(algorithm, key, buffer);
            op.oncomplete = function (e) {
                resolve(e.target.result);
            };
            op.onerror = function (e) {
                reject(new TypeError);
            };
        })
    };

    nfCrypto.subtle.decrypt = function (algorithm, key, buffer) {
        return new Promise(function(resolve, reject) {
            var op = nfOldCrypto.subtle.decrypt(algorithm, key, buffer);
            op.oncomplete = function (e) {
                resolve(e.target.result);
            };
            op.onerror = function (e) {
                reject(new TypeError);
            };
        })
    };

    nfCrypto.subtle.sign = function (algorithm, key, buffer) {
        return new Promise(function(resolve, reject) {
            var op = nfOldCrypto.subtle.sign(algorithm, key, buffer);
            op.oncomplete = function (e) {
                resolve(e.target.result);
            };
            op.onerror = function (e) {
                reject(new TypeError);
            };
        })
    };

    nfCrypto.subtle.verify = function (algorithm, key, signature, buffer) {
        return new Promise(function(resolve, reject) {
            var op = nfOldCrypto.subtle.verify(algorithm, key, signature, buffer);
            op.oncomplete = function (e) {
                resolve(e.target.result);
            };
            op.onerror = function (e) {
                reject(new TypeError);
            };
        })
    };

    nfCrypto.subtle.generateKey = function (algorithm, extractable, keyUsage) {
        return new Promise(function(resolve, reject) {
            var op = nfOldCrypto.subtle.generateKey(algorithm, extractable, keyUsage);
            op.oncomplete = function (e) {
                resolve(e.target.result);
            };
            op.onerror = function (e) {
                reject(new TypeError);
            };
        })
    };

    nfCrypto.subtle.deriveKey = function (algorithm, baseKey, derivedKeyAlgorithm, extractable, keyUsage) {
        return new Promise(function(resolve, reject) {
            var op = nfOldCrypto.subtle.deriveKey(algorithm, baseKey, derivedKeyAlgorithm, extractable, keyUsage);
            op.oncomplete = function (e) {
                resolve(e.target.result);
            };
            op.onerror = function (e) {
                reject(new TypeError);
            };
        })
    };

    nfCrypto.subtle.wrapKey = function (format, keyToWrap, wrappingKey, wrappingAlgorithm) {
        return new Promise(function(resolve, reject) {
            var op = nfOldCrypto.subtle.wrapKey(format, keyToWrap, wrappingKey, wrappingAlgorithm);
            op.oncomplete = function (e) {
                resolve(e.target.result);
            };
            op.onerror = function (e) {
                reject(new TypeError);
            };
        })
    };
    
    nfCrypto.subtle.unwrapKey = function (format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, usage) {
        return new Promise(function(resolve, reject) {
            var op = nfOldCrypto.subtle.unwrapKey(format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, usage);
            op.oncomplete = function (e) {
                resolve(e.target.result);
            };
            op.onerror = function (e) {
                reject(new TypeError);
            };
        })
    };
    
    nfCryptokeys.getKeyByName = function (keyName) {
        return new Promise(function(resolve, reject) {
            var op = nfOldCryptokeys.getKeyByName(keyName);
            op.oncomplete = function (e) {
                resolve(e.target.result);
            };
            op.onerror = function (e) {
                reject(new TypeError);
            };
        })
    };
    
    nfCrypto.getRandomValues = nfOldCrypto.getRandomValues;

})(window);
