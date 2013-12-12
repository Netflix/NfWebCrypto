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

/*
Some of the code in this one source file borrows from PolyCrypt (polycrypt.net).
A big thank you to the folks at Raytheon BBN Technologies for providing source
inspiration for this javascript-challenged programmer.

The PolyCrypt license follows:

Copyright (C) Raytheon BBN Technologies Corp. 2013 All Rights Reserved.

Development of this software program, WHAC, is sponsored by the Cyber Security
Division of the United States Department of Homeland Security's Science and
Technology Directorate. 

This software is licensed pursuant to the following license terms and
conditions: Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
(1) Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer. (2) Redistributions in binary
form must reproduce the above copyright notice, this list of conditions and the
following disclaimer in the documentation and/or other materials provided with
the distribution. (3) Neither the name of Raytheon BBN Technologies Corp. nor
the names of its contributors may be used to endorse or promote products derived
from this software without specific prior written permission. 

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS  "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT  LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 

End of (PolyCrypt) License Terms and Conditions.
*/

(function (window) {
    'use strict';

    var that = {};
    var nfCrypto = window.nfCrypto.subtle;

    // public api root
    window.nfNewCrypto = window.nfCrypto;
    window.nfNewCrypto.subtle = that;

    that.digest = function (algorithm, buffer) {
        return new Promise(function(resolve, reject) {
            var op = nfCrypto.digest(algorithm, buffer);
            op.oncomplete = function (e) {
                resolve(e.target.result);
            };
            op.onerror = function (e) {
                reject(new TypeError);
            };
        })
    }
    

    that.importKey = function (format, keyData, algorithm, extractable, keyUsage) {
        if (format == "jwk") {
            var str = latin1.stringify(keyData);
            var newstr = str.replace("ext","extractable");
            keyData = latin1.parse(newstr);
        }
        return new Promise(function(resolve, reject) {
            var op = nfCrypto.importKey(format, keyData, algorithm, extractable, keyUsage);
            op.oncomplete = function (e) {
                resolve(e.target.result);
            };
            op.onerror = function (e) {
                reject(new TypeError);
            };
        })
    };

    that.exportKey = function (format, key) {
        return new Promise(function(resolve, reject) {
            var op = nfCrypto.exportKey(format, key);
            op.oncomplete = function (e) {
                var res = e.target.result;
                var str = latin1.stringify(res);
                if (str.search("extractable")) {
                    var newstr = str.replace("extractable", "ext");
                    res = latin1.parse(newstr);
                }
                resolve(res);
            };
            op.onerror = function (e) {
                reject(new TypeError);
            };
        })
    };

    that.encrypt = function (algorithm, key, buffer) {
        return new Promise(function(resolve, reject) {
            var op = nfCrypto.encrypt(algorithm, key, buffer);
            op.oncomplete = function (e) {
                resolve(e.target.result);
            };
            op.onerror = function (e) {
                reject(new TypeError);
            };
        })
    };

    that.decrypt = function (algorithm, key, buffer) {
        return new Promise(function(resolve, reject) {
            var op = nfCrypto.decrypt(algorithm, key, buffer);
            op.oncomplete = function (e) {
                resolve(e.target.result);
            };
            op.onerror = function (e) {
                reject(new TypeError);
            };
        })
    };

    that.sign = function (algorithm, key, buffer) {
        return new Promise(function(resolve, reject) {
            var op = nfCrypto.sign(algorithm, key, buffer);
            op.oncomplete = function (e) {
                resolve(e.target.result);
            };
            op.onerror = function (e) {
                reject(new TypeError);
            };
        })
    };

    that.verify = function (algorithm, key, signature, buffer) {
        return new Promise(function(resolve, reject) {
            var op = nfCrypto.verify(algorithm, key, signature, buffer);
            op.oncomplete = function (e) {
                resolve(e.target.result);
            };
            op.onerror = function (e) {
                reject(new TypeError);
            };
        })
    };

    that.generateKey = function (algorithm, extractable, keyUsage) {
        return new Promise(function(resolve, reject) {
            var op = nfCrypto.generateKey(algorithm, extractable, keyUsage);
            op.oncomplete = function (e) {
                resolve(e.target.result);
            };
            op.onerror = function (e) {
                reject(new TypeError);
            };
        })
    };

    that.deriveKey = function (algorithm, baseKey, derivedKeyAlgorithm, extractable, keyUsage) {
        return new Promise(function(resolve, reject) {
            var op = nfCrypto.deriveKey(algorithm, baseKey, derivedKeyAlgorithm, extractable, keyUsage);
            op.oncomplete = function (e) {
                resolve(e.target.result);
            };
            op.onerror = function (e) {
                reject(new TypeError);
            };
        })
    };

    that.wrapKey = function (keyToWrap, wrappingKey, wrappingAlgorithm) {
        return new Promise(function(resolve, reject) {
            var op = nfCrypto.wrapKey(keyToWrap, wrappingKey, wrappingAlgorithm);
            op.oncomplete = function (e) {
                resolve(e.target.result);
            };
            op.onerror = function (e) {
                reject(new TypeError);
            };
        })
    };

    that.unwrapKey = function (jweKeyData, algorithm, wrappingKey, extractable, usage) {
        return new Promise(function(resolve, reject) {
            var op = nfCrypto.unwrapKey(jweKeyData, algorithm, wrappingKey, extractable, usage);
            op.oncomplete = function (e) {
                resolve(e.target.result);
            };
            op.onerror = function (e) {
                reject(new TypeError);
            };
        })
    };

})(window);
