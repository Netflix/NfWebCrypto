/*global TestArray, util, tv */

/* global pluginStartLoadTime, pluginEndLoadTime */

// -----------------------------------------------------------------------------
TestArray.addTest(
    "Load Plugin",
    function() {
        this.startTime = pluginStartLoadTime;
        this.endTime = pluginEndLoadTime;
        this.complete(true);
    }
);

//-----------------------------------------------------------------------------
TestArray.addTest(
    "Generate a 256-bit AES key",
    function() {
        var length = 192;
        var op = window.nfCrypto.subtle.generateKey({
            name: "AES-CBC",
            params: { length: 256 }
        });
        var that = this;
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(.1, false );
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            that.complete( 
                key.hasOwnProperty('type') &&
                key.hasOwnProperty('extractable') &&
                key.hasOwnProperty('algorithm') &&
                key.hasOwnProperty('keyUsage')
            );
        };
    }
);

// -----------------------------------------------------------------------------
TestArray.addTest(
    "Generate a 2048-bit RSAES-PKCS1-v1_5 key pair",
    function() {
        var op = window.nfCrypto.subtle.generateKey({
            'name': 'RSAES-PKCS1-v1_5',
            'params': {
                'modulusLength': 2048,
                'publicExponent': new Uint8Array([0x01, 0x00, 0x01])
            }
        }, false, ['encrypt', 'decrypt']);
        var that = this;
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(.2, false );
        };
        op.oncomplete = function(e) {
            tv.rsaesKey = e.target.result;
            that.complete(  
                tv.rsaesKey.hasOwnProperty('publicKey') &&
                tv.rsaesKey.hasOwnProperty('privateKey')
            );
        };
    }
);

TestArray.addTest(
    "Generate a 2048-bit RSASSA-PKCS1-v1_5 key pair",
    function() {
        var op = window.nfCrypto.subtle.generateKey({
            'name': 'RSASSA-PKCS1-v1_5',
            'params': {
                'modulusLength': 2048,
                'publicExponent': new Uint8Array([0x01, 0x00, 0x01])
            }
        }, false, ['sign', 'verify']);
        var that = this;
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(false);
        };
        op.oncomplete = function(e) {
            tv.rsassaKey = e.target.result;
            that.complete(  
                    tv.rsassaKey.hasOwnProperty('publicKey') &&
                    tv.rsassaKey.hasOwnProperty('privateKey')
            );
        };
    }
);

// -----------------------------------------------------------------------------
TestArray.addTest(
    "Import an AES key",
    function() {
        var op = window.nfCrypto.subtle.importKey(
            "raw",
            util.hex2abv("f3095c4fe5e299477643c2310b44f0aa"),
            "AES-GCM"
        );
        var that = this;
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(.3, false );
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            that.complete( 
                key.hasOwnProperty('type') &&
                key.hasOwnProperty('extractable') &&
                key.hasOwnProperty('algorithm') &&
                key.hasOwnProperty('keyUsage')
            );
        };
    }
);

// -----------------------------------------------------------------------------
TestArray.addTest(
    "Export an RSA public key in SPKI format",
    function() {
        var that = this;
        var op1 = window.nfCrypto.subtle.exportKey("spki", tv.rsaesKey.publicKey);
        op1.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(false );
        };
        op1.oncomplete = function(e) {
            var spki = e.target.result;
            that.complete(spki.length != 0);
        };
    }
);

// -----------------------------------------------------------------------------
TestArray.addTest(
    "SHA-256 digest",
    function() {
        var that = this;
        var op = window.nfCrypto.subtle.digest("SHA-256", tv.t3_data);
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete( false );
        };
        op.oncomplete = function(e) {
            that.memcmp_complete(tv.t3_result, e.target.result); 
        };
    }
);

// -----------------------------------------------------------------------------
TestArray.addTest(
    "HMAC SHA-256",
    function() {
        var that = this;
        var op = window.nfCrypto.subtle.importKey("raw", tv.t4_key, { name: "HMAC", params: { hash: {name: "SHA-256"} } });
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(false );
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            var op2 = window.nfCrypto.subtle.sign({
                name: "HMAC",
                params: { hash: "SHA-256" }
            }, key, tv.t4_data);
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.complete(false );
            };
            op2.oncomplete = function(e) {
                that.memcmp_complete(tv.t4_result, e.target.result );
            };
        };
    }
);


// -----------------------------------------------------------------------------
TestArray.addTest(
    "RSAES encrypt/decrypt 28 bytes",
    function () {
        var that = this;
        var op = window.nfCrypto.subtle.encrypt("RSAES-PKCS1-v1_5", tv.rsaesKey.publicKey, tv.t7_data);
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(false );
        };
        op.oncomplete = function(e) {
            var data = e.target.result;
            var op2 = window.nfCrypto.subtle.decrypt("RSAES-PKCS1-v1_5", tv.rsaesKey.privateKey, data);
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.complete(false );
            };
            op2.oncomplete = function(e) {
                that.memcmp_complete(tv.t7_data, e.target.result );
            };
        };
    }
);


// -----------------------------------------------------------------------------
TestArray.addTest(
    "RSASSA/SHA-256 sign/verify 228 bytes",
    function () { 
    var that = this;
        var op1 = window.nfCrypto.subtle.sign({
            name: "RSASSA-PKCS1-v1_5",
            params: { hash: "SHA-256" }
        }, tv.rsassaKey.privateKey, tv.t10_data);
        op1.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(false );
        };
        op1.oncomplete = function(e) {
            var sig = e.target.result;
            var op2 = window.nfCrypto.subtle.verify({
                name: "RSASSA-PKCS1-v1_5",
                params: { hash: "SHA-256" }
            }, tv.rsassaKey.publicKey, sig, tv.t10_data);
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.complete(false );
            };
            op2.oncomplete = function(e) {
                that.complete(e.target.result);
            };
        };
    }
);


// -----------------------------------------------------------------------------
TestArray.addTest(
    "AES-CBC encryption",
    function () {
        var that = this;
        var op = window.nfCrypto.subtle.importKey("raw", tv.t13_key, "AES-CBC");
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(false );
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            var op2 = window.nfCrypto.subtle.encrypt({
                name: "AES-CBC",
                params: { iv: tv.t13_iv }
            }, key, tv.t13_data);
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.complete(false );
            };
            op2.oncomplete = function(e) {
                that.memcmp_complete(tv.t13_result, e.target.result );
            };
        };
    }
);


// -----------------------------------------------------------------------------
TestArray.addTest(
    "AES-CBC decryption",
    function () {
        var that = this;
        var op = window.nfCrypto.subtle.importKey("raw", tv.t14_key, "AES-CBC");
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(false );
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            var op2 = window.nfCrypto.subtle.decrypt({
                name: "AES-CBC",
                params: { iv: tv.t14_iv }
            }, key, tv.t14_data);
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.complete(false );
            };
            op2.oncomplete = function(e) {
                that.memcmp_complete(tv.t14_result, e.target.result );
            };
        };
    }
);


// -----------------------------------------------------------------------------
TestArray.addTest(
    "AES-GCM encryption",
    function () { 
        var that = this;
        var op = window.nfCrypto.subtle.importKey("raw", tv.t18_key, "AES-GCM");
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(false );
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            var op2 = window.nfCrypto.subtle.encrypt({
                name: "AES-GCM",
                params: { 
                    iv: tv.t18_iv,
                    additionalData: tv.t18_adata,
                    tagLength: 128
                }
            }, key, tv.t18_data);
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.complete(false );
            };
            op2.oncomplete = function(e) {
                // Concatenate the result and tag
                var t18_fullresult = util.abvcat(
                    tv.t18_result,
                    tv.t18_tag
                );
                that.memcmp_complete(t18_fullresult, e.target.result );
            };
        };
    }
);


//-----------------------------------------------------------------------------
TestArray.addTest(
    "AES-GCM decryption",
    function () { 
        var that = this;
        var op = window.nfCrypto.subtle.importKey("raw", tv.t19_key, "AES-GCM");
        op.onerror = function(e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(false );
        };
        op.oncomplete = function(e) {
            var key = e.target.result;
            // Concatenate the result and tag
            var t19_fulldata = util.abvcat(
                tv.t19_data,
                tv.t19_tag
            );
            var op2 = window.nfCrypto.subtle.decrypt({
                name: "AES-GCM",
                params: { 
                    iv: tv.t19_iv,
                    additionalData: tv.t19_adata,
                    tagLength: 128
                }
            }, key, t19_fulldata);
            op2.onerror = function(e) {
                console.log("ERROR :: " + e.target.result);
                that.complete(false );
            };
            op2.oncomplete = function(e) {
                that.memcmp_complete(tv.t19_result, e.target.result );
            };
        };
    }
);


//-----------------------------------------------------------------------------
TestArray.addTest(
    "Unwrap JWE-JS Key, RSA-OAEP+AES-GCM128",
    function () {
        var that = this;
        var op1 = window.nfCrypto.subtle.importKey(
                "pkcs8",
                tv.t20_rsaKey, 
                "RSA-OAEP",
                false,
                ["unwrap"]
        );
        op1.onerror = function (e) {
            console.log("ERROR :: " + e.target.result);
            that.complete(false );
        };
        op1.oncomplete = function (e) {
            var wrappingKey = e.target.result;
            var op2 = window.nfCrypto.subtle.unwrapKey(
                    util.latin1.parse(tv.t20_jweData),
                    "AES-CBC",
                    wrappingKey,
                    true);
            op2.onerror = function (e) {
                console.log("ERROR :: " + e.target.result);
                that.complete(false );
            };
            op2.oncomplete = function (e) {
                var unwrappedKey = e.target.result;
                var op3 = window.nfCrypto.subtle.exportKey("raw", unwrappedKey);
                op3.onerror = function (e) {
                    console.log("ERROR :: " + e.target.result);
                    that.complete(false );
                };
                op3.oncomplete = function (e) {
                    that.memcmp_complete(tv.t20_key, e.target.result);
                }
            }
        };
    }
);

