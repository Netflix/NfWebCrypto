NOTE: THIS PROJECT IS NO LONGER UNDER ACTIVE MAINTAINENCE.
With most browsers now providing W3C Web Crypto implementations and Chrome disallowing 3rd-party PPAPI plugins, there is little use for this project. It will remain here on Github indefinitely, but there are no plans to keep any branch updated. The most recent code lives in the 'newInterface' branch.

Netflix WebCrypto (NfWebCrypto)
================================

Netflix WebCrypto is a polyfill of the [W3C Web Cryptography API](http://www.w3.org/TR/WebCryptoAPI/),
22 April 2013 Editor's Draft, as a native Chrome PPAPI plugin. Unlike a javascript polyfill, the native implementation
supports a stronger security model with no key material exposed to javascript. The goal is to make the Web Crypto
Javascript API [freely available](http://www.apache.org/licenses/LICENSE-2.0) to web
developers for experimentation and use prior to its implementation by browser vendors.

Currently only Google Chrome / Chromium on linux amd64 is supported.

Features
--------

NfWebCrypto does not implement the Web Crypto API in its entirety, due to
limitations of browser plugin technology and initial focus on operations and
algorithms most useful to Netflix. However, the existing feature set supports
many typical and common crypto use cases targeted by the Web Crypto API.

Supported

* Interfaces supported:
  + Key, KeyPair
  + KeyOperation
  + CryptoOperation
  + CryptoKeys
* SubtleCrypto interface methods supported
  + encrypt, decrypt
  + sign, verify
  + generateKey
  + exportKey, importKey
  + wrapKey, unwrapKey* **
* CryptoKeys interface methods supported
  + getKeyByName
* Key formats supported
  + symmetric keys: raw and jwk (raw)
  + asymmetric keys: pkcs#8 (public), spki (private), and jwk (public only)
* Algorithms supported
  + SHA-1, SHA-224, SHA-256, SHA-384, SHA-512: digest
  + HMAC SHA-256: sign, verify, importKey, exportKey, generateKey
  + AES-128 CBC w/ PKCS#5 padding: encrypt, decrypt, importKey, exportKey, generateKey
  + RSASSA-PKCS1-v1_5: sign, verify, importKey, generateKey
  + RSAES-PKCS1-v1_5: encrypt, decrypt, importKey, exportKey, generateKey
  + Diffie-Hellman: generateKey, deriveKey
  + RSA-OAEP: wrapKey, unwrapKey
  + AES-KW: wrapKey, unwrapKey
  + AES-GCM: encrypt, decrypt, importKey, exportKey, generateKey

*A special "Kds" NamedKey bound to the plugin binary and script origin can be used with (un)wrapKey to export/import
opaque key representations for persistence in HTML5 local storage or equivalent.

**Wrap/Unwrap operations follow the Netflix [KeyWrap Proposal](http://www.w3.org/2012/webcrypto/wiki/KeyWrap_Proposal)
and support protection of the JWE payload with AES128-GCM.
It is be possible to wrap/unwrap the following key types: HMAC SHA-256 and AES-128 CBC.

Not Supported

* The streaming/progressive processing model in not supported
* Synchronous API's like getRandomValues() are not supported
* Algorithm normalizing rules are not fully implemented

Moving forward, Netflix will continue to enhance this implementation and try to keep it as much in sync as possible
with the latest draft Web Crypto API spec.

Requirements
------------

Linux

* Ubuntu 12.04 64-bit with build-essential, libssl-dev-1.0.1c or later, and cmake 2.8 or later
* 64-bit Google Chrome / Chromium R22 or later (tested with R27)

Directory Tour
--------------

    base/
        Common C++ source for both the plugin and crypto component.
    cmake/
        Cmake toolchain files.
        Linux desktop builds use the linux system build tools and libs.
        Only 64-bit builds are supported for now.
    crypto/
        C++ source for the crypto component. The contents of this directory is
        of primary interest to native devs; the entry point is the CadmiumCrypto
        class. This directory currently builds to an archive file.
    crypto/test/
        Contains C++ gtest unit tests that exercise the CadmiumCrypto class
        interface. Not fleshed out yet and currently not built.
    misc/
        Miscellaneous code to support development. Currently has code to run and
        debug the Chrome browser with the plugin properly registered.
    plugin/
        C++ source of the PPAPI plugin. This code builds to shared library that
        is dl-loaded by the browser when the plugin is registered. It handles
        interfacing with the browser, bridging to the crypto thread, and decode/
        dispatch of JSON messages to and from the browser. Native devs will
        probably only be interested in the NativeBridge class here.
    web/nfcrypto.js
        The javascript front-end for the plugin. The bottom level of this code
        handles the transport of JSON-serialized messages to and from the
        plugin, while the top level implements the W3C WebCrypto interface.
        Native devs will need to change the bottom level to match their bridge
        API. This source file borrows heavily from PolyCrypt (polycrypt.net)
    web/test_qa.html
        The Jasmine HTML unit tests that exercise the javascript WebCrypto
        API exposed to the javascript client by nfcrypto.js.
        

How to Build
------------
The following has been verified on Ubunutu 12.04. cmake 2.8 or later is required.

NOTE: The SYSTEM key mentioned above depends in part on a secret build-time key 
SECRET\_SYSTEM\_KEY that for example purposes is hard-coded in linux_common.cmake.
Actual deployments must change this key.

    $ mkdir buildDir
    $ cd buildDir
    $ cmake -DCMAKE_TOOLCHAIN_FILE=(repo)/cmake/toolchains/linux64.cmake -DCMAKE_BUILD_TYPE=[Debug|Release] (repo)
    $ make -j<N>

Build Results
-------------

Browser plugin - This is registered and run within the Chrome browser.

    (buildDir)/plugin/libnfwebcrypto.so
    (buildDir)/plugin/nfwebcrypto.info
    
Native gtest unit test executable (if built). This is run from the command
line.

    (buildDir)/crypto/test/test
    
Native CadmiumCrypto archive. Native apps will link to this archive.

    (buildDir)/crypto/libcadcrypto.a


How to run the Unit Tests
-------------------------

Chrome must be run with a special command line option to register the plugin.
The easiest way to do this is to use the provided start.sh script, which employs
the .info file generated by the build.

Make a directory and copy or symlink start.sh, libnfwebcrypto.so, and
nfwebcrypto.info.

    $ mkdir runNfWebCrypto
    $ cd !$
    $ ln -s (repo)/misc/desktop/start.sh
    $ ln -s (buildDir)/plugin/libnfwebcrypto.so
    $ ln -s (buildDir)/plugin/nfwebcrypto.info

The start.sh script depends on the chrome executable present at
/opt/google/chrome/chrome. Edit the script if this is not true. Finally, start
chrome and run the [unit tests hosted on github](http://netflix.github.io/NfWebCrypto/web/test_qa.html)
by running the script.

    $ ./start.sh
    
Note that there must not be any other chrome instance running in the system
before the script is executed. Otherwise the action will be to just open a new
tab on the existing instance without loading the plugin.

The unit tests will run automatically and all should pass.

Sample Code
-----------

Here are some examples of how to use the Web Cryptography API to perform typical
crypto operations. These will work once the plugin is installed and enabled. More
detailed usage examples may be found in the javascript unit tests.

The examples below use the following utility functions to convert between string
and Uint8Array:

```JavaScript

// string to uint array
function text2ua(s) {
    var escstr = encodeURIComponent(s);
    var binstr = escstr.replace(/%([0-9A-F]{2})/g, function(match, p1) {
        return String.fromCharCode('0x' + p1);
    });
    var ua = new Uint8Array(binstr.length);
    Array.prototype.forEach.call(binstr, function (ch, i) {
        ua[i] = ch.charCodeAt(0);
    });
    return ua;
}

// uint array to string
function ua2text(ua) {
    var binstr = Array.prototype.map.call(ua, function (ch) {
        return String.fromCharCode(ch);
    }).join('');
    var escstr = binstr.replace(/(.)/g, function (m, p) {
        var code = p.charCodeAt(p).toString(16).toUpperCase();
        if (code.length < 2) {
            code = '0' + code;
        }
        return '%' + code;
    });
    return decodeURIComponent(escstr);
}

```

### Compute SHA-1 hash ###

```JavaScript

<script src='nfcrypto.js'></script>
<script>
    var cryptoSubtle = window.nfCrypto.subtle;
    var data = "This is some data to hash";    
    var op = cryptoSubtle.digest({ name: "SHA-1" }, text2ua(data));
    op.oncomplete = function (e) {
        window.alert("SHA-1 of \"" + data + "\": " + btoa(e.target.result));
    };
</script>

```

### AES-CBC Encryption / Decryption ###

```JavaScript

<script src='nfcrypto.js'></script>
<script>

    var cryptoSubtle = window.nfCrypto.subtle;
    var cleartext = "This is some cleartext to encrypt.";
    var key;
    var iv = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]);
    var ciphertext;
    
    // generate a non-extractable 128-bit AES key
    function generateKey() {
        var genKeyOp = cryptoSubtle.generateKey(
            { name: "AES-CBC", params: { length: 128 } },
            false
        );
        genKeyOp.oncomplete = function (e) {
            key = e.target.result;
            encryptData();
        }
    }
    
    // encrypt cleartext to get ciphertext
    function encryptData() {
        var encOp = cryptoSubtle.encrypt({
            name: "AES-CBC",
            params: { iv: iv }
        }, key, text2ua(cleartext));
        encOp.oncomplete = function (e) {
            cipherText = e.target.result;
            decryptData();
        }
    }
    
    // decrypt ciphertext to get cleartext
    function decryptData() {
        var encOp = cryptoSubtle.decrypt({
            name: "AES-CBC",
            params: { iv: iv }
        }, key, cipherText);
        encOp.oncomplete = function (e) {
            var cleartext2 = ua2text(e.target.result);
            if (cleartext2.valueOf() == cleartext.valueOf()) {
                window.alert("Round-trip encryption/decryption works!");
            }
        }
    }

    generateKey();

</script>

```

### Sign / Verify Data with HMAC SHA256 ###

```JavaScript

<script src='nfcrypto.js'></script>
<script>

    var cryptoSubtle = window.nfCrypto.subtle;
    var data = "This is some data to sign",
        hmacKey,
        signature;

    function generateKey() {
        var genOp = cryptoSubtle.generateKey({ name: "HMAC", params: { hash: {name: "SHA-256"} } });
        genOp.oncomplete = function (e) {
            hmacKey = e.target.result;
            signData();
        };
    }
    
    function signData() {
        var signOp = cryptoSubtle.sign(
            { name: "HMAC", params: { hash: "SHA-256" } },
            hmacKey,
            text2ua(data)
        );
        signOp.oncomplete = function (e) {
            signature = e.target.result;
            verifyData();
        };
    }
    
    function verifyData() {
        var verifyOp = cryptoSubtle.verify(
            { name: "HMAC", params: { hash: "SHA-256" } },
            hmacKey,
            signature,
            text2ua(data)
        );
        verifyOp.oncomplete = function (e) {
            if (e.target.result) {
                window.alert("Round-trip hmac sign/verify works!");
            }
        };
    }

    generateKey();
    
</script>

```

### RSA Encryption / Decryption ###

```JavaScript

<script src='nfcrypto.js'></script>
<script>

    var cryptoSubtle = window.nfCrypto.subtle;
    var clearText = "This is some data to encrypt";
    var pubKey, privKey;
    var cipherText;
    
    // generate a 1024-bit RSA key pair for encryption
    function generateKey() {
        var genOp = cryptoSubtle.generateKey({
            name: "RSAES-PKCS1-v1_5",
            params: {
                modulusLength: 1024,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]) // Fermat F4
            }
        }, false);
        genOp.oncomplete = function (e) {
            pubKey  = e.target.result.publicKey;
            privKey = e.target.result.privateKey;
            exportKey();
        }
    }
    
    // export the public key in SPKI format in order to send it to the peer
    function exportKey() {
        var exportOp = cryptoSubtle.exportKey("spki", pubKey);
        exportOp.oncomplete = function (e) {
            var pubKeySpki = e.target.result;
            // here you would send pubKeySpki to peer
            encryptData();
        }
    }
    
    // simulate peer encryption by encrypting clearText with the public key
    function encryptData() {
        var encryptOp = cryptoSubtle.encrypt(
            { name: "RSAES-PKCS1-v1_5" },
            pubKey,
            text2ua(clearText)
        );
        encryptOp.oncomplete = function (e) {
            cipherText = e.target.result;
            decryptData();
        }
    }
    
    // pretend the cipherText was received from the peer, and decrypt it
    // with the private key; should get the same clearText back
    function decryptData() {
        var decryptOp = cryptoSubtle.decrypt({ name: "RSAES-PKCS1-v1_5" }, privKey, cipherText);
        decryptOp.oncomplete = function (e) {
            var clearText2 = ua2text(e.target.result);
            if (clearText2.valueOf() == clearText.valueOf()) {
                window.alert("Round-trip RSA encrypt/decrypt successful!");
            }
        }
    }
    
    generateKey();
    
</script>

```
