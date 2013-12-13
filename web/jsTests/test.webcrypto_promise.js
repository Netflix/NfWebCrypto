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

(function () {
    "use strict";
    
    // get "crypto" from the right namespace
    var crypto,
        cryptoSubtle;
    
    if (window.msCrypto) { // IE
        crypto = window.msCrypto;
    } else if (window.nfNewCrypto) { // Chrome OS, Chrome with NfWebCrypto
        crypto = window.nfNewCrypto;
    } else if (window.crypto) {  // all others
        crypto = window.crypto;
    } else {
        console.log('no crypto namespace');
        return;
    }
    
    // get crypto.subtle
    if (crypto.webkitSubtle) {  // Safari
        cryptoSubtle = crypto.webkitSubtle;
    } else if (crypto.subtle) { // all others
        cryptoSubtle = crypto.subtle;
    } else {
        console.log('no crypto.subtle namespace');
        return;
    }

    // --------------------------------------------------------------------------------
    describe("crypto interface", function () {

        it("crypto exists", function () {
            expect(crypto).toBeDefined();
        });

        it("crypto.getRandomValues exists", function () {
            expect(typeof crypto.getRandomValues).toEqual("function");
        });

        it("crypto.subtle exists", function () {
            expect(cryptoSubtle).toBeDefined();
        });

        it("crypto.subtle.encrypt exists", function () {
            expect(typeof cryptoSubtle.encrypt).toEqual("function");
        });

        it("crypto.subtle.decrypt exists", function () {
            expect(typeof cryptoSubtle.decrypt).toEqual("function");
        });

        it("crypto.subtle.sign exists", function () {
            expect(typeof cryptoSubtle.sign).toEqual("function");
        });

        it("crypto.subtle.verify exists", function () {
            expect(typeof cryptoSubtle.verify).toEqual("function");
        });

        it("crypto.subtle.digest exists", function () {
            expect(typeof cryptoSubtle.digest).toEqual("function");
        });

        it("crypto.subtle.generateKey exists", function () {
            expect(typeof cryptoSubtle.generateKey).toEqual("function");
        });

        it("crypto.subtle.importKey exists", function () {
            expect(typeof cryptoSubtle.importKey).toEqual("function");
        });

        it("crypto.subtle.exportKey exists", function () {
            expect(typeof cryptoSubtle.exportKey).toEqual("function");
        });

        it("crypto.subtle.wrapKey exists", function () {
            expect(typeof cryptoSubtle.wrapKey).toEqual("function");
        });

        it("crypto.subtle.unwrapKey exists", function () {
            expect(typeof cryptoSubtle.unwrapKey).toEqual("function");
        });

    });

    // --------------------------------------------------------------------------------

    describe("RandomSource", function () {

        it("getRandomValues", function () {
            runs(function () {
                var zeros = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

                var abv1 = new Uint8Array(8);
                var abv2 = crypto.getRandomValues(abv1);

                expect(abv1).toBe(abv2);
                expect(abv2).toNotEqual(zeros);

                var abv3 = new Uint8Array(8);
                var abv4 = crypto.getRandomValues(abv3);

                expect(abv3).toBe(abv4);
                expect(base16.stringify(abv4)).not.toEqual(base16.stringify(zeros));
                expect(base16.stringify(abv4)).not.toEqual(base16.stringify(abv2));
            });

        });

    });

    // --------------------------------------------------------------------------------

    describe("SHA", function () {

        it("digest SHA-256 known answer", function () {
            // convenient calculator here: http://www.fileformat.info/tool/hash.htm
            var data = base16.parse("6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071"),
                signature_sha256_hex = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";

            var signature,
                error,
                complete;

            runs(function () {
                cryptoSubtle.digest({ name: "SHA-256" }, data)
                .then(function (result) {
                    complete = true;
                    signature = result && new Uint8Array(result);
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            });

            waitsFor(function () {
                return error || complete;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(complete).toBeTruthy();
                expect(base16.stringify(signature)).toBe(signature_sha256_hex);
            });
        });

        it("digest SHA-384 known answer", function () {
            // convenient calculator here: http://www.fileformat.info/tool/hash.htm
            var data = base16.parse("6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071"),
                signature_sha384_hex = "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b";

            var signature,
                error,
                complete;

            runs(function () {
                cryptoSubtle.digest({ name: "SHA-384" }, data)
                .then(function (result) {
                    complete = true;
                    signature = result && new Uint8Array(result);
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            });

            waitsFor(function () {
                return error || complete;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(complete).toBeTruthy();
                expect(base16.stringify(signature)).toBe(signature_sha384_hex);
            });
        });
    });

    // --------------------------------------------------------------------------------

    describe("AES-CBC", function () {
        var rawKeyData = base64.parse('_BkaT2XycllUKn6aiGrdVw'),
            cleartext = base64.parse('eyJtZXNzYWdlaWQiOjIwNzAzMTM3MzcsIm5vbnJlcGxheWFibGUiOmZhbHNlLCJyZW5ld2FibGUiOnRydWUsImNhcGFiaWxpdGllcyI6eyJjb21wcmVzc2lvbmFsZ29zIjpbIkxaVyJdfSwia2V5cmVxdWVzdGRhdGEiOlt7InNjaGVtZSI6IkFTWU1NRVRSSUNfV1JBUFBFRCIsImtleWRhdGEiOnsia2V5cGFpcmlkIjoicnNhS2V5cGFpcklkIiwibWVjaGFuaXNtIjoiSldFX1JTQSIsInB1YmxpY2tleSI6Ik1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBM1RydHZQSUJKOGY5V2Jsa1FNeHgvczFnQmRjb0Z3bFNxQU5TTG5MSk9LdkJXNFRIdmNSeHR0VHc4dTRMWVFhM3h4Z1FNSUdBKzVMSXVxaGEyL1BXQ1dub2Vqdks1c05SM1I2cEJncjI0Ti9remZOeUpYYUt4WHJ1N1F1VW8vMG9VSGZJK3YxcE1qZ3VYN2ZqcWhtQ3RIdWNkQjFnTDNBenhNZ1J5MFdoU2NzdVFrN294bGtGQ3IxTnJiZEtvQ2xMVThCcnpvNmNsRVhmY2dIeUhiWU9kcEg4OVZPV2srMnJOM0VSL28yQ2RJeFpSL3A4SFBTS1NkMjc4ckRBejgydThUTWJ3b3RtREtLZzc0cWFoYkxrbjdpQnNOd2Y2M1hUM0JtY0JKTjA2SFplS0UyQTNOY0k1VHp4SFEwL3ZvNEpiQXFaWmFvTnRMYVAvTFpaWGNUbGRRSURBUUFCIn19XSwidXNlcmF1dGhkYXRhIjp7InNjaGVtZSI6Ik5FVEZMSVhJRCIsImF1dGhkYXRhIjp7Im5ldGZsaXhpZCI6InYlM0QyJTI2bWFjJTNEQVFFQUVBQUJBQlJ5Vng2aFdPc2Z1VXRVQTR6azdtT2dKeERVa3Y1LUo3VS4lMjZjaCUzREFRRUFFQUFCQUJURXdITFFIbmV1TV92Z0I3czREQ3RmMm16OUtGOUwxVlUuJTI2Y3QlM0RCUUFPQUFFQkVPc3gyU2VmRWZvbHd0M2VQUkF0ZXAyQndJVmszbldoYkxCTllNQ3czYjc1eXQ1ZmFoTkRRTmR0NXNOSEpFYjVUVFZrYnNTYlVhNHlpRjE2aHV2NEFDcUxVV1VMYWE1aVV5Sk1ZRF92OXpZSmhacC03bExhdlFyck03S2ZCb3R3N0hzLVJWZWwwYi16cXNIMzV0SHd6OXJ3V3dFRU05b3ZDV1paODJaQUE1YkZ4dE1LTGgxX01idmNTUzdXaGRvYWg5T18tWm90WUxkX2Z5aUJTT0VDX25feUpZa3pVR0IySmZ4X2xMdDdTdklOVmxuR0I4enlPVjdIM2tsV0xULV9QMmlFdTNpRFh3eVVhelJqNUlidm1jdktwenBRcmVidm05RXpSRjNQWXV3ekxra2RCOHl4QmkwcE9ZREM5OXE4MldQbTRQSXQ2c2xhOTZrQ255b2IwUHhlRUhFYWxfcDZPaXhKSWM5c2RFSW90bDJ6aEVvdUFkcDVvZXFoNE8zUngtQXV5ZUxqSWw5bWFFY0c1MXRmMy1HWUxHUXFVeVRiMlh0U1hkWkUzcHhmYmZLX1hyWTF6cUFJZ3N1QXV3MUFTX1lKcE94ZGppSHBuM0I0OGpPaXFRc2ZqUWNxTW5HbW5jb29lSEw2aENtUzNJSWFXUjRTQmpfRThwZWwyd3ZYb01HNkZfYkd3TFNkTTlzTDA3aTd4MWt4UnBNU0E0YWxiMWV6RmxiMEdaRGx2Q3FOYm1vbWZGeExfZEFXZGlRcEw3THZaamxNZ0lYcXpDRGRaTDNBcXZKZGtsV2tJem9mY1pVM0ZCZWpoZ3VOUEc0LiUyNmJ0JTNEdXNyIiwic2VjdXJlbmV0ZmxpeGlkIjoidiUzRDIlMjZtYWMlM0RBUUVBRVFBQkFCUTR3ZU56bGpkam5QZzVHSHdFUnVHZzZwRk84RG14LTZ3LiUyNmR0JTNEMTM2NzQ0OTI2OTAxMSJ9fX0='),
            cipherText = base64.parse('R9PHIE/XtAlTNIP3jiQAB2Pnw553AcYwHVFGEFW+pRq9Ur/ab7+4ckUjlYroQmd1LdnbA78YO+FVf7HfyDgZ5+FN541fBmlLmA/OYsyCO3e9CgAEdTJQGRd2XRR4gmGDFBjhpYunEGpPLXAgbf2aOCeGcq7Qyz9LlCq6cCMfSQ9wOKbhyL+BDzZEobZFwVkuKsjACdpnyh5ok53O4HMCnvtTvnS7EOr4fr0/+of234f1Um5zg8ny6n83dtGK9No15bdm38+lAGNG/C16znyFNWT++ue9Jlp5nbG7qrb/TswagvKOGJqKGkyV3oWViUj5Ar3j4vg9omUV6XuREmVLet/nFo4RJS/fKYEef7xbgRqTSkw4xg3sPTXTrP0GTmgWlgXk9rW93ua+ntmgpXIito5uCV7dmgBfWEy2YXjM7bjL7+e+Ihwlm0cDacyRZQKIq24OsYaLVw5deWxNWMDdJVJ8iWZkvvadCSDU9ehApKH40PeP/sln0nrv4vv2ugygLnOTXkLlkSYMMSEkFbujZl3q5HddF6VN57lQXg+KKwppGzsKGaNy5mq6E/E4KBeC9hlv+xWYPbvY4Xwe9bOSR/fpY93YmaPJpc5x/4Qb7wKJRbvik4AlbKBR4L7CUT5XpxBO42ZtHP+jBcWI0S444WG7nnn45pfeZuLtfP5MDDqcW7/thtyQ7BKWchW4gmoz+Cq3MgysGE1/ytFWZobQ4hmnEhdVGpzVouKvlZJW3v0CM9eIChof8HKiZ5xiBm271tZvR34X3evOUA7VWc+uyCijFt55wnA9780PD4NPoCX2sqi1Y0ovHxTjZG1FZvaDAZ8Hy+xTJ1SW3q9lqPUGx9haDqS8NUScNXBPZZtB02QVocLN74UOuolbcxuKBC39u66/HFuf0OO6ES/98V6nnAz+M2nWaR0U7Ogdw0Oa03z1MKH/9Vi01Fee2T9oxmyzo2EvH1a8BryvRaIdvqnRm4iLAqciNf51XQBDyulCgUhHGOiBwpDwuUJ6gsA7wO5GwjuTzttMhWmzugC58FkL3aX7ieoCXW+u/J8ppURPXlI9uxarQ5Tp81qMwqWWWiutKl4IT4FdPmYLGhIcXOC6wGfTe2iBh8PggTklqF0Sev0L28bF1BmrfkJOw1vtf0BZTXfe3pRTTojZXtorOByRR5OB3kyScyliT2ipDtwxfRe4m6UqvGonk64PAO7HcoCbJH9oIAlc3Lk6v/ue373RGusJfs8NV3v2BTD9aBLykbNDsWsXg6S0cPhlRtJ+2R7Py3aGe+lWFhU9zxhBl+WqBGjFV1vfbT9a2obZjNW/gCJ4rUh2K8U+6EMK+fRyp68i6tfVjRt+FilX0RZ7J95O78GIa+xWzBLaihgax0aCi4usx2kTqwyjfEGb3VwW48PkUkinTmN2h5QE7VB1j0a3invB/SA48bBj68dFr12jtgdoI6W5bbMer3QFqaDPQA6JcuY73KsDSGOo4DtPGVtKRhLMksFUDVC0hPqq9kjbSSfKm+MX5f+Vml5TnSRr10kP08aLBZ1XYC9vlFa/PtLcCopFex0E9c3+OZmcn4AsuqLMXesAF8pZGhVExZLeQ3MWrgsgML+TvGLSJCuVCj9aD1wmHlAQF6d+7C2Uh4IVAnG+ctENDr/wRgX3f3pXWnsP0qzby1hwutImi9VtfwIJ84evCuccHst0pF7fQH07Udx7kFb2ZF9YKCGx/uDgbD8WXalimgrghdN1BwCqOfDmVDz4pbq2AlEOWlU+kbtrlKWmsgDj83BVo4CKU4mdn/hgzVzQX/ZAfbxDYjak+cRBwnHyS/kP/vcraWNW/LXOOjMo59VQr2QtzlxmjazmT7T94uyvrnbjlFYGK+GoCKuEsKsTMUaaU1eYM/tsAWt9IfyDEuzDRNdWwT9Ky1SNVSBUgCGfBF6r59sDgo8Uv+i4R4I4Tu7bRd2IACWZj9JEG8hfBIk2n5O1AY1CFoGoC9agaf1bG1jxW+kLXeO8YeK+xCHEHbPWmg3KX7xoLyMnF1l5ICTv86FZOSa4CUQ4oGcQ3BowOdTSy+hAnVIqXZOCmYuKXJ60UgpBIaaYjI2yMzY='),
            iv = base64.parse('Zzm0jwUF1gwiw75Jex8tVQ=='),
            algorithmNoIv = { name: "AES-CBC" },
            algorithm = { name: "AES-CBC", iv: iv };

        var error,
            symmetricKey1;

        it("importKey raw AES-CBC 128 bit", function () {

            runs(function () {
                error = undefined;
                cryptoSubtle.importKey('raw', rawKeyData, algorithmNoIv, false, ["encrypt", "decrypt"])
                    .then(function (result) {
                        symmetricKey1 = result;
                    })
                    .catch(function (e) {
                        error = "importKey ERROR";
                    });
            });

            waitsFor(function () {
                return symmetricKey1 || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(symmetricKey1).toBeDefined();
                expect(symmetricKey1.extractable).toBe(false);
                expect(symmetricKey1.type).toBe("secret");
            });

        });

        it("decrypt AES-CBC 128 known answer", function () {

            runs(function () {
                expect(symmetricKey1).toBeDefined("should be executed after import raw");
            });

            var decryptedData;

            runs(function () {
                error = undefined;
                cryptoSubtle.decrypt(algorithm, symmetricKey1, cipherText)
                    .then(function (result) {
                        decryptedData = result && new Uint8Array(result);
                    })
                    .catch(function (e) {
                        error = "decrypt ERROR";
                    });
            });

            waitsFor(function () {
                return decryptedData || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(decryptedData).toBeDefined();
                expect(base16.stringify(decryptedData)).toEqual(base16.stringify(cleartext));
            });

        });

        it("encrypt AES-CBC 128 known answer", function () {

            runs(function () {
                expect(symmetricKey1).toBeDefined("should be executed after import raw");
            });

            var encryptedData;

            runs(function () {
                error = undefined;
                cryptoSubtle.encrypt(algorithm, symmetricKey1, cleartext)
                    .then(function (result) {
                        encryptedData = result && new Uint8Array(result);
                    })
                    .catch(function (e) {
                        error = "encrypt ERROR";
                    });
            });

            waitsFor(function () {
                return encryptedData || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(encryptedData).toBeDefined();
                expect(base16.stringify(encryptedData)).toEqual(base16.stringify(cipherText));
            });

        });

        it("generateKey AES-CBC, export", function () {
            var error;

            var keyLength = 128,
                key,
                keyData;

            runs(function () {
                error = undefined;
                cryptoSubtle.generateKey({ name: "AES-CBC", length: keyLength }, true, [])
                .then(function (result) {
                    key = result;
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            });

            waitsFor(function () {
                return key || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(key.extractable).toBe(true);
            });

            runs(function () {
                error = undefined;
                cryptoSubtle.exportKey("raw", key)
                .then(function (result) {
                    keyData = result;
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            });

            waitsFor(function () {
                return keyData || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(keyData).toBeDefined();
                expect(keyData.byteLength).toEqual(keyLength / 8);
                expect(base16.stringify(keyData)).not.toEqual(base16.stringify([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
            });

            runs(function () {
                error = undefined;
                key = undefined;
                cryptoSubtle.generateKey({ name: "AES-CBC", length: keyLength }, false, [])
                .then(function (result) {
                    key = result;
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            });

            waitsFor(function () {
                return key || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
                expect(key.extractable).toBe(false);
            });

            runs(function () {
                error = undefined;
                keyData = undefined;
                try {
                    cryptoSubtle.exportKey("raw", key)
                    .then(function (result) {
                        keyData = result;
                    })
                    .catch(function (result) {
                        error = "ERROR";
                    })
                } catch(e) {
                    error = "ERROR";
                }
            });

            waitsFor(function () {
                return keyData || error;
            });

            runs(function () {
                expect(error).toBeDefined();
                expect(keyData).toBeUndefined();
            });

        });

    });


    // --------------------------------------------------------------------------------

    describe("AES-KW", function () {
        
        var algorithm = { name: "AES-KW" };
        var error, wrappingKey;
        var rawKeyData = base16.parse("000102030405060708090A0B0C0D0E0F");
        
        it("importKey raw AES-KW 128 bit", function () {

            runs(function () {
                error = undefined;
                cryptoSubtle.importKey('raw', rawKeyData, algorithm, false, ["wrapKey", "unwrapKey"])
                    .then(function (result) {
                        wrappingKey = result;
                    })
                    .catch(function (e) {
                        error = "ERROR";
                    });
            });

            waitsFor(function () {
                return wrappingKey || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(wrappingKey).toBeDefined();
                expect(wrappingKey.extractable).toBe(false);
                expect(wrappingKey.type).toBe("secret");
            });

        });

        it("generateKey AES-KW, export", function () {
            var error;

            var keyLength = 128,
                key,
                keyData;

            runs(function () {
                error = undefined;
                cryptoSubtle.generateKey({ name: "AES-KW", length: keyLength }, true, [])
                .then(function (result) {
                    key = result;
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            });

            waitsFor(function () {
                return key || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(key.extractable).toBe(true);
            });

            runs(function () {
                error = undefined;
                cryptoSubtle.exportKey("raw", key)
                .then(function (result) {
                    keyData = result;
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            });

            waitsFor(function () {
                return keyData || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(keyData).toBeDefined();
                expect(keyData.byteLength).toEqual(keyLength / 8);
                expect(base16.stringify(keyData)).not.toEqual(base16.stringify([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
            });

            runs(function () {
                error = undefined;
                key = undefined;
                cryptoSubtle.generateKey({ name: "AES-KW", length: keyLength }, false, [])
                .then(function (result) {
                    key = result;
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            });

            waitsFor(function () {
                return key || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
                expect(key.extractable).toBe(false);
            });

            runs(function () {
                error = undefined;
                keyData = undefined;
                try {
                    cryptoSubtle.exportKey("raw", key)
                    .then(function (result) {
                        keyData = result;
                    })
                    .catch(function (result) {
                        error = "ERROR";
                    })
                } catch(e) {
                    error = "ERROR";
                }
            });

            waitsFor(function () {
                return keyData || error;
            });

            runs(function () {
                expect(error).toBeDefined();
                expect(keyData).toBeUndefined();
            });

        });

    });


    // --------------------------------------------------------------------------------

    describe("HMAC SHA-256", function () {
        var rawKeyData = base64.parse('lKydjFak78oOUS1-9QO2zICP4CsZ0w6ORuDXdZz2Tu4'),
            data = base64.parse('eyJrZXlpZCI6Ik5GQ0RJRS0wMS1WQk5GOVpGSDVYWTlWQ0VLUVZZR18zNiIsIml2IjoiWnptMGp3VUYxZ3dpdzc1SmV4OHRWUT09IiwiY2lwaGVydGV4dCI6IlI5UEhJRS9YdEFsVE5JUDNqaVFBQjJQbnc1NTNBY1l3SFZGR0VGVytwUnE5VXIvYWI3KzRja1VqbFlyb1FtZDFMZG5iQTc4WU8rRlZmN0hmeURnWjUrRk41NDFmQm1sTG1BL09Zc3lDTzNlOUNnQUVkVEpRR1JkMlhSUjRnbUdERkJqaHBZdW5FR3BQTFhBZ2JmMmFPQ2VHY3E3UXl6OUxsQ3E2Y0NNZlNROXdPS2JoeUwrQkR6WkVvYlpGd1ZrdUtzakFDZHBueWg1b2s1M080SE1DbnZ0VHZuUzdFT3I0ZnIwLytvZjIzNGYxVW01emc4bnk2bjgzZHRHSzlObzE1YmRtMzgrbEFHTkcvQzE2em55Rk5XVCsrdWU5SmxwNW5iRzdxcmIvVHN3YWd2S09HSnFLR2t5VjNvV1ZpVWo1QXIzajR2ZzlvbVVWNlh1UkVtVkxldC9uRm80UkpTL2ZLWUVlZjd4YmdScVRTa3c0eGczc1BUWFRyUDBHVG1nV2xnWGs5clc5M3VhK250bWdwWElpdG81dUNWN2RtZ0JmV0V5MllYak03YmpMNytlK0lod2xtMGNEYWN5UlpRS0lxMjRPc1lhTFZ3NWRlV3hOV01EZEpWSjhpV1prdnZhZENTRFU5ZWhBcEtINDBQZVAvc2xuMG5ydjR2djJ1Z3lnTG5PVFhrTGxrU1lNTVNFa0ZidWpabDNxNUhkZEY2Vk41N2xRWGcrS0t3cHBHenNLR2FOeTVtcTZFL0U0S0JlQzlobHYreFdZUGJ2WTRYd2U5Yk9TUi9mcFk5M1ltYVBKcGM1eC80UWI3d0tKUmJ2aWs0QWxiS0JSNEw3Q1VUNVhweEJPNDJadEhQK2pCY1dJMFM0NDRXRzdubm40NXBmZVp1THRmUDVNRERxY1c3L3RodHlRN0JLV2NoVzRnbW96K0NxM01neXNHRTEveXRGV1pvYlE0aG1uRWhkVkdwelZvdUt2bFpKVzN2MENNOWVJQ2hvZjhIS2laNXhpQm0yNzF0WnZSMzRYM2V2T1VBN1ZXYyt1eUNpakZ0NTV3bkE5NzgwUEQ0TlBvQ1gyc3FpMVkwb3ZIeFRqWkcxRlp2YURBWjhIeSt4VEoxU1czcTlscVBVR3g5aGFEcVM4TlVTY05YQlBaWnRCMDJRVm9jTE43NFVPdW9sYmN4dUtCQzM5dTY2L0hGdWYwT082RVMvOThWNm5uQXorTTJuV2FSMFU3T2dkdzBPYTAzejFNS0gvOVZpMDFGZWUyVDlveG15em8yRXZIMWE4QnJ5dlJhSWR2cW5SbTRpTEFxY2lOZjUxWFFCRHl1bENnVWhIR09pQndwRHd1VUo2Z3NBN3dPNUd3anVUenR0TWhXbXp1Z0M1OEZrTDNhWDdpZW9DWFcrdS9KOHBwVVJQWGxJOXV4YXJRNVRwODFxTXdxV1dXaXV0S2w0SVQ0RmRQbVlMR2hJY1hPQzZ3R2ZUZTJpQmg4UGdnVGtscUYwU2V2MEwyOGJGMUJtcmZrSk93MXZ0ZjBCWlRYZmUzcFJUVG9qWlh0b3JPQnlSUjVPQjNreVNjeWxpVDJpcER0d3hmUmU0bTZVcXZHb25rNjRQQU83SGNvQ2JKSDlvSUFsYzNMazZ2L3VlMzczUkd1c0pmczhOVjN2MkJURDlhQkx5a2JORHNXc1hnNlMwY1BobFJ0SisyUjdQeTNhR2UrbFdGaFU5enhoQmwrV3FCR2pGVjF2ZmJUOWEyb2Jaak5XL2dDSjRyVWgySzhVKzZFTUsrZlJ5cDY4aTZ0ZlZqUnQrRmlsWDBSWjdKOTVPNzhHSWEreFd6QkxhaWhnYXgwYUNpNHVzeDJrVHF3eWpmRUdiM1Z3VzQ4UGtVa2luVG1OMmg1UUU3VkIxajBhM2ludkIvU0E0OGJCajY4ZEZyMTJqdGdkb0k2VzViYk1lcjNRRnFhRFBRQTZKY3VZNzNLc0RTR09vNER0UEdWdEtSaExNa3NGVURWQzBoUHFxOWtqYlNTZkttK01YNWYrVm1sNVRuU1JyMTBrUDA4YUxCWjFYWUM5dmxGYS9QdExjQ29wRmV4MEU5YzMrT1ptY240QXN1cUxNWGVzQUY4cFpHaFZFeFpMZVEzTVdyZ3NnTUwrVHZHTFNKQ3VWQ2o5YUQxd21IbEFRRjZkKzdDMlVoNElWQW5HK2N0RU5Eci93UmdYM2YzcFhXbnNQMHF6YnkxaHd1dEltaTlWdGZ3SUo4NGV2Q3VjY0hzdDBwRjdmUUgwN1VkeDdrRmIyWkY5WUtDR3gvdURnYkQ4V1hhbGltZ3JnaGROMUJ3Q3FPZkRtVkR6NHBicTJBbEVPV2xVK2tidHJsS1dtc2dEajgzQlZvNENLVTRtZG4vaGd6VnpRWC9aQWZieERZamFrK2NSQnduSHlTL2tQL3ZjcmFXTlcvTFhPT2pNbzU5VlFyMlF0emx4bWphem1UN1Q5NHV5dnJuYmpsRllHSytHb0NLdUVzS3NUTVVhYVUxZVlNL3RzQVd0OUlmeURFdXpEUk5kV3dUOUt5MVNOVlNCVWdDR2ZCRjZyNTlzRGdvOFV2K2k0UjRJNFR1N2JSZDJJQUNXWmo5SkVHOGhmQklrMm41TzFBWTFDRm9Hb0M5YWdhZjFiRzFqeFcra0xYZU84WWVLK3hDSEVIYlBXbWczS1g3eG9MeU1uRjFsNUlDVHY4NkZaT1NhNENVUTRvR2NRM0Jvd09kVFN5K2hBblZJcVhaT0NtWXVLWEo2MFVncEJJYWFZakkyeU16WT0iLCJzaGEyNTYiOiI1QU1RMTRER1FOZGNjS0tzTG9iUmU0bWt4bmJoL3ZCNzEvbWlES3FKOXpJPSJ9'),
            baddata = base64.parse('EyJrZXlpZCI6Ik5GQ0RJRS0wMS1WQk5GOVpGSDVYWTlWQ0VLUVZZR18zNiIsIml2IjoiWnptMGp3VUYxZ3dpdzc1SmV4OHRWUT09IiwiY2lwaGVydGV4dCI6IlI5UEhJRS9YdEFsVE5JUDNqaVFBQjJQbnc1NTNBY1l3SFZGR0VGVytwUnE5VXIvYWI3KzRja1VqbFlyb1FtZDFMZG5iQTc4WU8rRlZmN0hmeURnWjUrRk41NDFmQm1sTG1BL09Zc3lDTzNlOUNnQUVkVEpRR1JkMlhSUjRnbUdERkJqaHBZdW5FR3BQTFhBZ2JmMmFPQ2VHY3E3UXl6OUxsQ3E2Y0NNZlNROXdPS2JoeUwrQkR6WkVvYlpGd1ZrdUtzakFDZHBueWg1b2s1M080SE1DbnZ0VHZuUzdFT3I0ZnIwLytvZjIzNGYxVW01emc4bnk2bjgzZHRHSzlObzE1YmRtMzgrbEFHTkcvQzE2em55Rk5XVCsrdWU5SmxwNW5iRzdxcmIvVHN3YWd2S09HSnFLR2t5VjNvV1ZpVWo1QXIzajR2ZzlvbVVWNlh1UkVtVkxldC9uRm80UkpTL2ZLWUVlZjd4YmdScVRTa3c0eGczc1BUWFRyUDBHVG1nV2xnWGs5clc5M3VhK250bWdwWElpdG81dUNWN2RtZ0JmV0V5MllYak03YmpMNytlK0lod2xtMGNEYWN5UlpRS0lxMjRPc1lhTFZ3NWRlV3hOV01EZEpWSjhpV1prdnZhZENTRFU5ZWhBcEtINDBQZVAvc2xuMG5ydjR2djJ1Z3lnTG5PVFhrTGxrU1lNTVNFa0ZidWpabDNxNUhkZEY2Vk41N2xRWGcrS0t3cHBHenNLR2FOeTVtcTZFL0U0S0JlQzlobHYreFdZUGJ2WTRYd2U5Yk9TUi9mcFk5M1ltYVBKcGM1eC80UWI3d0tKUmJ2aWs0QWxiS0JSNEw3Q1VUNVhweEJPNDJadEhQK2pCY1dJMFM0NDRXRzdubm40NXBmZVp1THRmUDVNRERxY1c3L3RodHlRN0JLV2NoVzRnbW96K0NxM01neXNHRTEveXRGV1pvYlE0aG1uRWhkVkdwelZvdUt2bFpKVzN2MENNOWVJQ2hvZjhIS2laNXhpQm0yNzF0WnZSMzRYM2V2T1VBN1ZXYyt1eUNpakZ0NTV3bkE5NzgwUEQ0TlBvQ1gyc3FpMVkwb3ZIeFRqWkcxRlp2YURBWjhIeSt4VEoxU1czcTlscVBVR3g5aGFEcVM4TlVTY05YQlBaWnRCMDJRVm9jTE43NFVPdW9sYmN4dUtCQzM5dTY2L0hGdWYwT082RVMvOThWNm5uQXorTTJuV2FSMFU3T2dkdzBPYTAzejFNS0gvOVZpMDFGZWUyVDlveG15em8yRXZIMWE4QnJ5dlJhSWR2cW5SbTRpTEFxY2lOZjUxWFFCRHl1bENnVWhIR09pQndwRHd1VUo2Z3NBN3dPNUd3anVUenR0TWhXbXp1Z0M1OEZrTDNhWDdpZW9DWFcrdS9KOHBwVVJQWGxJOXV4YXJRNVRwODFxTXdxV1dXaXV0S2w0SVQ0RmRQbVlMR2hJY1hPQzZ3R2ZUZTJpQmg4UGdnVGtscUYwU2V2MEwyOGJGMUJtcmZrSk93MXZ0ZjBCWlRYZmUzcFJUVG9qWlh0b3JPQnlSUjVPQjNreVNjeWxpVDJpcER0d3hmUmU0bTZVcXZHb25rNjRQQU83SGNvQ2JKSDlvSUFsYzNMazZ2L3VlMzczUkd1c0pmczhOVjN2MkJURDlhQkx5a2JORHNXc1hnNlMwY1BobFJ0SisyUjdQeTNhR2UrbFdGaFU5enhoQmwrV3FCR2pGVjF2ZmJUOWEyb2Jaak5XL2dDSjRyVWgySzhVKzZFTUsrZlJ5cDY4aTZ0ZlZqUnQrRmlsWDBSWjdKOTVPNzhHSWEreFd6QkxhaWhnYXgwYUNpNHVzeDJrVHF3eWpmRUdiM1Z3VzQ4UGtVa2luVG1OMmg1UUU3VkIxajBhM2ludkIvU0E0OGJCajY4ZEZyMTJqdGdkb0k2VzViYk1lcjNRRnFhRFBRQTZKY3VZNzNLc0RTR09vNER0UEdWdEtSaExNa3NGVURWQzBoUHFxOWtqYlNTZkttK01YNWYrVm1sNVRuU1JyMTBrUDA4YUxCWjFYWUM5dmxGYS9QdExjQ29wRmV4MEU5YzMrT1ptY240QXN1cUxNWGVzQUY4cFpHaFZFeFpMZVEzTVdyZ3NnTUwrVHZHTFNKQ3VWQ2o5YUQxd21IbEFRRjZkKzdDMlVoNElWQW5HK2N0RU5Eci93UmdYM2YzcFhXbnNQMHF6YnkxaHd1dEltaTlWdGZ3SUo4NGV2Q3VjY0hzdDBwRjdmUUgwN1VkeDdrRmIyWkY5WUtDR3gvdURnYkQ4V1hhbGltZ3JnaGROMUJ3Q3FPZkRtVkR6NHBicTJBbEVPV2xVK2tidHJsS1dtc2dEajgzQlZvNENLVTRtZG4vaGd6VnpRWC9aQWZieERZamFrK2NSQnduSHlTL2tQL3ZjcmFXTlcvTFhPT2pNbzU5VlFyMlF0emx4bWphem1UN1Q5NHV5dnJuYmpsRllHSytHb0NLdUVzS3NUTVVhYVUxZVlNL3RzQVd0OUlmeURFdXpEUk5kV3dUOUt5MVNOVlNCVWdDR2ZCRjZyNTlzRGdvOFV2K2k0UjRJNFR1N2JSZDJJQUNXWmo5SkVHOGhmQklrMm41TzFBWTFDRm9Hb0M5YWdhZjFiRzFqeFcra0xYZU84WWVLK3hDSEVIYlBXbWczS1g3eG9MeU1uRjFsNUlDVHY4NkZaT1NhNENVUTRvR2NRM0Jvd09kVFN5K2hBblZJcVhaT0NtWXVLWEo2MFVncEJJYWFZakkyeU16WT0iLCJzaGEyNTYiOiI1QU1RMTRER1FOZGNjS0tzTG9iUmU0bWt4bmJoL3ZCNzEvbWlES3FKOXpJPSJ9'),
            signature = base64.parse('Uwax6dDaWtwOc4MrYIoTTAg9bEGfwG7RumJ+DVodCnY='),
            algorithm = { name: "HMAC", hash: {name: "SHA-256" }};

        var error,
            hmacKey;

        it("importKey raw HMAC SHA-256", function () {

            runs(function () {
                error = undefined;
                cryptoSubtle.importKey('raw', rawKeyData, algorithm, false, ["sign", "verify"])
                    .then(function (result) {
                        hmacKey = result;
                    })
                    .catch(function (e) {
                        error = "importKey ERROR";
                    });
            });

            waitsFor(function () {
                return hmacKey || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(hmacKey).toBeDefined();
                expect(hmacKey.extractable).toBe(false);
                expect(hmacKey.type).toBe("secret");
            });

        });

        it("verify HMAC SHA-256 known answer", function () {

            var verified;

            runs(function () {
                expect(hmacKey).toBeDefined("should be executed after unwrapKey");
            });

            runs(function () {
                error = undefined;
                cryptoSubtle.verify(algorithm, hmacKey, signature, data)
                    .then(function (result) {
                        verified = result;
                    })
                    .catch(function (e) {
                        error = "verify ERROR";
                    });
            });

            waitsFor(function () {
                return (verified !== undefined) || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(verified).toBe(true);
            });

        });

        it("verify HMAC SHA-256 negative", function () {

            var verified;

            runs(function () {
                expect(hmacKey).toBeDefined("should be executed after unwrapKey");
            });

            runs(function () {
                error = undefined;
                cryptoSubtle.verify(algorithm, hmacKey, signature, baddata)
                    .then(function (result) {
                        verified = result;
                    })
                    .catch(function (e) {
                        error = "verify ERROR";
                    });
            });

            waitsFor(function () {
                return (verified !== undefined) || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(verified).toBe(false);
            });

        });

        it("sign HMAC SHA-256 known answer", function () {

            var signature2;

            runs(function () {
                expect(hmacKey).toBeDefined("should be executed after unwrapKey");
            });

            runs(function () {
                error = undefined;
                cryptoSubtle.sign(algorithm, hmacKey, data)
                    .then(function (result) {
                        signature2 = result && new Uint8Array(result);
                    })
                    .catch(function (e) {
                        error = "sign ERROR";
                    });
            });

            waitsFor(function () {
                return signature2 || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(signature2).toBeDefined();
                expect(latin1.stringify(signature2)).toBe(latin1.stringify(signature));
            });

        });
        
        it("generateKey HMAC SHA-256, export", function () {
            var error;

            var keyLengthBytes = 32,
                key,
                keyData;

            runs(function () {
                error = undefined;
                cryptoSubtle.generateKey(
                    {
                        name: "HMAC",
                        hash: {name: "SHA-256"},
                        length: keyLengthBytes
                    },
                    true,
                    []
                )
                .then(function (result) {
                    key = result;
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            });

            waitsFor(function () {
                return key || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(key.extractable).toBe(true);
            });

            runs(function () {
                error = undefined;
                cryptoSubtle.exportKey("raw", key)
                .then(function (result) {
                    keyData = result;
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            });

            waitsFor(function () {
                return keyData || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(keyData).toBeDefined();
                expect(keyData.byteLength).toEqual(keyLengthBytes);
                expect(base16.stringify(keyData)).not.toEqual(base16.stringify([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
            });

            runs(function () {
                error = undefined;
                key = undefined;
                cryptoSubtle.generateKey(
                    {
                        name: "HMAC",
                        hash: {name: "SHA-256"},
                        length: keyLengthBytes
                    },
                    false,
                    []
                )
                .then(function (result) {
                    key = result;
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            });

            waitsFor(function () {
                return key || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
                expect(key.extractable).toBe(false);
            });

            runs(function () {
                error = undefined;
                keyData = undefined;
                try {
                    cryptoSubtle.exportKey("raw", key)
                    .then(function (result) {
                        keyData = result;
                    })
                    .catch(function (result) {
                        error = "ERROR";
                    })
                } catch(e) {
                    error = "ERROR";
                }
            });

            waitsFor(function () {
                return keyData || error;
            });

            runs(function () {
                expect(error).toBeDefined();
                expect(keyData).toBeUndefined();
            });

        });


    });

    // --------------------------------------------------------------------------------

    describe("RSA keys", function () {
        
        beforeEach(function () {
            this.addMatchers({
                toBeAnyOf: function(expecteds) {
                    var result = false;
                    for (var i = 0, l = expecteds.length; i < l; i++) {
                        if (this.actual === expecteds[i]) {
                            result = true;
                            break;
                        }
                    }
                    return result;
                }
            });
        });
        
        it("generateKey RSAES-PKCS1-v1_5", function () {
            var error, pubKey, privKey;
            runs(function () {
                error = undefined;
                cryptoSubtle.generateKey(
                    {
                        name: "RSAES-PKCS1-v1_5",
                        modulusLength: 1024,
                        publicExponent: new Uint8Array([0x01, 0x00, 0x01])
                    },
                    false,
                    ["encrypt", "decrypt"]
                )
                .then(function (result) {
                    pubKey = result.publicKey;
                    privKey = result.privateKey;
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            });
            waitsFor(function () {
                return pubKey || privKey || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(pubKey).toBeDefined();
                expect(pubKey.algorithm.name).toBeAnyOf(["RSAES-PKCS1-v1_5", "rsa-pkcs1-v1_5"]);
                expect(pubKey.extractable).toBeTruthy() // public key forced extractable
                expect(privKey).toBeDefined();
                expect(privKey.algorithm.name).toBeAnyOf(["RSAES-PKCS1-v1_5", "rsa-pkcs1-v1_5"]);
                expect(privKey.extractable).toBeFalsy(); // private key takes the extractable input arg val
            });
        });

        it("generateKey RSA-OAEP", function () {
            var error, pubKey, privKey;
            runs(function () {
                error = undefined;
                cryptoSubtle.generateKey(
                    {
                        name: "RSA-OAEP",
                        modulusLength: 1024,
                        publicExponent: new Uint8Array([0x01, 0x00, 0x01])
                    },
                    false,
                    ["encrypt", "decrypt"]
                )
                .then(function (result) {
                    pubKey = result.publicKey;
                    privKey = result.privateKey;
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            });
            waitsFor(function () {
                return pubKey || privKey || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(pubKey).toBeDefined();
                expect(pubKey.algorithm.name).toBeAnyOf(["RSA-OAEP", "rsa-oaep"]);
                expect(pubKey.extractable).toBeTruthy() // public key forced extractable
                expect(privKey).toBeDefined();
                expect(privKey.algorithm.name).toBeAnyOf(["RSA-OAEP", "rsa-oaep"]);
                expect(privKey.extractable).toBeFalsy(); // private key takes the extractable input arg val
            });
        });

        it("generateKey RSASSA-PKCS1-v1_5", function () {
            var error, pubKey, privKey;
            runs(function () {
                error = undefined;
                cryptoSubtle.generateKey(
                    {
                        name: "RSASSA-PKCS1-v1_5",
                        modulusLength: 1024,
                        publicExponent: new Uint8Array([0x01, 0x00, 0x01])
                    },
                    false,
                    ["sign", "verify"]
                )
                .catch(function (result) {
                    error = "ERROR";
                })
                .then(function (result) {
                    pubKey = result.publicKey;
                    privKey = result.privateKey;
                })
            });
            waitsFor(function () {
                return pubKey || privKey || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(pubKey).toBeDefined();
                expect(pubKey.algorithm.name).toBeAnyOf(["RSASSA-PKCS1-v1_5", "rsassa-pkcs1-v1_5"]);
                expect(pubKey.extractable).toBeTruthy(); // public key forced extractable
                expect(privKey).toBeDefined();
                expect(privKey.algorithm.name).toBeAnyOf(["RSASSA-PKCS1-v1_5", "rsassa-pkcs1-v1_5"]);
                expect(privKey.extractable).toBeFalsy(); // private key takes the extractable input arg val
            });
        });

        it("importKey/exportKey spki RSAES-PKCS1-v1_5 public key", function () {
            var error,
                key,
                exportedSpkiKeyData;

            // openssl genrsa -out pair.pem 2048
            // openssl rsa -in pair.pem -out pubkey.der -outform DER -pubout
            // openssl enc -base64 -in pubkey.der
            var spkiPubKeyData = base64.parse(
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsjUf4UZyuZ5JKazU0Kq/" +
                "dbaVY0oQxYZcsCQxRrjKF6yQaHACzeubHHaXRLwXkCVvBf2V0HBdJ/xCiIqwos3X" +
                "CMgMWu0mzlSxfv0kyAuH46SzTZdAt5hJPMSjt+eTJI+9hYq6DNqN09ujBwlhQM2J" +
                "hI9V3tZhBD5nQPTNkXYRD3aZp5wWtErIdXDP4ZXFcPdu6sLjH68WZuR9M6Q5Xztz" +
                "O9DA7+m/7CHDvWWhlvuN15t1a4dwBuxlY0eZh1JjM6OPH9zJ2OKJIVOLNIE2WejQ" +
                "E5a7IarLOHM8bYtBZ7/tSyx3MkN40OjPA7ZWiEpyT/wDiZo45aLlN4vsWJpIcdqS" +
                "RwIDAQAB"
            );

            runs(function () {
                error = undefined;
                cryptoSubtle.importKey("spki", spkiPubKeyData, { name: "RSAES-PKCS1-v1_5" }, true, [])
                .then(function (result) {
                    key = result;
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            });

            waitsFor(function () {
                return key || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
                expect(key.type).toBe("public");
                expect(key.extractable).toBe(true);
                // TODO: confirm that these checks are valid and add them
                // expect(key.algorithm.name).toBe("RSAES-PKCS1-v1_5");
            });

            // verify exported key matches what was imported
            runs(function () {
                error = undefined;
                cryptoSubtle.exportKey("spki", key)
                .then(function (result) {
                    exportedSpkiKeyData = result && new Uint8Array(result);
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            });

            waitsFor(function () {
                return error || exportedSpkiKeyData;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(exportedSpkiKeyData).toBeDefined();
                expect(base16.stringify(exportedSpkiKeyData)).toBe(base16.stringify(spkiPubKeyData));
            });
        });

        it("importKey pkcs8 RSAES-PKCS1-v1_5 private key", function () {
            var error,
                privKey,
                pkcs8PrivKeyData2;

            // <private key of pair generated above>
            // openssl pkcs8 -topk8 -inform PEM -outform DER -in pair.pem -out privkey.der -nocrypt
            // openssl enc -base64 -in privkey.der
            var pkcs8PrivKeyData = base64.parse(
                "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCyNR/hRnK5nkkp" +
                "rNTQqr91tpVjShDFhlywJDFGuMoXrJBocALN65scdpdEvBeQJW8F/ZXQcF0n/EKI" +
                "irCizdcIyAxa7SbOVLF+/STIC4fjpLNNl0C3mEk8xKO355Mkj72FiroM2o3T26MH" +
                "CWFAzYmEj1Xe1mEEPmdA9M2RdhEPdpmnnBa0Ssh1cM/hlcVw927qwuMfrxZm5H0z" +
                "pDlfO3M70MDv6b/sIcO9ZaGW+43Xm3Vrh3AG7GVjR5mHUmMzo48f3MnY4okhU4s0" +
                "gTZZ6NATlrshqss4czxti0Fnv+1LLHcyQ3jQ6M8DtlaISnJP/AOJmjjlouU3i+xY" +
                "mkhx2pJHAgMBAAECggEAfHDkZicPjdaeOF/b7CqPr99jygW6WHRO3SEo173KQWXb" +
                "IVK2Yp0Xn3SghPrjaWD6ejBuITOVmYpp23cdiVI7yoIHPqdD5ej2WTrkKF0E803b" +
                "d18bbhkFa03VFWK8OVe2fD43VSp4x2wkF5HRO7NLSCnfSNBixtfculs4AU908lov" +
                "lr+aJJYeaUvdvpo5Vk15DVXxO+YiPjVd+oZ/jfZQl3WvOZH9t6STF4Sk4KEntdop" +
                "kFQA6Z3dzcrp5XLMq7twMZMokVfLf0rW+1GX//LKxZhq0UM2HdPliWFvzB5WUbTe" +
                "23cMIanBxONs7alz7J16Pt/nfFTbJpwuyRE9pODLgQKBgQDrSqb1pVMyk9rTIB9E" +
                "ZyaWdyiRHkpzAcYyQGMN/4gLmAlLCQnclTPly7fl33y9uMmHVXd2zoOYSvSLOoNZ" +
                "6mJTHRg59142r92FVpcHz3k5JHjWrLpCTv2lD1NpJTFHwiEv37mbJWgCtfKcN9u1" +
                "gKg9DAKektJoS09pxDqXPqZuFwKBgQDB5E/94gNQ4L7IlY/g3tEBeQu0sbeHMyIe" +
                "MxE6p2HJWCi2akH27nd8AVfUtAnDkrzmcTCRY2CjJH4nM759IhjHlaUzpUeRQb43" +
                "ari8QnXLeE53uVpgDFTtJjH5ytua846H9r4utetr2Y+giAXU3+CdOldfGAJdwajB" +
                "eHigOjdLUQKBgQCR+IRQDTrqO9Qb+ueq9ht4aYBfV110r/sXnd5WBtuN5cqOJJNb" +
                "p6zEuXfjQp0Ozp8oOJuet0vopUfFQI3QsJpDWd93xsFKSByz5h5YmBxqmPfmps3+" +
                "6SZuym1C4/IIxKT2IGPznmdCl0JmLDlABwtYpCTT395tGZuw0C5ROmriDQKBgQCK" +
                "MqmxU/75DrftUG0U4rwmSJjHWkRt4UxYKh4FqHhSgrvCCUqrLp2LjYmE2i57b4Ok" +
                "3Ni5SBQBNGmWl5MWrc7rswXlIdE4/5sM9MxnoxdCx6VmQH7iJugBgE/us2CDuUXG" +
                "M2Cq+o+qd4+f5FQDvu7iIktURFCrcvVNsQiJa/UtgQKBgCGZduyk7mtYatd9M3tG" +
                "HhMA+Q47KB0wbSPhn0YhZc+0VNZkjc5cS9IDn08cEA4HRRfob3Ou0+N9qla3MqXt" +
                "R9C3zb152OL4MmW9/u/0yoPu8NavhX+CbkJ56OeaPsd99a9pEJTRf0+YIkpKA0EZ" +
                "lKXOV21h9WXMBq+z/12CUyy0"
            );

            // import pkcs8-formatted private key
            runs(function () {
                cryptoSubtle.importKey("pkcs8", pkcs8PrivKeyData, { name: "RSAES-PKCS1-v1_5" }, true, [])
                .then(function (result) {
                    privKey = result;
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            });

            waitsFor(function () {
                return privKey || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(privKey).toBeDefined();
                expect(privKey.type).toBe("private");
                expect(privKey.extractable).toBe(true);
                expect(privKey.algorithm.name).toBe("RSAES-PKCS1-v1_5");
            });

        });

    });

    // --------------------------------------------------------------------------------

    describe("RSA operations", function () {

        beforeEach(function () {
            this.addMatchers({
                toBeAnyOf: function(expecteds) {
                    var result = false;
                    for (var i = 0, l = expecteds.length; i < l; i++) {
                        if (this.actual === expecteds[i]) {
                            result = true;
                            break;
                        }
                    }
                    return result;
                }
            });
        });
        
        it("RSAES-PKCS1-v1_5 encrypt/decrypt round trip", function () {
            var error,
                clearText = base16.parse("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            var encrypted;
            var pubKey_RSAES_PKCS1_v1_5, privKey_RSAES_PKCS1_v1_5;

            // Generate a fresh key pair.
            runs(function () {
                error = undefined;
                cryptoSubtle.generateKey(
                    {
                        name: "RSAES-PKCS1-v1_5",
                        modulusLength: 1024,
                        publicExponent: new Uint8Array([0x01, 0x00, 0x01])
                    },
                    false,
                    ["encrypt", "decrypt"]
                )
                .then(function (result) {
                    pubKey_RSAES_PKCS1_v1_5 = result.publicKey;
                    privKey_RSAES_PKCS1_v1_5 = result.privateKey;
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            });
            waitsFor(function () {
                return pubKey_RSAES_PKCS1_v1_5 || privKey_RSAES_PKCS1_v1_5 || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(pubKey_RSAES_PKCS1_v1_5).toBeDefined();
                expect(pubKey_RSAES_PKCS1_v1_5.extractable).toBeTruthy(); // public key forced extractable
                expect(privKey_RSAES_PKCS1_v1_5).toBeDefined();
                expect(privKey_RSAES_PKCS1_v1_5.extractable).toBeFalsy(); // private key takes the extractable input arg val
            });

            // encrypt clearText with the public key
            runs(function () {
                error = undefined;
                cryptoSubtle.encrypt({ name: "RSAES-PKCS1-v1_5" }, pubKey_RSAES_PKCS1_v1_5, clearText)
                .then(function (result) {
                    encrypted = result && new Uint8Array(result);
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            });

            waitsFor(function () {
                return encrypted || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(encrypted).toBeDefined();
                expect(base16.stringify(encrypted)).not.toBe(base16.stringify(clearText));
            });

            var decrypted;

            // decrypt cipherText with the private key, should get the same clearText back
            runs(function () {
                error = undefined;
                cryptoSubtle.decrypt({ name: "RSAES-PKCS1-v1_5" }, privKey_RSAES_PKCS1_v1_5, encrypted)
                .then(function (result) {
                    decrypted = result && new Uint8Array(result);
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            });

            waitsFor(function () {
                return decrypted || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(decrypted).toBeDefined();
                expect(base16.stringify(decrypted)).toBe(base16.stringify(clearText));
            });
        });

        it("RSAES-PKCS1-v1_5 encrypt/decrypt known answer", function () {
            // Because the random data in PKCS1.5 padding makes the encryption output non-
            // deterministic, we cannot easily do a typical known-answer test for RSA
            // encryption / decryption. Instead we will take a known-good encrypted
            // message, decrypt it, re-encrypt it, then decrypt again, verifying that the
            // original known cleartext is the result.

            var spkiPubKeyData = base16.parse(
                "30819f300d06092a864886f70d010101050003818d0030818902818100a8" +
                "d30894b93f376f7822229bfd2483e50da944c4ab803ca31979e0f47e70bf" +
                "683c687c6b3e80f280a237cea3643fd1f7f10f7cc664dbc2ecd45be53e1c" +
                "9b15a53c37dbdad846c0f8340c472abc7821e4aa7df185867bf38228ac3e" +
                "cc1d97d3c8b57e21ea6ba57b2bc3814a436e910ee8ab64a0b7743a927e94" +
                "4d3420401f7dd50203010001"
            );
            var pkcs8PrivKeyData = base16.parse(
                "30820276020100300d06092a864886f70d0101010500048202603082025c" +
                "02010002818100a8d30894b93f376f7822229bfd2483e50da944c4ab803c" +
                "a31979e0f47e70bf683c687c6b3e80f280a237cea3643fd1f7f10f7cc664" +
                "dbc2ecd45be53e1c9b15a53c37dbdad846c0f8340c472abc7821e4aa7df1" +
                "85867bf38228ac3ecc1d97d3c8b57e21ea6ba57b2bc3814a436e910ee8ab" +
                "64a0b7743a927e944d3420401f7dd5020301000102818100896cdffb50a0" +
                "691bd00ad9696933243a7c5861a64684e8d74b91aed0d76c28234da9303e" +
                "8c6ea2f89b141a9d5ea9a4ddd3d8eb9503dcf05ba0b1fd76060b281e3ae4" +
                "b9d497fb5519bdf1127db8ad412d6a722686c78df3e3002acca960c6b2a2" +
                "42a83ace5410693c03ce3d74cb9c9a7bacc8e271812920d1f53fee9312ef" +
                "4eb1024100d09c14418ce92af7cc62f7cdc79836d8c6e3d0d33e7229cc11" +
                "d732cbac75aa4c56c92e409a3ccbe75d4ce63ac5adca33080690782c6371" +
                "e3628134c3534ca603024100cf2d3206f6deea2f39b70351c51f85436200" +
                "5aa8f643e49e22486736d536e040dc30a2b4f9be3ab212a88d1891280874" +
                "b9a170cdeb22eaf61c27c4b082c7d1470240638411a5b3b307ec6e744802" +
                "c2d4ba556f8bfe72c7b76e790b89bd91ac13f5c9b51d04138d80b3450c1d" +
                "4337865601bf96748b36c8f627be719f71ac3c70b441024065ce92cfe34e" +
                "a58bf173a2b8f3024b4d5282540ac581957db3e11a7f528535ec098808dc" +
                "a0013ffcb3b88a25716757c86c540e07d2ad8502cdd129118822c30f0240" +
                "420a4983040e9db46eb29f1315a0d7b41cf60428f7460fce748e9a1a7d22" +
                "d7390fa328948e7e9d1724401374e99d45eb41474781201378a4330e8e80" +
                "8ce63551"
            );
            var cleartext = base16.parse(
                "ec358ed141c45d7e03d4c6338aebad718e8bcbbf8f8ee6f8d9f4b9ef06d8" +
                "84739a398c6bcbc688418b2ff64761dc0ccd40e7d52bed03e06946d0957a" +
                "eef9e822"
            );
            var ciphertext = base16.parse(
                "6106441c2b7a4b1a16260ed1ae4fe6135247345dc8e674754bbda6588c6c" +
                "0d95a3d4d26bb34cdbcbe327723e80343bd7a15cd4c91c3a44e6cb9c6cd6" +
                "7ad2e8bf41523188d9b36dc364a838642dcbc2c25e85dfb2106ba47578ca" +
                "3bbf8915055aea4fa7c3cbfdfbcc163f04c234fb6d847f39bab9612ecbee" +
                "04626e945c3ccf42"
            );
            var algorithm = { name: "RSAES-PKCS1-v1_5" };
            var publicKey, privateKey;
            var error;
            var decrypted1, encrypted, decrypted2;

            // import the keys
            runs(function () {
                error = undefined;
                cryptoSubtle.importKey("spki", spkiPubKeyData, algorithm, true, ["encrypt"])
                .then(function (result) {
                    publicKey = result;
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            });
            waitsFor(function () {
                return publicKey || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(publicKey).toBeDefined();
                expect(publicKey.type).toBe("public");
            });
            runs(function () {
                error = undefined;
                cryptoSubtle.importKey("pkcs8", pkcs8PrivKeyData, algorithm, true, ["decrypt"])
                .then(function (result) {
                    privateKey = result;
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            });
            waitsFor(function () {
                return privateKey || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(privateKey).toBeDefined();
                expect(privateKey.type).toBe("private");
            });
            
            // decrypt the known-good ciphertext
            runs(function () {
                error = undefined;
                cryptoSubtle.decrypt(algorithm, privateKey, ciphertext)
                .then(function (result) {
                    decrypted1 = result && new Uint8Array(result);
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            });
            waitsFor(function () {
                return decrypted1 || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(decrypted1).toBeDefined();
                expect(base16.stringify(decrypted1)).toBe(base16.stringify(cleartext));
            });
            
            // encrypt
            runs(function () {
                error = undefined;
                cryptoSubtle.encrypt(algorithm, publicKey, decrypted1)
                .then(function (result) {
                    encrypted = result && new Uint8Array(result);
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            });
            waitsFor(function () {
                return encrypted || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(encrypted).toBeDefined();
            });

            // decrypt again
            runs(function () {
                error = undefined;
                cryptoSubtle.decrypt(algorithm, privateKey, encrypted)
                .then(function (result) {
                    decrypted2 = result && new Uint8Array(result);
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            });
            waitsFor(function () {
                return decrypted2 || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(decrypted2).toBeDefined();
                expect(base16.stringify(decrypted2)).toBe(base16.stringify(cleartext));
            });
          
        });

        it("RSA-OAEP encrypt/decrypt round trip", function () {
            var error,
                clearText = base16.parse("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            var encrypted;
            var pubKey, privKey;

            // Generate a fresh key pair.
            runs(function () {
                error = undefined;
                cryptoSubtle.generateKey(
                    {
                        name: "RSA-OAEP",
                        modulusLength: 1024,
                        publicExponent: new Uint8Array([0x01, 0x00, 0x01])
                    },
                    false,
                    ["encrypt", "decrypt"]
                )
                .then(function (result) {
                    pubKey = result.publicKey;
                    privKey = result.privateKey;
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            });
            waitsFor(function () {
                return pubKey || privKey || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(pubKey).toBeDefined();
                expect(pubKey.extractable).toBeTruthy(); // public key forced extractable
                expect(privKey).toBeDefined();
                expect(privKey.extractable).toBeFalsy(); // private key takes the extractable input arg val
            });

            // encrypt clearText with the public key
            runs(function () {
                error = undefined;
                cryptoSubtle.encrypt({ name: "RSA-OAEP", hash: {name: "SHA-256"} }, pubKey, clearText)
                .then(function (result) {
                    encrypted = result && new Uint8Array(result);
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            });

            waitsFor(function () {
                return encrypted || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(encrypted).toBeDefined();
                expect(base16.stringify(encrypted)).not.toBe(base16.stringify(clearText));
            });

            var decrypted;

            // decrypt cipherText with the private key, should get the same clearText back
            runs(function () {
                error = undefined;
                cryptoSubtle.decrypt({ name: "RSA-OAEP", hash: {name: "SHA-256"} }, privKey, encrypted)
                .then(function (result) {
                    decrypted = result && new Uint8Array(result);
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            });

            waitsFor(function () {
                return decrypted || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(decrypted).toBeDefined();
                expect(base16.stringify(decrypted)).toBe(base16.stringify(clearText));
            });
        });

        it("RSA-OAEP encrypt/decrypt known answer", function () {
            // Because the random data in OAEP padding makes the encryption output non-
            // deterministic, we cannot easily do a typical known-answer test for RSA
            // encryption / decryption. Instead we will take a known-good encrypted
            // message, decrypt it, re-encrypt it, then decrypt again, verifying that the
            // original known cleartext is the result.
            
            // keys and ciphertext from example 10 of oaep-vect.txt from
            // https://das-labor.org/svn/microcontroller-2/crypto-lib/testvectors/rsa-pkcs-1v2-1-vec/oaep-vect.txt
            
            var pubKeyJwk = latin1.parse(JSON.stringify({
                alg:    "RSA-OAEP",
                kty:    "RSA",
                n:      base64.stringifyUrlSafe(base16.parse(
                        "ae45ed5601cec6b8cc05f803935c674d" +
                        "dbe0d75c4c09fd7951fc6b0caec313a8" +
                        "df39970c518bffba5ed68f3f0d7f22a4" +
                        "029d413f1ae07e4ebe9e4177ce23e7f5" +
                        "404b569e4ee1bdcf3c1fb03ef113802d" +
                        "4f855eb9b5134b5a7c8085adcae6fa2f" +
                        "a1417ec3763be171b0c62b760ede23c1" +
                        "2ad92b980884c641f5a8fac26bdad4a0" +
                        "3381a22fe1b754885094c82506d4019a" +
                        "535a286afeb271bb9ba592de18dcf600" +
                        "c2aeeae56e02f7cf79fc14cf3bdc7cd8" +
                        "4febbbf950ca90304b2219a7aa063aef" +
                        "a2c3c1980e560cd64afe779585b61076" +
                        "57b957857efde6010988ab7de417fc88" +
                        "d8f384c4e6e72c3f943e0c31c0c4a5cc" +
                        "36f879d8a3ac9d7d59860eaada6b83bb"
                )),
                e:      base64.stringifyUrlSafe(base16.parse("010001")),
                ext:    true,
                use:    "enc"
            }));

            var privKeyJwk = latin1.parse(JSON.stringify({
                alg:    "RSA-OAEP",
                kty:    "RSA",
                n:      base64.stringifyUrlSafe(base16.parse(
                        "ae45ed5601cec6b8cc05f803935c674d" +
                        "dbe0d75c4c09fd7951fc6b0caec313a8" +
                        "df39970c518bffba5ed68f3f0d7f22a4" +
                        "029d413f1ae07e4ebe9e4177ce23e7f5" +
                        "404b569e4ee1bdcf3c1fb03ef113802d" +
                        "4f855eb9b5134b5a7c8085adcae6fa2f" +
                        "a1417ec3763be171b0c62b760ede23c1" +
                        "2ad92b980884c641f5a8fac26bdad4a0" +
                        "3381a22fe1b754885094c82506d4019a" +
                        "535a286afeb271bb9ba592de18dcf600" +
                        "c2aeeae56e02f7cf79fc14cf3bdc7cd8" +
                        "4febbbf950ca90304b2219a7aa063aef" +
                        "a2c3c1980e560cd64afe779585b61076" +
                        "57b957857efde6010988ab7de417fc88" +
                        "d8f384c4e6e72c3f943e0c31c0c4a5cc" +
                        "36f879d8a3ac9d7d59860eaada6b83bb"
                )),
                e:      base64.stringifyUrlSafe(base16.parse("010001")),
                d:      base64.stringifyUrlSafe(base16.parse(
                        "056b04216fe5f354ac77250a4b6b0c85" +
                        "25a85c59b0bd80c56450a22d5f438e59" +
                        "6a333aa875e291dd43f48cb88b9d5fc0" +
                        "d499f9fcd1c397f9afc070cd9e398c8d" +
                        "19e61db7c7410a6b2675dfbf5d345b80" +
                        "4d201add502d5ce2dfcb091ce9997bbe" +
                        "be57306f383e4d588103f036f7e85d19" +
                        "34d152a323e4a8db451d6f4a5b1b0f10" +
                        "2cc150e02feee2b88dea4ad4c1baccb2" +
                        "4d84072d14e1d24a6771f7408ee30564" +
                        "fb86d4393a34bcf0b788501d193303f1" +
                        "3a2284b001f0f649eaf79328d4ac5c43" +
                        "0ab4414920a9460ed1b7bc40ec653e87" +
                        "6d09abc509ae45b525190116a0c26101" +
                        "848298509c1c3bf3a483e7274054e15e" +
                        "97075036e989f60932807b5257751e79"
                )),
                p:      base64.stringifyUrlSafe(base16.parse(
                        "ecf5aecd1e5515fffacbd75a2816c6eb" +
                        "f49018cdfb4638e185d66a7396b6f809" +
                        "0f8018c7fd95cc34b857dc17f0cc6516" +
                        "bb1346ab4d582cadad7b4103352387b7" +
                        "0338d084047c9d9539b6496204b3dd6e" +
                        "a442499207bec01f964287ff6336c398" +
                        "4658336846f56e46861881c10233d217" +
                        "6bf15a5e96ddc780bc868aa77d3ce769"
                )),
                q:      base64.stringifyUrlSafe(base16.parse(
                        "bc46c464fc6ac4ca783b0eb08a3c841b" +
                        "772f7e9b2f28babd588ae885e1a0c61e" +
                        "4858a0fb25ac299990f35be85164c259" +
                        "ba1175cdd7192707135184992b6c29b7" +
                        "46dd0d2cabe142835f7d148cc161524b" +
                        "4a09946d48b828473f1ce76b6cb6886c" +
                        "345c03e05f41d51b5c3a90a3f24073c7" +
                        "d74a4fe25d9cf21c75960f3fc3863183"
                )),
                dp:     base64.stringifyUrlSafe(base16.parse(
                        "c73564571d00fb15d08a3de9957a5091" +
                        "5d7126e9442dacf42bc82e862e5673ff" +
                        "6a008ed4d2e374617df89f17a160b43b" +
                        "7fda9cb6b6b74218609815f7d45ca263" +
                        "c159aa32d272d127faf4bc8ca2d77378" +
                        "e8aeb19b0ad7da3cb3de0ae7314980f6" +
                        "2b6d4b0a875d1df03c1bae39ccd833ef" +
                        "6cd7e2d9528bf084d1f969e794e9f6c1"
                )),
                dq:     base64.stringifyUrlSafe(base16.parse(
                        "2658b37f6df9c1030be1db68117fa9d8" +
                        "7e39ea2b693b7e6d3a2f70947413eec6" +
                        "142e18fb8dfcb6ac545d7c86a0ad48f8" +
                        "457170f0efb26bc48126c53efd1d1692" +
                        "0198dc2a1107dc282db6a80cd3062360" +
                        "ba3fa13f70e4312ff1a6cd6b8fc4cd9c" +
                        "5c3db17c6d6a57212f73ae29f619327b" +
                        "ad59b153858585ba4e28b60a62a45e49"
                )),
                qi:     base64.stringifyUrlSafe(base16.parse(
                        "6f38526b3925085534ef3e415a836ede" +
                        "8b86158a2c7cbfeccb0bd834304fec68" +
                        "3ba8d4f479c433d43416e63269623cea" +
                        "100776d85aff401d3fff610ee65411ce" +
                        "3b1363d63a9709eede42647cea561493" +
                        "d54570a879c18682cd97710b96205ec3" +
                        "1117d73b5f36223fadd6e8ba90dd7c0e" +
                        "e61d44e163251e20c7f66eb305117cb8"
                )),
                ext:    true,
                use:    "enc"
            }));
            
            var cleartext = base16.parse(
                    "8bba6bf82a6c0f86d5f1756e97956870" +
                    "b08953b06b4eb205bc1694ee"
            );

            var ciphertext =  base16.parse(
                    "53ea5dc08cd260fb3b858567287fa915" +
                    "52c30b2febfba213f0ae87702d068d19" +
                    "bab07fe574523dfb42139d68c3c5afee" +
                    "e0bfe4cb7969cbf382b804d6e6139614" +
                    "4e2d0e60741f8993c3014b58b9b1957a" +
                    "8babcd23af854f4c356fb1662aa72bfc" +
                    "c7e586559dc4280d160c126785a723eb" +
                    "eebeff71f11594440aaef87d10793a87" +
                    "74a239d4a04c87fe1467b9daf85208ec" +
                    "6c7255794a96cc29142f9a8bd418e3c1" +
                    "fd67344b0cd0829df3b2bec602531962" +
                    "93c6b34d3f75d32f213dd45c6273d505" +
                    "adf4cced1057cb758fc26aeefa441255" +
                    "ed4e64c199ee075e7f16646182fdb464" +
                    "739b68ab5daff0e63e9552016824f054" +
                    "bf4d3c8c90a97bb6b6553284eb429fcc"
            );
            
            var publicKey, privateKey, error;
            var algorithm = { name: "RSA-OAEP", hash: {name: "SHA-1"} };
            var decrypted1, encrypted, decrypted2;
            
            // import the public key
            runs(function () {
                error = undefined;
                cryptoSubtle.importKey("jwk", pubKeyJwk, algorithm, true, ["encrypt", "decrypt"])
                .then(function (result) {
                    publicKey = result;
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            })
            waitsFor(function () {
                return publicKey || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(publicKey).toBeDefined();
                expect(publicKey.algorithm.name).toBeAnyOf(["RSA-OAEP", "rsa-oaep"]);
                expect(publicKey.type).toBe("public");;
            });
            
            // import the private key
            runs(function () {
                error = undefined;
                cryptoSubtle.importKey("jwk", privKeyJwk, algorithm, true, ["encrypt", "decrypt"])
                .then(function (result) {
                    privateKey = result;
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            })
            waitsFor(function () {
                return privateKey || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(privateKey).toBeDefined();
                expect(privateKey.algorithm.name).toBeAnyOf(["RSA-OAEP", "rsa-oaep"]);
                expect(privateKey.type).toBe("private");;
            });

            // decrypt the known-good ciphertext
            runs(function () {
                error = undefined;
                cryptoSubtle.decrypt(algorithm, privateKey, ciphertext)
                .then(function (result) {
                    decrypted1 = result;
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            });
            waitsFor(function () {
                return decrypted1 || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(decrypted1).toBeDefined();
                expect(base16.stringify(new Uint8Array(decrypted1))).toBe(base16.stringify(cleartext));
            });
            
            // encrypt
            runs(function () {
                error = undefined;
                cryptoSubtle.encrypt(algorithm, publicKey, decrypted1)
                .then(function (result) {
                    encrypted = result && new Uint8Array(result);
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            });
            waitsFor(function () {
                return encrypted || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(encrypted).toBeDefined();
            });

            // decrypt again
            runs(function () {
                error = undefined;
                cryptoSubtle.decrypt(algorithm, privateKey, encrypted)
                .then(function (result) {
                    decrypted2 = result && new Uint8Array(result);
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            });
            waitsFor(function () {
                return decrypted2 || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(decrypted2).toBeDefined();
                expect(base16.stringify(decrypted2)).toBe(base16.stringify(cleartext));
            });

        });

        it("RSASSA-PKCS1-v1_5 SHA-256 sign/verify round trip", function () {
            var error;
            var data = base16.parse("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            var signature;
            var pubKey_RSASSA_PKCS1_v1_5, privKey_RSASSA_PKCS1_v1_5;
            
            // Generate a fresh key pair
            runs(function () {
                error = undefined;
                cryptoSubtle.generateKey(
                    {
                        name: "RSASSA-PKCS1-v1_5",
                        modulusLength: 1024,
                        publicExponent: new Uint8Array([0x01, 0x00, 0x01])
                    },
                    false,
                    ["sign", "verify"]
                )
                .catch(function (result) {
                    error = "ERROR";
                })
                .then(function (result) {
                    pubKey_RSASSA_PKCS1_v1_5 = result.publicKey;
                    privKey_RSASSA_PKCS1_v1_5 = result.privateKey;
                })
            });
            waitsFor(function () {
                return pubKey_RSASSA_PKCS1_v1_5 || privKey_RSASSA_PKCS1_v1_5 || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(pubKey_RSASSA_PKCS1_v1_5).toBeDefined();
                expect(pubKey_RSASSA_PKCS1_v1_5.extractable).toBeTruthy() // public key is forced extractable
                expect(privKey_RSASSA_PKCS1_v1_5).toBeDefined();
                expect(privKey_RSASSA_PKCS1_v1_5.extractable).toBeFalsy(); // private key takes the extractable input arg val
            });

            // sign data with the private key
            runs(function () {
                error = undefined;
                cryptoSubtle.sign({ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, privKey_RSASSA_PKCS1_v1_5, data)
                .then(function (result) {
                    signature = result && new Uint8Array(result);
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            });

            waitsFor(function () {
                return signature || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                // TODO: more tests
                expect(signature).toBeDefined();
            });

            var verified;

            // verify data with the public key
            runs(function () {
                error = undefined;
                cryptoSubtle.verify({ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, pubKey_RSASSA_PKCS1_v1_5, signature, data)
                .then(function (result) {
                    verified = result;
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            });

            waitsFor(function () {
                return verified !== undefined || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(verified).toBe(true);
            });

            // verify data with the public key and bad signature
            runs(function () {
                error = undefined;
                verified = undefined;
                signature[10] = signature[10] ^ 0xFF;
                cryptoSubtle.verify({ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, pubKey_RSASSA_PKCS1_v1_5, signature, data)
                .then(function (result) {
                    verified = result;
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            });

            waitsFor(function () {
                return verified !== undefined || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(verified).toBe(false);
            });

        });
        
        it("RSASSA-PKCS1-v1_5 SHA-256 verify known answer", function () {
            var pubKeyDataSpki = base64.parse("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm84o+RfF7KdJgbE6lggYAdUxOArfgCsGCq33+kwAK/Jmf3VnNo1NOGlRpLQUFAqYRqG29u4wl8fH0YCn0v8JNjrxPWP83Hf5Xdnh7dHHwHSMc0LxA2MyYlGzn3jOF5dG/3EUmUKPEjK/SKnxeKfNRKBWnm0K1rzCmMUpiZz1pxgEB/cIJow6FrDAt2Djt4L1u6sJ/FOy/zA1Hf4mZhytgabDfapxAzsks+HF9rMr3wXW5lSP6y2lM+gjjX/bjqMLJQ6iqDi6++7ScBh0oNHmgUxsSFE3aBRBaCL1kz0HOYJe26UqJqMLQ71SwvjgM+KnxZvKa1ZHzQ+7vFTwE7+yxwIDAQAB");
            var data = base64.parse("eyJub25yZXBsYXlhYmxlIjpmYWxzZSwia2V5cmVzcG9uc2VkYXRhIjp7Im1hc3RlcnRva2VuIjp7InRva2VuZGF0YSI6ImV5SnpaWEYxWlc1alpXNTFiV0psY2lJNk9ETXNJbkpsYm1WM1lXeDNhVzVrYjNjaU9qRXpOalV4T1RRM05qa3NJbk5sYzNOcGIyNWtZWFJoSWpvaVFsRkRRVUZCUlVKRlJ6aERNM2hvY25aV1FqQmFibVZtTnpoUk1IRlhUMEZ2Ulc0eWFVcHRRMlJ0YUZZeWJGTjZTbXBVUjBoWmRFdDNOamRaT1dreVdtTXhabEZ1TW00MVMwZDVjVkp2YURORlZGUTBSbTFKUW1sU1ZIRnlLMlp4TjNJNVNscDRTSGhxYVRORVMyaHdiWGQwVURkQ2JVNWtkRlkxWlV4bmF6RXpjMDVqVldOMWVFeEdUVEpxTTI1R1MwOXpjbWcxWjJOMFZ6VkdVMnBWTmxGS1QyTnBUM2d3TTJ4TVpqQnlNRU5KZWpKU1NVeGpSMGhpU0ZSTlJtSmlURGh5Wmt4eU4wazJUa2g0TVVSblZXMXlOSGd5Tnl0Rk1Hc3hjbkV5U1d4Vk0xTmFORlJYYUVkNWMzVnVUVlpJTW5SNFptTlhSVDBpTENKbGVIQnBjbUYwYVc5dUlqb3hNelkxTVRrME9ESTVMQ0p6WlhKcFlXeHVkVzFpWlhJaU9qWTNOemswT1RZd016RTJOak01TkRSOSIsInNpZ25hdHVyZSI6IkFRRUFnUUFCQVNDOFNyTXI5ZDZZQVhha2tvV0VxNmRGK215akdZbDJCZFRFVWdYS04zQ3kySFg4aGlFPSJ9LCJzY2hlbWUiOiJBU1lNTUVUUklDX1dSQVBQRUQiLCJrZXlkYXRhIjp7ImtleXBhaXJpZCI6InJzYUtleXBhaXJJZCIsImhtYWNrZXkiOiJaWGxLYUdKSFkybFBhVXBUVlRCRmRGUXdSa1pWUTBselNXMVdkVmw1U1RaSmEwVjRUV3BvU0ZFd01HbG1VUzU2WjE5dlZIZHBUVTVpTkdsUFRHUlBaR1UwWldsdFJHOW1ObWt0VTNjMVpqZDFObWRQUTE5Zk1GbG1XblJsWHpsMVduQkRNVEpDTUZnNWJtcGFhVzFuTUZOWlYxaFZTVVJ3VDNNNGJHSnlPV1ZKTUdsc2NuTmFiRXQ0YUd4TE1taDZjR3d4TW1sV1ptSjVTVGhvUjI1b2MxZElia2hYY21KcmQwRmpMWEp4V2tobVREZFNjVE5RTlZwek4xVk1kREpXVEhWMU9FVlRiRlJQTVVSak1qSXdibU53UVZOVVJXUTFPRTl2VlhkQ2NVcHlabXhmU0U1M1FWOTBUMlJUZUhadlVWSm5OekJSZEhKdGFGQlFjbUpFVkZScFVqaFBUazV5VVU1aVNrRmZlRUZZUmxoSFZucHhRVzV0YkRCbVpVVTRWVXhoYVdkV1Ftb3hlSEJ4YUMxaU9YUnZiRlpGTTBzd1pGaFZSRGN4TTNoYVppMHhjV2N4UVZSV2NXMUVVWFpNVDNwbmRqUjZXbXRxVTBnNFRVZHJkVEF6ZWpsMFJFRldUbXhZV25Cb2RIRjVPRzFWWVVsblJIQTJkVTB4ZWxkc2FWVkNUbWN1T1hnNFYwUlZPRFoxTjFaRVRqRktkRzlHVFdOZlVTNXFXVWt5WDBoeFRuWTRXbFZXVm1kalozRjFXbVZOY3pkblpIVjBRekpMTUVSNlZsWnBTa04wYVhKTGRHZDJSWEZqVGpoclF6ZEpaamQyWTE5UU9XMDVSREJoYmpWM01rdFRhR3RsVEVoMlFVTnlNa2RGWlZsQ1ZXVk1aa3BLYm5BMldYbE5iVEpKYVhVdFdtRm9VR2RrWjNkU1RYSlZUMnhmU0ZwM2F6SkxkVlk1YkRGcWVqQkVVSFZzU0hKNGVrNHhaeTVtWmxsalJuZEZkWEZmVDNOMVUweGhTVEp1YW5GQiIsImVuY3J5cHRpb25rZXkiOiJaWGxLYUdKSFkybFBhVXBUVlRCRmRGUXdSa1pWUTBselNXMVdkVmw1U1RaSmEwVjRUV3BvU0ZFd01HbG1VUzQwVkZWWWExZHRiMFp3V1ZWRWEyTTJkVFk0Y1RoR1gzbGFRVVZFZVVWNlNEbFRaMHRtYldKV1dIaG9SMDlmVm5Oc1ZqSkNkRGR1U1ROYVIzTldSV2R2TjFoUVdsOVRZV3gzY0ZCTVdsRjJTR1JYU21kbVVFSmhiMDVxUWxKMVIxQkZkSGQwZHpocldHTkNjWEZXWkZGU1dWaHFXa3BOY21KUlpsOVZTVzB4U1ZSMk5sODVZazgxVkROM1kwbG5VVVZwUmt4ME0zTktTa00wYURscFpUZExhWG8xWmpkc2RUWlVORmgzYzFaM1ZYZGhlVEJ2TTFJeVMwc3hXRkJsWjBWU2F6RmFRa3RoWjJKUVFtbzJiRzl0UVRVMlpsVnVkMEZqUlZBMFlWOXZlVGRXZFV0SVNXSnRjSEF3WVVWdVNtOUpjRVJGTTFGTVJESk1kbU5NZW5FMVVVOUJURms1TkZWeU15MTFjRVoyTFY5amExbDBTRzFzWVhaclYzQkpZbFpaVG05WGNrZGtVbUZzZFdSMVRuRTRaa1JGY0UxWGJtWTJVMDlLT0cxVlRVRTFSMVJoYjFsa2JUY3lhUzFJYjJoSFFuZ3hZMmN1TldadGJpMVFSRGg1TVVoWFVIbHFPV1JqVlZscVVTNTNZakJhWDA1VE5uZFBhRWQyYkVkbFYxaHJZbHBsZUhKVFFqUk9MVkJQZHpGNFdUWmpUV0pHVmtWQmVtY3dieTB3VWw4emVWVk1iM2R2YjB3eFdVODNTRTlMVDI5NGQxWnZPRjh3TFVNMGMxa3hjamx1UW1aTFpsZDJNMDVMYUhVd2FXeG1ka1ZUZWs5d1dWOVBURzVEZUVkU1FWOURTMU11TTFGMFlVZHdkM0UyZVVseVFYQmFUM1JPV1ZOdlFRPT0ifX0sInJlbmV3YWJsZSI6ZmFsc2UsImNhcGFiaWxpdGllcyI6eyJjb21wcmVzc2lvbmFsZ29zIjpbIkdaSVAiLCJMWlciXX0sIm1lc3NhZ2VpZCI6MjE1MDU1OTgwfQ==");
            var baddata = base64.parse("eyJuAAAAZXBsYXlhYmxlIjpmYWxzZSwia2V5cmVzcG9uc2VkYXRhIjp7Im1hc3RlcnRva2VuIjp7InRva2VuZGF0YSI6ImV5SnpaWEYxWlc1alpXNTFiV0psY2lJNk9ETXNJbkpsYm1WM1lXeDNhVzVrYjNjaU9qRXpOalV4T1RRM05qa3NJbk5sYzNOcGIyNWtZWFJoSWpvaVFsRkRRVUZCUlVKRlJ6aERNM2hvY25aV1FqQmFibVZtTnpoUk1IRlhUMEZ2Ulc0eWFVcHRRMlJ0YUZZeWJGTjZTbXBVUjBoWmRFdDNOamRaT1dreVdtTXhabEZ1TW00MVMwZDVjVkp2YURORlZGUTBSbTFKUW1sU1ZIRnlLMlp4TjNJNVNscDRTSGhxYVRORVMyaHdiWGQwVURkQ2JVNWtkRlkxWlV4bmF6RXpjMDVqVldOMWVFeEdUVEpxTTI1R1MwOXpjbWcxWjJOMFZ6VkdVMnBWTmxGS1QyTnBUM2d3TTJ4TVpqQnlNRU5KZWpKU1NVeGpSMGhpU0ZSTlJtSmlURGh5Wmt4eU4wazJUa2g0TVVSblZXMXlOSGd5Tnl0Rk1Hc3hjbkV5U1d4Vk0xTmFORlJYYUVkNWMzVnVUVlpJTW5SNFptTlhSVDBpTENKbGVIQnBjbUYwYVc5dUlqb3hNelkxTVRrME9ESTVMQ0p6WlhKcFlXeHVkVzFpWlhJaU9qWTNOemswT1RZd016RTJOak01TkRSOSIsInNpZ25hdHVyZSI6IkFRRUFnUUFCQVNDOFNyTXI5ZDZZQVhha2tvV0VxNmRGK215akdZbDJCZFRFVWdYS04zQ3kySFg4aGlFPSJ9LCJzY2hlbWUiOiJBU1lNTUVUUklDX1dSQVBQRUQiLCJrZXlkYXRhIjp7ImtleXBhaXJpZCI6InJzYUtleXBhaXJJZCIsImhtYWNrZXkiOiJaWGxLYUdKSFkybFBhVXBUVlRCRmRGUXdSa1pWUTBselNXMVdkVmw1U1RaSmEwVjRUV3BvU0ZFd01HbG1VUzU2WjE5dlZIZHBUVTVpTkdsUFRHUlBaR1UwWldsdFJHOW1ObWt0VTNjMVpqZDFObWRQUTE5Zk1GbG1XblJsWHpsMVduQkRNVEpDTUZnNWJtcGFhVzFuTUZOWlYxaFZTVVJ3VDNNNGJHSnlPV1ZKTUdsc2NuTmFiRXQ0YUd4TE1taDZjR3d4TW1sV1ptSjVTVGhvUjI1b2MxZElia2hYY21KcmQwRmpMWEp4V2tobVREZFNjVE5RTlZwek4xVk1kREpXVEhWMU9FVlRiRlJQTVVSak1qSXdibU53UVZOVVJXUTFPRTl2VlhkQ2NVcHlabXhmU0U1M1FWOTBUMlJUZUhadlVWSm5OekJSZEhKdGFGQlFjbUpFVkZScFVqaFBUazV5VVU1aVNrRmZlRUZZUmxoSFZucHhRVzV0YkRCbVpVVTRWVXhoYVdkV1Ftb3hlSEJ4YUMxaU9YUnZiRlpGTTBzd1pGaFZSRGN4TTNoYVppMHhjV2N4UVZSV2NXMUVVWFpNVDNwbmRqUjZXbXRxVTBnNFRVZHJkVEF6ZWpsMFJFRldUbXhZV25Cb2RIRjVPRzFWWVVsblJIQTJkVTB4ZWxkc2FWVkNUbWN1T1hnNFYwUlZPRFoxTjFaRVRqRktkRzlHVFdOZlVTNXFXVWt5WDBoeFRuWTRXbFZXVm1kalozRjFXbVZOY3pkblpIVjBRekpMTUVSNlZsWnBTa04wYVhKTGRHZDJSWEZqVGpoclF6ZEpaamQyWTE5UU9XMDVSREJoYmpWM01rdFRhR3RsVEVoMlFVTnlNa2RGWlZsQ1ZXVk1aa3BLYm5BMldYbE5iVEpKYVhVdFdtRm9VR2RrWjNkU1RYSlZUMnhmU0ZwM2F6SkxkVlk1YkRGcWVqQkVVSFZzU0hKNGVrNHhaeTVtWmxsalJuZEZkWEZmVDNOMVUweGhTVEp1YW5GQiIsImVuY3J5cHRpb25rZXkiOiJaWGxLYUdKSFkybFBhVXBUVlRCRmRGUXdSa1pWUTBselNXMVdkVmw1U1RaSmEwVjRUV3BvU0ZFd01HbG1VUzQwVkZWWWExZHRiMFp3V1ZWRWEyTTJkVFk0Y1RoR1gzbGFRVVZFZVVWNlNEbFRaMHRtYldKV1dIaG9SMDlmVm5Oc1ZqSkNkRGR1U1ROYVIzTldSV2R2TjFoUVdsOVRZV3gzY0ZCTVdsRjJTR1JYU21kbVVFSmhiMDVxUWxKMVIxQkZkSGQwZHpocldHTkNjWEZXWkZGU1dWaHFXa3BOY21KUlpsOVZTVzB4U1ZSMk5sODVZazgxVkROM1kwbG5VVVZwUmt4ME0zTktTa00wYURscFpUZExhWG8xWmpkc2RUWlVORmgzYzFaM1ZYZGhlVEJ2TTFJeVMwc3hXRkJsWjBWU2F6RmFRa3RoWjJKUVFtbzJiRzl0UVRVMlpsVnVkMEZqUlZBMFlWOXZlVGRXZFV0SVNXSnRjSEF3WVVWdVNtOUpjRVJGTTFGTVJESk1kbU5NZW5FMVVVOUJURms1TkZWeU15MTFjRVoyTFY5amExbDBTRzFzWVhaclYzQkpZbFpaVG05WGNrZGtVbUZzZFdSMVRuRTRaa1JGY0UxWGJtWTJVMDlLT0cxVlRVRTFSMVJoYjFsa2JUY3lhUzFJYjJoSFFuZ3hZMmN1TldadGJpMVFSRGg1TVVoWFVIbHFPV1JqVlZscVVTNTNZakJhWDA1VE5uZFBhRWQyYkVkbFYxaHJZbHBsZUhKVFFqUk9MVkJQZHpGNFdUWmpUV0pHVmtWQmVtY3dieTB3VWw4emVWVk1iM2R2YjB3eFdVODNTRTlMVDI5NGQxWnZPRjh3TFVNMGMxa3hjamx1UW1aTFpsZDJNMDVMYUhVd2FXeG1ka1ZUZWs5d1dWOVBURzVEZUVkU1FWOURTMU11TTFGMFlVZHdkM0UyZVVseVFYQmFUM1JPV1ZOdlFRPT0ifX0sInJlbmV3YWJsZSI6ZmFsc2UsImNhcGFiaWxpdGllcyI6eyJjb21wcmVzc2lvbmFsZ29zIjpbIkdaSVAiLCJMWlciXX0sIm1lc3NhZ2VpZCI6MjE1MDU1OTgwfQ==");
            var signature = base64.parse("EP9n/RwVsPojZhUHZI4Y0bkC6eweUUFIl9/tEyXh7D7/ffYtanHilXmtI6r4EL7TgE0yKRtUclIbirNCb1qwtgH1qycJqN8gIKzQkKE7tPO1mkwP1EVRIhY2Ryxs4hKjnAdi+JT/RLbAQuTAUD7aN3WhsrY8KWb96N72m1STzL4FrfPaHJGqe59zysu6RCqUy1UlG2mPaRn3EJ9nRmZT+Ga5rLhgrzyHzozVb9Rn0zLZz8OZamf0vCqwjf6bOwEP0WcADZS3b7J2N0/bX+j5XQpHlqYcUzj2GUWHLtLRzw10IlzfSr4ggwVbkMGc3o5wdLFaWwKmXtCf109UAlnynw==");

            var error,
                pubKey,
                verified;
            
            var algorithm = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
            
            runs(function () {
                error = undefined;
                cryptoSubtle.importKey("spki", pubKeyDataSpki, algorithm, false, ["verify"])
                    .then(function (result) {
                        pubKey = result;
                    })
                    .catch(function (e) {
                        error = "importKey ERROR";
                    });
            });

            waitsFor(function () {
                return pubKey || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(pubKey).toBeDefined();
                expect(pubKey.type).toBe("public");
            });


            // verify data
            runs(function () {
                error = undefined;
                verified = undefined;
                cryptoSubtle.verify(algorithm, pubKey, signature, data)
                    .then(function (result) {
                        verified = result;
                    })
                    .catch(function (e) {
                        error = "verify ERROR";
                    });
            });

            waitsFor(function () {
                return verified !== undefined || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(verified).toBe(true);
            });

            runs(function () {
                error = undefined;
                verified = undefined;
                cryptoSubtle.verify(algorithm, pubKey, signature, baddata)
                    .then(function (result) {
                        verified = result;
                    })
                    .catch(function (e) {
                        error = "verify ERROR";
                    });
            });

            waitsFor(function () {
                return verified !== undefined || error;
            });

            runs(function () {
                expect(error).toBeUndefined();
                expect(verified).toBe(false);
            });

        });

    });

    // --------------------------------------------------------------------------------

    describe("JSON Web Key (JWK)", function () {
        var error;
        var key;
        var exportedData;
        var key128 = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]);
        var key256 = new Uint8Array(key128.length * 2);
        key256.set(key128);
        key256.set(key128, key128.length);
        
        beforeEach(function () {
            this.addMatchers({
                toBeAnyOf: function(expecteds) {
                    var result = false;
                    for (var i = 0, l = expecteds.length; i < l; i++) {
                        if (this.actual === expecteds[i]) {
                            result = true;
                            break;
                        }
                    }
                    return result;
                }
            });
        });

        it("A128CBC import/export", function () {
            
            var jwk1 = latin1.parse(JSON.stringify({
                alg:    "A128CBC",
                kty:    "oct",
                use:    "enconly",
                ext:    true,
                k:      base64.stringifyUrlSafe(key128),
            }));
            runs(function () {
                key = undefined;
                error = undefined;
                cryptoSubtle.importKey("jwk", jwk1, { name: "AES-CBC" }, true, ["encrypt"])
                .then(function (result) {
                    key = result;
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            })
            waitsFor(function () {
                return key || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
                expect(key.algorithm.name).toBeAnyOf(["AES-CBC", "aes-cbc"]);
            });
            runs(function () {
                error = undefined;
                exportedData = undefined;
                cryptoSubtle.exportKey("jwk", key)
                .then(function (result) {
                    exportedData = result && new Uint8Array(result);
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            })
            waitsFor(function () {
                return exportedData || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
                var json1 = JSON.parse(latin1.stringify(jwk1));
                var json2 = JSON.parse(latin1.stringify(exportedData));
                expect(json1).toEqual(json2);
            });
            
        });

        it("HS256 import/export", function () {
            var jwk3 = latin1.parse(JSON.stringify({
                alg:    "HS256",
                kty:    "oct",
                use:    "sigonly",
                ext:    true,
                k:      base64.stringifyUrlSafe(key256),
            }));
            runs(function () {
                key = undefined;
                error = undefined;
                cryptoSubtle.importKey("jwk", jwk3, {name: "HMAC", hash: {name: "SHA-256" }}, true, ["sign"])
                .then(function (result) {
                    key = result;
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            })
            waitsFor(function () {
                return key || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
                expect(key.algorithm.name).toBeAnyOf(["HMAC", "hmac"]);
            });
            runs(function () {
                error = undefined;
                exportedData = undefined;
                cryptoSubtle.exportKey("jwk", key)
                .then(function (result) {
                    exportedData = result && new Uint8Array(result);
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            })
            waitsFor(function () {
                return exportedData || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
                var json1 = JSON.parse(latin1.stringify(jwk3));
                var json2 = JSON.parse(latin1.stringify(exportedData));
                expect(json1).toEqual(json2);
            });
        });

        it("RSA1_5 public key import/export", function () {

            // keys from example 10 of oaep-vect.txt from
            // https://das-labor.org/svn/microcontroller-2/crypto-lib/testvectors/rsa-pkcs-1v2-1-vec/oaep-vect.txt

            var jwk4 = latin1.parse(JSON.stringify({
                alg:    "RSA1_5",
                kty:    "RSA",
                n:      base64.stringifyUrlSafe(base16.parse(
                        "ae45ed5601cec6b8cc05f803935c674d" +
                        "dbe0d75c4c09fd7951fc6b0caec313a8" +
                        "df39970c518bffba5ed68f3f0d7f22a4" +
                        "029d413f1ae07e4ebe9e4177ce23e7f5" +
                        "404b569e4ee1bdcf3c1fb03ef113802d" +
                        "4f855eb9b5134b5a7c8085adcae6fa2f" +
                        "a1417ec3763be171b0c62b760ede23c1" +
                        "2ad92b980884c641f5a8fac26bdad4a0" +
                        "3381a22fe1b754885094c82506d4019a" +
                        "535a286afeb271bb9ba592de18dcf600" +
                        "c2aeeae56e02f7cf79fc14cf3bdc7cd8" +
                        "4febbbf950ca90304b2219a7aa063aef" +
                        "a2c3c1980e560cd64afe779585b61076" +
                        "57b957857efde6010988ab7de417fc88" +
                        "d8f384c4e6e72c3f943e0c31c0c4a5cc" +
                        "36f879d8a3ac9d7d59860eaada6b83bb"
                )),
                e:      base64.stringifyUrlSafe(base16.parse("010001")),
                ext:    true,
                use:    "deconly"
            }));
            runs(function () {
                key = undefined;
                error = undefined;
                cryptoSubtle.importKey("jwk", jwk4, { name: "RSAES-PKCS1-v1_5" }, true, ["decrypt"])
                .then(function (result) {
                    key = result;
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            })
            waitsFor(function () {
                return key || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
                expect(key.algorithm.name).toBeAnyOf(["RSAES-PKCS1-v1_5", "rsaes-pkcs1-v1_5"]);
            });
            runs(function () {
                error = undefined;
                exportedData = undefined;
                cryptoSubtle.exportKey("jwk", key)
                .then(function (result) {
                    exportedData = result && new Uint8Array(result);
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            })
            waitsFor(function () {
                return exportedData || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
                var json1 = JSON.parse(latin1.stringify(jwk4));
                var json2 = JSON.parse(latin1.stringify(exportedData));
                expect(json1).toEqual(json2);
            });
        });

        it("RSA-OAEP public key import/export", function () {
            // key from example 10 of oaep-vect.txt from
            // https://das-labor.org/svn/microcontroller-2/crypto-lib/testvectors/rsa-pkcs-1v2-1-vec/oaep-vect.txt
            var jwk = latin1.parse(JSON.stringify({
                alg:    "RSA-OAEP",
                kty:    "RSA",
                n:      base64.stringifyUrlSafe(base16.parse(
                        "ae45ed5601cec6b8cc05f803935c674d" +
                        "dbe0d75c4c09fd7951fc6b0caec313a8" +
                        "df39970c518bffba5ed68f3f0d7f22a4" +
                        "029d413f1ae07e4ebe9e4177ce23e7f5" +
                        "404b569e4ee1bdcf3c1fb03ef113802d" +
                        "4f855eb9b5134b5a7c8085adcae6fa2f" +
                        "a1417ec3763be171b0c62b760ede23c1" +
                        "2ad92b980884c641f5a8fac26bdad4a0" +
                        "3381a22fe1b754885094c82506d4019a" +
                        "535a286afeb271bb9ba592de18dcf600" +
                        "c2aeeae56e02f7cf79fc14cf3bdc7cd8" +
                        "4febbbf950ca90304b2219a7aa063aef" +
                        "a2c3c1980e560cd64afe779585b61076" +
                        "57b957857efde6010988ab7de417fc88" +
                        "d8f384c4e6e72c3f943e0c31c0c4a5cc" +
                        "36f879d8a3ac9d7d59860eaada6b83bb"
                )),
                e:      base64.stringifyUrlSafe(base16.parse("010001")),
                ext:    true,
                use:    "enconly"
            }));
            runs(function () {
                key = undefined;
                error = undefined;
                cryptoSubtle.importKey("jwk", jwk, { name: "RSA-OAEP", hash: {name: "SHA-1"} }, true, ["encrypt"])
                .then(function (result) {
                    key = result;
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            })
            waitsFor(function () {
                return key || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
                expect(key.algorithm.name).toBeAnyOf(["RSA-OAEP", "rsa-oaep"]);
                expect(key.type).toBe("public");;
            });
            runs(function () {
                error = undefined;
                exportedData = undefined;
                cryptoSubtle.exportKey("jwk", key)
                .then(function (result) {
                    exportedData = result && new Uint8Array(result);
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            })
            waitsFor(function () {
                return exportedData || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
                var json1 = JSON.parse(latin1.stringify(jwk));
                var json2 = JSON.parse(latin1.stringify(exportedData));
                expect(json1).toEqual(json2);
            });
        });

        it("RSA-OAEP private key import", function () {
            // key from example 10 of oaep-vect.txt from
            // https://das-labor.org/svn/microcontroller-2/crypto-lib/testvectors/rsa-pkcs-1v2-1-vec/oaep-vect.txt
            var jwk = latin1.parse(JSON.stringify({
                alg:    "RSA-OAEP",
                kty:    "RSA",
                n:      base64.stringifyUrlSafe(base16.parse(
                        "ae45ed5601cec6b8cc05f803935c674d" +
                        "dbe0d75c4c09fd7951fc6b0caec313a8" +
                        "df39970c518bffba5ed68f3f0d7f22a4" +
                        "029d413f1ae07e4ebe9e4177ce23e7f5" +
                        "404b569e4ee1bdcf3c1fb03ef113802d" +
                        "4f855eb9b5134b5a7c8085adcae6fa2f" +
                        "a1417ec3763be171b0c62b760ede23c1" +
                        "2ad92b980884c641f5a8fac26bdad4a0" +
                        "3381a22fe1b754885094c82506d4019a" +
                        "535a286afeb271bb9ba592de18dcf600" +
                        "c2aeeae56e02f7cf79fc14cf3bdc7cd8" +
                        "4febbbf950ca90304b2219a7aa063aef" +
                        "a2c3c1980e560cd64afe779585b61076" +
                        "57b957857efde6010988ab7de417fc88" +
                        "d8f384c4e6e72c3f943e0c31c0c4a5cc" +
                        "36f879d8a3ac9d7d59860eaada6b83bb"
                )),
                e:      base64.stringifyUrlSafe(base16.parse("010001")),
                d:      base64.stringifyUrlSafe(base16.parse(
                        "056b04216fe5f354ac77250a4b6b0c85" +
                        "25a85c59b0bd80c56450a22d5f438e59" +
                        "6a333aa875e291dd43f48cb88b9d5fc0" +
                        "d499f9fcd1c397f9afc070cd9e398c8d" +
                        "19e61db7c7410a6b2675dfbf5d345b80" +
                        "4d201add502d5ce2dfcb091ce9997bbe" +
                        "be57306f383e4d588103f036f7e85d19" +
                        "34d152a323e4a8db451d6f4a5b1b0f10" +
                        "2cc150e02feee2b88dea4ad4c1baccb2" +
                        "4d84072d14e1d24a6771f7408ee30564" +
                        "fb86d4393a34bcf0b788501d193303f1" +
                        "3a2284b001f0f649eaf79328d4ac5c43" +
                        "0ab4414920a9460ed1b7bc40ec653e87" +
                        "6d09abc509ae45b525190116a0c26101" +
                        "848298509c1c3bf3a483e7274054e15e" +
                        "97075036e989f60932807b5257751e79"
                )),
                p:      base64.stringifyUrlSafe(base16.parse(
                        "ecf5aecd1e5515fffacbd75a2816c6eb" +
                        "f49018cdfb4638e185d66a7396b6f809" +
                        "0f8018c7fd95cc34b857dc17f0cc6516" +
                        "bb1346ab4d582cadad7b4103352387b7" +
                        "0338d084047c9d9539b6496204b3dd6e" +
                        "a442499207bec01f964287ff6336c398" +
                        "4658336846f56e46861881c10233d217" +
                        "6bf15a5e96ddc780bc868aa77d3ce769"
                )),
                q:      base64.stringifyUrlSafe(base16.parse(
                        "bc46c464fc6ac4ca783b0eb08a3c841b" +
                        "772f7e9b2f28babd588ae885e1a0c61e" +
                        "4858a0fb25ac299990f35be85164c259" +
                        "ba1175cdd7192707135184992b6c29b7" +
                        "46dd0d2cabe142835f7d148cc161524b" +
                        "4a09946d48b828473f1ce76b6cb6886c" +
                        "345c03e05f41d51b5c3a90a3f24073c7" +
                        "d74a4fe25d9cf21c75960f3fc3863183"
                )),
                dp:     base64.stringifyUrlSafe(base16.parse(
                        "c73564571d00fb15d08a3de9957a5091" +
                        "5d7126e9442dacf42bc82e862e5673ff" +
                        "6a008ed4d2e374617df89f17a160b43b" +
                        "7fda9cb6b6b74218609815f7d45ca263" +
                        "c159aa32d272d127faf4bc8ca2d77378" +
                        "e8aeb19b0ad7da3cb3de0ae7314980f6" +
                        "2b6d4b0a875d1df03c1bae39ccd833ef" +
                        "6cd7e2d9528bf084d1f969e794e9f6c1"
                )),
                dq:     base64.stringifyUrlSafe(base16.parse(
                        "2658b37f6df9c1030be1db68117fa9d8" +
                        "7e39ea2b693b7e6d3a2f70947413eec6" +
                        "142e18fb8dfcb6ac545d7c86a0ad48f8" +
                        "457170f0efb26bc48126c53efd1d1692" +
                        "0198dc2a1107dc282db6a80cd3062360" +
                        "ba3fa13f70e4312ff1a6cd6b8fc4cd9c" +
                        "5c3db17c6d6a57212f73ae29f619327b" +
                        "ad59b153858585ba4e28b60a62a45e49"
                )),
                qi:     base64.stringifyUrlSafe(base16.parse(
                        "6f38526b3925085534ef3e415a836ede" +
                        "8b86158a2c7cbfeccb0bd834304fec68" +
                        "3ba8d4f479c433d43416e63269623cea" +
                        "100776d85aff401d3fff610ee65411ce" +
                        "3b1363d63a9709eede42647cea561493" +
                        "d54570a879c18682cd97710b96205ec3" +
                        "1117d73b5f36223fadd6e8ba90dd7c0e" +
                        "e61d44e163251e20c7f66eb305117cb8"
                )),
                ext:    true,
                use:    "enc"
            }));
            runs(function () {
                key = undefined;
                error = undefined;
                cryptoSubtle.importKey("jwk", jwk, { name: "RSA-OAEP", hash: {name: "SHA-1"} }, true, [])
                .then(function (result) {
                    key = result;
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            })
            waitsFor(function () {
                return key || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
                expect(key.algorithm.name).toBeAnyOf(["RSA-OAEP", "rsa-oaep"]);
                expect(key.type).toBe("private");
            });
        });

        it("A128KW import/export", function () {
            var jwk5 = latin1.parse(JSON.stringify({
                alg:    "A128KW",
                kty:    "oct",
                use:    "wrap",
                ext:    true,
                k:      base64.stringifyUrlSafe(key128),
            }));
            runs(function () {
                key = undefined;
                error = undefined;
                cryptoSubtle.importKey("jwk", jwk5, { name: "AES-KW" }, true, ["wrapKey"])
                .then(function (result) {
                    key = result;
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            })
            waitsFor(function () {
                return key || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
                expect(key.algorithm.name).toBeAnyOf(["AES-KW", "aes-kw"]);
            });
            runs(function () {
                error = undefined;
                exportedData = undefined;
                cryptoSubtle.exportKey("jwk", key)
                .then(function (result) {
                    exportedData = result && new Uint8Array(result);
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            })
            waitsFor(function () {
                return exportedData || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
                var json1 = JSON.parse(latin1.stringify(jwk5));
                var json2 = JSON.parse(latin1.stringify(exportedData));
                expect(json1).toEqual(json2);
            });
        });

        it("A256KW import/export", function () {
            var jwk6 = latin1.parse(JSON.stringify({
                alg:    "A256KW",
                kty:    "oct",
                use:    "unwrap",
                ext:    true,
                k:      base64.stringifyUrlSafe(key256),
            }));
            runs(function () {
                key = undefined;
                error = undefined;
                cryptoSubtle.importKey("jwk", jwk6, { name: "AES-KW" }, true, ["unwrapKey"])
                .then(function (result) {
                    key = result;
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            })
            waitsFor(function () {
                return key || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
                expect(key.algorithm.name).toBeAnyOf(["AES-KW", "aes-kw"]);
            });
            runs(function () {
                error = undefined;
                exportedData = undefined;
                cryptoSubtle.exportKey("jwk", key)
                .then(function (result) {
                    exportedData = result && new Uint8Array(result);
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            })
            waitsFor(function () {
                return exportedData || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(key).toBeDefined();
                var json1 = JSON.parse(latin1.stringify(jwk6));
                var json2 = JSON.parse(latin1.stringify(exportedData));
                expect(json1).toEqual(json2);
            });

        });
    });
    
    // --------------------------------------------------------------------------------

    describe("Key Wrapping Operations", function () {

        it("AES-KW wrap/unwrap known answer", function () {
            
            // The following test vector is from http://www.ietf.org/rfc/rfc3394.txt
            // 4.1 Wrap 128 bits of Key Data with a 128-bit KEK
            var wraporKeyData = base16.parse("000102030405060708090A0B0C0D0E0F"),
                wrapeeKeyData = base16.parse("00112233445566778899AABBCCDDEEFF"),
                wrappedKeyDataKnown = base16.parse("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5");
            var wrapeeKey, wraporKey, wrappedKeyData, wrapeeKey2, wrapeeKeyData2;
            var error;
            
            // Import the known wrap-ee key
            runs(function () {
                error = undefined;
                cryptoSubtle.importKey('raw', wrapeeKeyData, { name: "AES-CBC" }, true, [])
                    .then(function (result) {
                        wrapeeKey = result;
                    })
                    .catch(function (e) {
                        error = "ERROR";
                    });
            });
            waitsFor(function () {
                return wrapeeKey || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(wrapeeKey).toBeDefined();
                expect(wrapeeKey.extractable).toBe(true);
                expect(wrapeeKey.type).toBe("secret");
            });

            // Import the known wrap-or key
            runs(function () {
                error = undefined;
                cryptoSubtle.importKey('raw', wraporKeyData, { name: "AES-KW" }, false, ["wrapKey", "unwrapKey"])
                    .then(function (result) {
                        wraporKey = result;
                    })
                    .catch(function (e) {
                        error = "ERROR";
                    });
            });
            waitsFor(function () {
                return wraporKey || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(wraporKey).toBeDefined();
                expect(wraporKey.extractable).toBe(false);
                expect(wraporKey.type).toBe("secret");
            });
            
            // Wrap the wrapee key with the wrapor and compare with the known result
            runs(function () {
                error = undefined;
                cryptoSubtle.wrapKey('raw', wrapeeKey, wraporKey, { name: "AES-KW" })
                    .then(function (result) {
                        wrappedKeyData = result;
                    })
                    .catch(function (e) {
                        error = "ERROR";
                    });
            });
            waitsFor(function () {
                return wrappedKeyData || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(wrappedKeyData).toBeDefined();
                expect(new Uint8Array(wrappedKeyData)).toEqual(wrappedKeyDataKnown);
            });
            
            // Unwrap the wrapped key
            runs(function () {
                error = undefined;
                cryptoSubtle.unwrapKey(
                        'raw',
                        wrappedKeyData,
                        wraporKey,
                        { name: "AES-KW" },
                        { name: "AES-CBC" },
                        true,
                        [])
                    .then(function (result) {
                        wrapeeKey2 = result;
                    })
                    .catch(function (e) {
                        error = "ERROR";
                    });
            });
            waitsFor(function () {
                return wrapeeKey2 || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(wrapeeKey2).toBeDefined();
                expect(wrapeeKey2.extractable).toBe(true);
                expect(wrapeeKey2.type).toBe("secret");
            });
            
            // Export the unwrapped key data and compare to the original
            runs(function () {
                error = undefined;
                cryptoSubtle.exportKey("raw", wrapeeKey2)
                .then(function (result) {
                    wrapeeKeyData2 = result;
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            });
            waitsFor(function () {
                return wrapeeKeyData2 || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(wrapeeKeyData2).toBeDefined();
                expect(new Uint8Array(wrapeeKeyData2)).toEqual(wrapeeKeyData);
            });

        });
        
        it("RSAES-PKCS1-v1_5 wrap/unwrap round trip", function () {
            // Note: we can't do a known-answer test for RSAES-PKCS1-v1_5 because
            // of the random padding.
            
            var wrapeeKeyData = base16.parse("8f56a26e7e8b77dca15ed54339724bf5");
            var wrapeeKey, wraporKeyPublic, wraporKeyPrivate, wrappedKeyData, wrapeeKey2, wrapeeKeyData2;
            var error;
            
            // Import the known wrap-ee key
            runs(function () {
                error = undefined;
                cryptoSubtle.importKey('raw', wrapeeKeyData, { name: "AES-CBC" }, true, [])
                    .then(function (result) {
                        wrapeeKey = result;
                    })
                    .catch(function (e) {
                        error = "importKey ERROR";
                    });
            });
            waitsFor(function () {
                return wrapeeKey || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(wrapeeKey).toBeDefined();
                expect(wrapeeKey.extractable).toBe(true);
                expect(wrapeeKey.type).toBe("secret");
            });

            // Generate an RSAES-PKCS1-v1_5 key pair
            runs(function () {
                error = undefined;
                cryptoSubtle.generateKey(
                    {
                        name: "RSAES-PKCS1-v1_5",
                        modulusLength: 1024,
                        publicExponent: new Uint8Array([0x01, 0x00, 0x01])
                    },
                    false,
                    ["wrapKey", "unwrapKey"]
                )
                .then(function (result) {
                    wraporKeyPublic = result.publicKey;
                    wraporKeyPrivate = result.privateKey;
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            });
            waitsFor(function () {
                return wraporKeyPublic || wraporKeyPrivate || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(wraporKeyPublic).toBeDefined();
                expect(wraporKeyPublic.extractable).toBeTruthy() // public key is forced extractable
                expect(wraporKeyPrivate).toBeDefined();
                expect(wraporKeyPrivate.extractable).toBeFalsy() // private key takes input extractable
            });
            
            // Wrap the key using the public wrappor key
            runs(function () {
                error = undefined;
                cryptoSubtle.wrapKey('jwk', wrapeeKey, wraporKeyPublic, { name: "RSAES-PKCS1-v1_5" })
                    .then(function (result) {
                        wrappedKeyData = result;
                    })
                    .catch(function (e) {
                        error = "ERROR";
                    });
            });
            waitsFor(function () {
                return wrappedKeyData || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(wrappedKeyData).toBeDefined();
            });
            
            // Unwrap the wrapped key using the private wrappor key
            runs(function () {
                error = undefined;
                cryptoSubtle.unwrapKey(
                        'jwk',
                        wrappedKeyData,
                        wraporKeyPrivate,
                        { name: "RSAES-PKCS1-v1_5" }, { name: "AES-CBC" },
                        true,
                        [])
                    .then(function (result) {
                        wrapeeKey2 = result;
                    })
                    .catch(function (e) {
                        error = "ERROR";
                    });
            });
            waitsFor(function () {
                return wrapeeKey2 || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(wrapeeKey2).toBeDefined();
                expect(wrapeeKey2.extractable).toBe(true);
                expect(wrapeeKey2.type).toBe("secret");
            });
            
            // Export the unwrapped key data and compare to the original
            runs(function () {
                error = undefined;
                cryptoSubtle.exportKey("raw", wrapeeKey2)
                .then(function (result) {
                    wrapeeKeyData2 = result && new Uint8Array(result);
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            });
            waitsFor(function () {
                return wrapeeKeyData2 || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(wrapeeKeyData2).toBeDefined();
                expect(base16.stringify(wrapeeKeyData2)).toBe(base16.stringify(wrapeeKeyData));
            });
        });
        
        it("RSA-OAEP wrap/unwrap round trip", function () {
            // Note: we can't do a known-answer test for RSA-OAEP because
            // of the random padding.
            
            var wrapeeKeyData = base16.parse("8f56a26e7e8b77dca15ed54339724bf5");
            var wrapeeKey, wraporKeyPublic, wraporKeyPrivate, wrappedKeyData, wrapeeKey2, wrapeeKeyData2;
            var error;
            
            // Import the known wrap-ee key
            runs(function () {
                error = undefined;
                cryptoSubtle.importKey('raw', wrapeeKeyData, { name: "AES-CBC" }, true, [])
                    .then(function (result) {
                        wrapeeKey = result;
                    })
                    .catch(function (e) {
                        error = "importKey ERROR";
                    });
            });
            waitsFor(function () {
                return wrapeeKey || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(wrapeeKey).toBeDefined();
                expect(wrapeeKey.extractable).toBe(true);
                expect(wrapeeKey.type).toBe("secret");
            });

            // Generate an RSA-OAEP key pair
            runs(function () {
                error = undefined;
                cryptoSubtle.generateKey(
                    {
                        name: "RSA-OAEP",
                        modulusLength: 1024,
                        publicExponent: new Uint8Array([0x01, 0x00, 0x01])
                    },
                    false,
                    ["wrapKey", "unwrapKey"]
                )
                .then(function (result) {
                    wraporKeyPublic = result.publicKey;
                    wraporKeyPrivate = result.privateKey;
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            });
            waitsFor(function () {
                return wraporKeyPublic || wraporKeyPrivate || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(wraporKeyPublic).toBeDefined();
                expect(wraporKeyPublic.extractable).toBeTruthy() // public key is forced extractable
                expect(wraporKeyPrivate).toBeDefined();
                expect(wraporKeyPrivate.extractable).toBeFalsy() // private key takes input extractable
            });
            
            var wrapAlgorithm = { name: "RSA-OAEP", hash: {name: "SHA-256"} };
            
            // Wrap the key using the public wrappor key
            runs(function () {
                error = undefined;
                cryptoSubtle.wrapKey('raw', wrapeeKey, wraporKeyPublic, wrapAlgorithm)
                    .then(function (result) {
                        wrappedKeyData = result;
                    })
                    .catch(function (e) {
                        error = "ERROR";
                    });
            });
            waitsFor(function () {
                return wrappedKeyData || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(wrappedKeyData).toBeDefined();
            });
            
            // Unwrap the wrapped key using the private wrappor key
            runs(function () {
                error = undefined;
                cryptoSubtle.unwrapKey(
                        'raw',
                        wrappedKeyData,
                        wraporKeyPrivate,
                        wrapAlgorithm,
                        { name: "AES-CBC" },
                        true,
                        [])
                    .then(function (result) {
                        wrapeeKey2 = result;
                    })
                    .catch(function (e) {
                        error = "ERROR";
                    });
            });
            waitsFor(function () {
                return wrapeeKey2 || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(wrapeeKey2).toBeDefined();
                expect(wrapeeKey2.extractable).toBe(true);
                expect(wrapeeKey2.type).toBe("secret");
            });
            
            // Export the unwrapped key data and compare to the original
            runs(function () {
                error = undefined;
                cryptoSubtle.exportKey("raw", wrapeeKey2)
                .then(function (result) {
                    wrapeeKeyData2 = result && new Uint8Array(result);
                })
                .catch(function (result) {
                    error = "ERROR";
                })
            });
            waitsFor(function () {
                return wrapeeKeyData2 || error;
            });
            runs(function () {
                expect(error).toBeUndefined();
                expect(wrapeeKeyData2).toBeDefined();
                expect(base16.stringify(wrapeeKeyData2)).toBe(base16.stringify(wrapeeKeyData));
            });
        });
        
    });

})();
