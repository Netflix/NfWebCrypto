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
describe("multiThreadedDigest", function () {

	it("digest", function () {
		// convenient calculator here: http://www.fileformat.info/tool/hash.htm
		var data = base16.parse("6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071");
		var result_sha384 = "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b";
		var result_sha1 = "84983e441c3bd26ebaae4aa1f95129e5e54670f1";


		var op1 = undefined, 
		    op2 = undefined,
		    result1 = undefined, 
		    result2 = undefined,
		    error1 = undefined,
		    error2 = undefined,
		    complete1 = undefined, 
		    complete2 = undefined;

		runs(function () {
			op1 = nfCrypto.digest("SHA-384", data)
			op1.onerror = function (e) {
				error1 = "ERROR :: " + e.target.result;
			};
			op1.oncomplete = function (e) {
				complete1 = true;
				result1 = e.target.result;
			};
		});

		runs(function () {
			op2 = nfCrypto.digest("SHA-1", data)
			op2.onerror = function (e) {
				error2 = "ERROR :: " + e.target.result;
			};
			op2.oncomplete = function (e) {
				complete2 = true;
				result2 = e.target.result;
			};
		});

		waitsFor(function () {
			return (error1 || complete1) &&  (error2 || complete2);
		});

		runs(function () {
			expect(error1).toBeUndefined();
			expect(complete1).toBeTruthy();
			expect(error2).toBeUndefined();
			expect(complete2).toBeTruthy();
			expect(base16.stringify(result1)).toBe(result_sha384);
			expect(base16.stringify(result2)).toBe(result_sha1);
		});
	});//end of it("DigestSHA384")

});//end of describe("multiThreadedDigest")

describe("multiThreadedDerive", function () {

	it("derive", function () {


		var dhPrime = base64.parse(
	            "lpTp2Nk6WsdMUJtLvOhekhMs0ZzOR30afkfVJ9nsKRUV8Liz4ertUAbh" +
	            "sbkeoluRoBsQ4ug0uNZgsuMhrWRM4ag7Mo2QFO5+FvHkT/6JV5rD7kfW" +
	            "aLa3ZofC/pCjW15gKP0E7+qII3Ps9gui9jfkzaobYInWwLVhqOUg55beJ98=");
	    var dhGenerator = base64.parse("AAU=");
	    var randPubkey = new Uint8Array([157,193,10,17,136,207,227,77,9,53,388,96,213,9,65,218]); 
		var genPubkey = undefined,
		genPrivkey = undefined,
		error = undefined,
		op = undefined;
		//Generate key pair first then derive
		//This is because the generate creates a "secret" in crypto context which is required for derive key 
        runs(function () {
        	try {
        		var fermatF4 = new Uint8Array([0x01, 0x00, 0x01]);
        		op = nfCrypto.generateKey( {name: "DH", params: { prime: dhPrime, generator: dhGenerator } }, true, ["derive", "decrypt"] );

        		op.onerror = function (e) {
                    error = "ERROR";
                };
                op.oncomplete = function (e) {
                	genPubkey  = e.target.result.publicKey;
                	genPrivkey = e.target.result.privateKey;
                };
			} catch(e) {
				error = "ERROR";
			}
        });

        waitsFor(function () {
            return genPubkey || genPrivkey || error;
        });

        runs(function () {
            expect(error).toBeUndefined();
            expect(genPubkey).toBeDefined();
            expect(genPrivkey).toBeDefined();
        });
        //Derive key from generate key
        var error1 = undefined,
            sharedKey1 = undefined,
            op1 = undefined,
            error2 = undefined,
            sharedKey2 = undefined,
            op2 = undefined;

		runs(function () {
			try {	
				op1 = nfCrypto.deriveKey({ name: "DH", params: { public: randPubkey } }, genPubkey, "AES-CBC", true, ["encrypt", "decrypt"]);
				op1.onerror = function (e) {
					error1 = "ERROR";
				};
				op1.oncomplete = function (e) {
					sharedKey1  = e.target.result;
				};
			} catch(e) {
				error1 = "ERROR";
			}
		});

        runs(function () {
			try {
				console.log('Started derviveKey2')
				op2 = nfCrypto.deriveKey({ name: "DH", params: { public: randPubkey } }, genPubkey, "AES-CBC", true, ["encrypt", "decrypt"]);
				op2.onerror = function (e) {
					error2 = "ERROR";
				};
				op2.oncomplete = function (e) {
					sharedKey2  = e.target.result;
				};
			} catch(e) {
				error2 = "ERROR";
			}
		});

		waitsFor(function () {
			 return (sharedKey1 || error1) && (sharedKey2 || error2);
		});

		runs(function () {
			expect(error1).toBeUndefined();
			expect(sharedKey1).toBeDefined();
			expect(error2).toBeUndefined();
			expect(sharedKey2).toBeDefined();
		});
	});
}); //describe("multiThreadedDerive")

describe("multiThreadedGenerate", function () {
	it("generate", function () {
		var error1 = undefined,
		error2 = undefined,
		key = undefined,
		op1 = undefined,
		op2 = undefined,
		pubKey = undefined,
		privKey = undefined;

		//Generate AES-CBC
		runs(function () {
			try {
				op1 = nfCrypto.generateKey({ name: "AES-CBC", params: { length: 128 } }, true);
				op1.onerror = function (e) {
					error1 = "ERROR";
				};
				op1.oncomplete = function (e) {
					key = e.target.result;
				};
			} catch(e) {
				error1 = "ERROR";
			}
		});

		//Generate RSAES-PKCS1-v1_5
		runs(function () {
			try {
				op2 = nfCrypto.generateKey({ name: "RSAES-PKCS1-v1_5", params: { modulusLength: 512, publicExponent: new Uint8Array([0x01, 0x00, 0x01]) } }, false, ["encrypt", "decrypt"]);
				op2.onerror = function (e) {
					error2 = "ERROR";
				};
				op2.oncomplete = function (e) {
					pubKey  = e.target.result.publicKey;
	                privKey = e.target.result.privateKey;
				};
			} catch(e) {
				error2 = "ERROR";
			}
		});

		waitsFor(function () {
			return (key || error1) && (pubKey || privKey || error2);
		});

		runs(function () {
			expect(error1).toBeUndefined();
			expect(key).toBeDefined();
			expect(error2).toBeUndefined();
			expect(pubKey).toBeDefined();	
			expect(privKey).toBeDefined();	
		});
	});
}); //describe("multiThreadedGenerate")

describe("multiThreadedGetKey", function () {
	it("getkey", function () {
		var error = undefined;
		var keyName = undefined;
		var keyKde = undefined
		keyKdh = undefined,
		error = undefined,
		errorRecv = undefined,
		op = undefined,
		operation = undefined;

		runs(function () {
			try {
				op = nfCryptoKeys.getKeyByName("Kde");
				op.onerror = function (e) {
					error = "ERROR";
				};
				op.oncomplete = function (e) {
					keyKde = e.target.result;
				};
			} catch(e) {
				error = "ERROR";
			}
		});

		runs(function () {
			try {
				operation = nfCryptoKeys.getKeyByName("Kdh");
				operation.onerror = function (e) {
					errorRecv = "ERROR";
				};
				operation.oncomplete = function (e) {
					keyKdh = e.target.result;
				};
			} catch(e) {
				errorRecv = "ERROR";
			}
		});

		waitsFor(function () {
			return (keyKde || error) && (keyKdh || errorRecv);
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(keyKde).toBeDefined();	
			expect(errorRecv).toBeUndefined();
			expect(keyKdh).toBeDefined();	
		});
	});//it
});//describe("multiThreadedGetKey")


describe("multiThreadedEncryptDecrypt", function () {
	it("encryptdecrypt", function () {
		var error = undefined,
		encrypted = undefined,
		decrypted = undefined,
		importedKey = undefined;
		var org_iv = "562e17996d093d28ddb3ba695a2e6f58";
		var IV = base16.parse(org_iv);
		var IV_DECRYPT = base16.parse(org_iv);
		var cleartext_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    	clearText = base16.parse(cleartext_hex);
		runs(function () {
			try {
				var op = undefined;
				op = nfCrypto.importKey(
							"raw",
							new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]),
							"AES-CBC",
							true,
							["encrypt", "decrypt"]
				);

				op.onerror = function (e) {
					error = "ERROR :: " + e.target.result
				};
				op.oncomplete = function (e) {
					importedKey = e.target.result;
				};
			} catch(e) {
				error = "ERROR";
			}
		});

		waitsFor(function () {
			return importedKey || error;
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(importedKey).toBeDefined();
		});

		var errorEncrypt = undefined,
		encryptedTwice = undefined,
		encryptOperation = undefined,
		encryptOp = undefined,
		error = undefined;

		//First encrypt
		runs(function () {
			try {
				encryptOp = nfCrypto.encrypt({	name: "AES-CBC", params: { iv: IV } }, importedKey, clearText);
				encryptOp.onerror = function (e) {
					error = "ERROR";
				};
				encryptOp.oncomplete = function (e) {
					encrypted = e.target.result;
				};
			} catch(e) {
				error = "ERROR";
			}
		});

		//Second encrypt
		runs(function () {
			try {
				encryptOperation = nfCrypto.encrypt({	name: "AES-CBC", params: { iv: IV } }, importedKey, clearText);
				encryptOperation.onerror = function (e) {
					errorEncrypt = "ERROR";
				};
				encryptOperation.oncomplete = function (e) {
					encryptedTwice = e.target.result;
				};
			} catch(e) {
				errorEncrypt = "ERROR";
			}
		});

		waitsFor(function () {
			return (encrypted || error) && (encryptedTwice || errorEncrypt);
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(encrypted).toBeDefined();
			expect(errorEncrypt).toBeUndefined();
			expect(encryptedTwice).toBeDefined();
		});

		var decryptedTwice = undefined,
		decryptOp = undefined,
		decryptOperation = undefined,
		errorDecrypt = undefined;

		//First decrypt
		runs(function () {
			try {
				error = undefined;
				decryptOp = nfCrypto.decrypt({	name: "AES-CBC", params: { iv: IV_DECRYPT } }, importedKey, encrypted);
				decryptOp.onerror = function (e) {
					error = "ERROR";
				};
				decryptOp.oncomplete = function (e) {
					decrypted = e.target.result;
				};
			} catch(e) {
				error = "ERROR";
			}
		});

		//Second decrypt
		runs(function () {
			try {
				decryptOperation = nfCrypto.decrypt({	name: "AES-CBC", params: { iv: IV_DECRYPT } }, importedKey, encryptedTwice);
				decryptOperation.onerror = function (e) {
					errorDecrypt = "ERROR";
				};
				decryptOperation.oncomplete = function (e) {
					decryptedTwice = e.target.result;
				};
			} catch(e) {
				errorDecrypt = "ERROR";
			}
		});

		waitsFor(function () {
			return (decrypted || error) && (decryptedTwice || errorDecrypt);
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(decrypted).toBeDefined();
			expect(errorDecrypt).toBeUndefined();
			expect(decryptedTwice).toBeDefined();
		});
	});//it
});//describe("multiThreadedEncryptDecrypt")

describe("multiThreadedKeywrapunwrap", function () {
	it("keywrapunwrap", function () {

		var error = undefined,
		keyToWrap = undefined,
		keyData = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]),
		unwrappedKey = undefined,
		exportKeyData = undefined,
		jweData = undefined,
		pubKey = undefined,
		privKey = undefined;

		// generate RSA pub/priv key pair for wrapping with
		runs(function () {
			try {
				var genOp = undefined;
				genOp = nfCrypto.generateKey({name: "RSA-OAEP", params: { modulusLength: 1024, publicExponent: new Uint8Array([0x01, 0x00, 0x01])}},
						false,
						["wrap", "unwrap"]
				);
				genOp.onerror = function (e) {
					error = "ERROR";
				};
				genOp.oncomplete = function (e) {
					pubKey  = e.target.result.publicKey;
					privKey = e.target.result.privateKey;
				};
			} catch(e) {
				error = "ERROR";
			}
		});
		waitsFor(function () {
			return (pubKey && privKey) || error;
		});
		runs(function () {
			expect(error).toBeUndefined();
			expect(pubKey).toBeDefined();
			expect(privKey).toBeDefined();
		});

		// create the key to be wrapped
		runs(function () {
			try {
				error = undefined;
				var op = undefined;
				op = nfCrypto.importKey("raw", keyData, { name: "AES-CBC" }, true);
				op.onerror = function (e) {
					error = "ERROR";
				};
				op.oncomplete = function (e) {
					keyToWrap = e.target.result;
				};
			} catch(e) {
				error = "ERROR";
			}
		});
		waitsFor(function () {
			return keyToWrap || error;
		});
		runs(function () {
			expect(error).toBeUndefined();
			expect(keyToWrap).toBeDefined();
		});

		var wrapData = undefined,
		wrapError = undefined;

		// wrap the wrap-ee key using the public wrapping key
		//First wrap operation
		runs(function () {
			try {
				error = undefined;
				var op = undefined;
				op = nfCrypto.wrapKey(keyToWrap, pubKey, { name: "RSA-OAEP" });

				op.onerror = function (e) {
					error = "ERROR";
				};
				op.oncomplete = function (e) {
					jweData = e.target.result;
				};
			} catch(e) {
				error = "ERROR";
			}
		});

		//Second wrap operation
		runs(function () {
			try {
				error = undefined;
				var operation = undefined;
				operation = nfCrypto.wrapKey(keyToWrap, pubKey, { name: "RSA-OAEP" });

				operation.onerror = function (e) {
					wrapError = "ERROR";
				};
				operation.oncomplete = function (e) {
					wrapData = e.target.result;
				};
			} catch(e) {
				wrapError = "ERROR";
			}
		});
		waitsFor(function () {
			return (jweData || error) && (wrapData || wrapError);
		});
		runs(function () {
			expect(error).toBeUndefined();
			expect(jweData).toBeDefined();
			expect(wrapError).toBeUndefined();
			expect(wrapData).toBeDefined();
		});

		var errorUnwrap = undefined,
		operation = undefined,
		secondKey = undefined,
		errorUnwrap = undefined;

		//First unwrap
		runs(function () {
			try {
				error = undefined;
				var op = undefined;
				op = nfCrypto.unwrapKey(jweData, null, privKey, true);

				op.onerror = function (e) {
					error = "ERROR";
				};
				op.oncomplete = function (e) {
					unwrappedKey = e.target.result;
				};
			} catch(e) {
				error = "ERROR";
			}
		});

		//Second unwrap
		runs(function () {
			try {
				operation = nfCrypto.unwrapKey(wrapData, null, privKey, true);
				operation.onerror = function (e) {
					errorUnwrap = "ERROR";
				};
				operation.oncomplete = function (e) {
					secondKey = e.target.result;
				};
			} catch(e) {
				errorUnwrap = "ERROR";
			}
		});

		waitsFor(function () {
			return (unwrappedKey || error) && (errorUnwrap || secondKey);
		});
		runs(function () {
			expect(error).toBeUndefined();
			expect(unwrappedKey).toBeDefined();
			expect(errorUnwrap).toBeUndefined();
			expect(secondKey).toBeDefined();
		});

	});//it
});//describe("multiThreadedKeyWrapUnwrap")

describe("multiThreadedImportExport", function () {
	it("importexport", function () {
		var error = undefined,
		error2 = undefined;
		var key = undefined,
		keyHmac = undefined;
		var exportedKeyData = undefined,
		exportedKeyHmac = undefined;
		var importedKey = undefined;
		 // create an AES key
        var keyData = new Uint8Array([
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
            ]);
        var PKCS8KEY = base64.parse(
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
        var privKey = undefined;

		//First import raw
		runs(function () {
			var op = nfCrypto.importKey("raw", new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]), "AES-GCM", true, ["encrypt", "decrypt"]);
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				key = e.target.result;
			};
		});

		//Second import pkcs8
		runs(function () {
			try {
				var op = nfCrypto.importKey("pkcs8", PKCS8KEY, { name: "RSAES-PKCS1-v1_5" }, true);
				op.onerror = function (e) {
					error = "ERROR";
				};
				op.oncomplete = function (e) {
					privKey = e.target.result;
				};
			} catch(e) {
				error = "ERROR";
			}
		});
		waitsFor(function () {
			return (key || error) && (privKey || error2);
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(key).toBeDefined();
			expect(error2).toBeUndefined();
			expect(privKey).toBeDefined();
		});

		error = undefined;
		error2 = undefined;

		//export key
		runs(function () {
			var op = nfCrypto.exportKey("raw", key);
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				exportedKeyData = e.target.result;
			};
		});

		//second export privKey
		runs(function () {
			var op = nfCrypto.exportKey("pkcs8", privKey);
			op.onerror = function (e) {
				error2 = "ERROR";
			};
			op.oncomplete = function (e) {
				exportedKeyHmac = e.target.result;
			};
		});

		waitsFor(function () {
			return (exportedKeyData || error) && (exportedKeyHmac || error2);
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(exportedKeyData).toBeDefined();
			expect(error2).toBeUndefined();
			expect(exportedKeyHmac).toBeDefined();
		});
	});//it
});//describe("multiThreadedImportExport")

describe("multiThreadedSignVerify", function () {
	it("signverify", function () {
		var error = undefined,
		error = undefined,
		signature = undefined,
		verified = undefined,
		importKey = undefined;

		var keyData = new Uint8Array([
		                              0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		                              0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
		                              ]);
		var DATA = hex2abv("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

		//First import the key to sign/verify with
		runs(function () {
			try {
				error = undefined;
				var op = nfCrypto.importKey("raw", keyData, { name: "HMAC", params: { hash: "SHA-256" } }, true, ["sign", "verify"]);
				op.onerror = function (e) {
					error = "ERROR";
				};
				op.oncomplete = function (e) {
					importKey = e.target.result;
				};
			} catch(e) {
				error = "ERROR";
			}
		});
		
		runs(function () {
			try {
				error2 = undefined;
				var op = nfCrypto.importKey("raw", keyData, { name: "HMAC", params: { hash: "SHA-1" } }, true, ["sign", "verify"]);
				op.onerror = function (e) {
					error2 = "ERROR";
				};
				op.oncomplete = function (e) {
					importKeySha1 = e.target.result;
				};
			} catch(e) {
				error2 = "ERROR";
			}
		});

		waitsFor(function () {
			return (importKey || error) && (importKeySha1 || error2);
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(importKey).toBeDefined();
			expect(error2).toBeUndefined();
			expect(importKeySha1).toBeDefined();
		});

		//First: Sign HMAC SHA-256
		runs(function () {
			try {
				error = undefined;
				var signOp = nfCrypto.sign({ name: "HMAC", params: { hash: "SHA-256" }}, importKey, DATA);
				signOp.onerror = function (e) {
					error = "ERROR";
				};
				signOp.oncomplete = function (e) {
					signature = e.target.result;
				};
			} catch(e) {
				error = "ERROR";
			}
		});

		var signatureSHA = undefined,
		error2 = undefined;

		//Second: Sign HMAC SHA-1
		runs(function () {
			try {
				var signOp = nfCrypto.sign({ name: "HMAC", params: { hash: "SHA-1" }}, importKeySha1, DATA);
				signOp.onerror = function (e) {
					error2 = "ERROR";
				};
				signOp.oncomplete = function (e) {
					signatureSHA = e.target.result;
				};
			} catch(e) {
				error2 = "ERROR";
			}
		});

		waitsFor(function () {
			return (signature || error) && (signatureSHA || error2);
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(signature).toBeDefined();
			expect(error2).toBeUndefined();
			expect(signatureSHA).toBeDefined();
		});

		//Verify 1
		runs(function () {
			try {
				error = undefined;
				var signOp = nfCrypto.verify({ name: "HMAC", params: { hash: "SHA-256" }}, importKey, signature, DATA);
				signOp.onerror = function (e) {
					error = "ERROR";
				};
				signOp.oncomplete = function (e) {
					verified = e.target.result;
				};
			} catch(e) {
				error = "ERROR";
			}					
		});
		
		//Verify 2
		var verifiedSha = undefined,
		error2 = undefined;
		
		runs(function () {
			try {
				var signOp = nfCrypto.verify({ name: "HMAC", params: { hash: "SHA-1" }}, importKeySha1, signatureSHA, DATA);
				signOp.onerror = function (e) {
					error2 = "ERROR";
				};
				signOp.oncomplete = function (e) {
					verifiedSha = e.target.result;
				};
			} catch(e) {
				error2 = "ERROR";
			}					
		});

		waitsFor(function () {
			return (verified !== undefined || error) && (verifiedSha !== undefined || error2);
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(verified).toBe(true);
			expect(error2).toBeUndefined();
			expect(verifiedSha).toBe(true);
		});

	});//it
});//describe("multiThreadedSignVerify")
