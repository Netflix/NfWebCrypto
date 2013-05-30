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

describe("ImportExportRSA", function () {

	//Global key data
	// SPKI - Simple Public Key Infrastructure
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

	// PKCS #8: Private Key Information Syntax Standard #8
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

	it("ImportExportSpkiKeyHappyPath", function () {
		var error = undefined;
		var key = undefined;
		var exportedSpkiKeyData = undefined;

		runs(function () {
			error = undefined;
			var op = nfCrypto.importKey("spki", spkiPubKeyData, { name: "RSAES-PKCS1-v1_5" }, true);
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				key = e.target.result;
			};
		});

		waitsFor(function () {
			return key || error;
		});

		runs(function () {
			expect(error).toBeUndefined();
			//Doing checks on keys to validate Key structure
			expect(key.algorithm.name).toEqual("RSAES-PKCS1-v1_5");
			expect(key.extractable).toBeTruthy();
			expect(key.keyUsages.length).toEqual(0);
			//TODO: need to confirm what the default value should be
			//expect(key.keyUsages[0]).toEqual("sign");
			expect(key.type).toEqual("public");
			//Handle is how C++ correlates keys with JS
			//0 implies invalid key
			expect(key.handle).not.toEqual(0);
		});

		runs(function () {
			var op = nfCrypto.exportKey("spki", key);
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				exportedSpkiKeyData = e.target.result;
			};
		});

		waitsFor(function () {
			return error || exportedSpkiKeyData;
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(exportedSpkiKeyData).toBeDefined();
			expect(exportedSpkiKeyData).toEqual(spkiPubKeyData);
		});
	});//it("ImportExportSpkiKeyHappyPath")


	it("ImportExportPKCS8HappyPath", function () {
		var error = undefined;
		var privKey = undefined;
		var pkcs8PrivKeyData2 = undefined;

		// import pkcs8-formatted private key
		runs(function () {
			var op = nfCrypto.importKey("pkcs8", pkcs8PrivKeyData, { name: "RSAES-PKCS1-v1_5" }, true);
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				privKey = e.target.result;
			};
		});

		waitsFor(function () {
			return privKey || error;
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(privKey.algorithm.name).toEqual("RSAES-PKCS1-v1_5");
			expect(privKey.keyUsages.length).toEqual(0);
			//TODO: need to confirm what the default value should be
			//expect(key.keyUsages[0]).toEqual("sign");
			//Handle is how C++ correlates keys with JS
			//0 implies invalid key
			expect(privKey.handle).not.toEqual(0);
			//TODO: need to confirm what the default value should be
			expect(privKey.type).toBe("private");
			expect(privKey.extractable).toBe(true);
		});

		// export the private key back out, raw pkcs8 data should be the same
		runs(function () {
			error = undefined;
			var op = nfCrypto.exportKey("pkcs8", privKey);
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				pkcs8PrivKeyData2 = e.target.result;
			};
		});

		waitsFor(function () {
			return pkcs8PrivKeyData2 || error;
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(pkcs8PrivKeyData2).toBeDefined();
			expect(base16.stringify(pkcs8PrivKeyData2)).toEqual(base16.stringify(pkcs8PrivKeyData));
		});
	});

	//Import public and private keys no export, encrypt with public, decrypt with private
	//Also checks that extractable field in api is ignored for spki keys
	//Always return extractable=true since that's what C++ code does
	it("ImportPKCSPrivateKeySPKIPublicKey", function () {
		var error = undefined;
		var privKey = undefined;
		var pubKey = undefined;
		var decrypted = undefined;
		var cipherText = undefined;

		// import pkcs8-formatted private key
		runs(function () {
			var op = nfCrypto.importKey("pkcs8", pkcs8PrivKeyData, { name: "RSAES-PKCS1-v1_5" }, false);
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				privKey = e.target.result;
			};
		});

		waitsFor(function () {
			return privKey || error;
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(privKey.algorithm.name).toEqual("RSAES-PKCS1-v1_5");
			expect(privKey.extractable).toBeFalsy();
			expect(privKey.keyUsages.length).toEqual(0);
			//TODO: need to confirm what the default value should be
			//expect(privKey.keyUsages[0]).toEqual("sign");
			expect(privKey.type).toBe("private");
			expect(privKey.extractable).toBe(false);
			//Handle is how C++ correlates keys with JS
			//0 implies invalid key
			expect(privKey.handle).not.toEqual(0);
		});

		// import corresponding spki-formatted public key
		runs(function () {
			error = undefined;8
			var op = nfCrypto.importKey("spki", spkiPubKeyData, { name: "RSAES-PKCS1-v1_5" }, false);
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				pubKey = e.target.result;
			};
		});

		waitsFor(function () {
			return pubKey || error;
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(pubKey.algorithm.name).toEqual("RSAES-PKCS1-v1_5");
			//Since this is a public key it should always be true, irrespective of what is specified in the api
			expect(pubKey.extractable).toBeTruthy();
			expect(pubKey.keyUsages.length).toEqual(0);
			//TODO: need to confirm what the default value should be
			//expect(pubKey.keyUsages[0]).toEqual("sign");
			expect(pubKey.type).toBe("public");
			//Handle is how C++ correlates keys with JS
			//0 implies invalid key
			expect(pubKey.handle).not.toEqual(0);
		});

		var clearText = base16.parse("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

		// encrypt clearText with the public key
		runs(function () {
			error = undefined;
			var encryptOp = nfCrypto.encrypt({ name: "RSAES-PKCS1-v1_5" }, pubKey, clearText);
			encryptOp.onerror = function (e) {
				error = "ERROR";
			};
			encryptOp.oncomplete = function (e) {
				cipherText = e.target.result;
			};
		});

		waitsFor(function () {
			return cipherText || error;
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(cipherText).toBeDefined();
			expect(cipherText).toNotEqual(clearText);
		});

		// decrypt cipherText with the private key, should get the same clearText back
		runs(function () {
			error = undefined;
			var encryptOp = nfCrypto.decrypt({ name: "RSAES-PKCS1-v1_5" }, privKey, cipherText);
			encryptOp.onerror = function (e) {
				error = "ERROR";
			};
			encryptOp.oncomplete = function (e) {
				decrypted = e.target.result;
			};
		});

		waitsFor(function () {
			return decrypted || error;
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(decrypted).toBeDefined();
			expect(decrypted).toEqual(clearText);
		});
	});//it("ImportPKCSPublicPrivateKey")

	//importKey/exportKey raw AES-CBC
	it("ImportExportRawHappyPath", function () {
		var error = undefined;
		var key = undefined;
		var keyData = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]);
		var keyData2 = undefined;    

		runs(function () {
			// TODO:
			// Once https://www.w3.org/Bugs/Public/show_bug.cgi?id=21435 is resolved, might need to pass in length as part of AlgorithmIdentifier
			var op = nfCrypto.importKey("raw", keyData, { name: "AES-CBC" }, true);
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				key = e.target.result;
			};
		});

		waitsFor(function () {
			return key || error;
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(key.algorithm.name).toEqual("AES-CBC");
			expect(key.extractable).toBeTruthy();
			expect(key.keyUsages.length).toEqual(0);
			//TODO: need to confirm what the default value should be
			//expect(key.keyUsages[0]).toEqual("sign");
			expect(key.type).toBe("secret");
			//Handle is how C++ correlates keys with JS
			//0 implies invalid key
			expect(key.handle).not.toEqual(0);
		});

		runs(function () {
			var op = nfCrypto.exportKey("raw", key);
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				keyData2 = e.target.result;
			};
		});

		waitsFor(function () {
			return keyData2 || error;
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(keyData2).toBeDefined();
			expect(base16.stringify(keyData2)).toEqual(base16.stringify(keyData));
		});

	});

	it("ImportNullKey", function () {
		var error = undefined;
		var key = undefined;
		var jwkKeyData = null;

		runs(function () {

			var op = nfCrypto.importKey("jwk", jwkKeyData, { name: "RSAES-PKCS1-v1_5" }, true);
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				key = e.target.result;
			};
		});

		waitsFor(function () {
			return key || error;
		});

		runs(function () {
			expect(error).toBe("ERROR");
			expect(key).toBeUndefined();
		});
	});//it("ImportNullKey")

	it("ImportEmptyKey", function () {
		var error = undefined;
		var key = undefined;
		var pkcsKey = hex2abv("");

		runs(function () {

			var op = nfCrypto.importKey("pkcs8", pkcsKey, { name: "RSAES-PKCS1-v1_5" }, true);
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				key = e.target.result;
			};
		});

		waitsFor(function () {
			return key || error;
		});

		runs(function () {
			expect(error).toBe("ERROR");
			expect(key).toBeUndefined();
		});
	});//it("ImportEmptyKey")

	it("ImportExportNullSpkiKey", function () {
		var error = undefined;
		var key = undefined;
		var exportedSpkiKeyData = undefined;

		runs(function () {
			error = undefined;
			var op = nfCrypto.importKey("spki", spkiPubKeyData, { name: "RSAES-PKCS1-v1_5" }, true);
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				key = e.target.result;
			};
		});

		waitsFor(function () {
			return key || error;
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(key).toBeDefined();
		});

		runs(function () {
			key = null;
			var op = nfCrypto.exportKey("spki", key);
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				exportedSpkiKeyData = e.target.result;
			};
		});

		waitsFor(function () {
			return error || exportedSpkiKeyData;
		});

		runs(function () {
			expect(error).toBe("ERROR");
			expect(exportedSpkiKeyData).toBeUndefined();
		});
	});//it("ImportExportNullSpkiKey")

	it("ImportExportEmptySpkiKey", function () {
		var error = undefined;
		var key = undefined;
		var exportedSpkiKeyData = undefined;

		runs(function () {
			error = undefined;
			var op = nfCrypto.importKey("spki", spkiPubKeyData, { name: "RSAES-PKCS1-v1_5" }, true);
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				key = e.target.result;
			};
		});

		waitsFor(function () {
			return key || error;
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(key).toBeDefined();
		});

		runs(function () {
			key = hex2abv("");
			var op = nfCrypto.exportKey("spki", key);
			op.onerror = function (e) {
				error = "ERROR";			};
				op.oncomplete = function (e) {
					exportedSpkiKeyData = e.target.result;
				};
		});

		waitsFor(function () {
			return error || exportedSpkiKeyData;
		});

		runs(function () {
			expect(error).toBe("ERROR");
			expect(exportedSpkiKeyData).toBeUndefined();
		});
	});//it("ImportExportEmptySpkiKey")

	//Importing two different keys objects and substituting one for another
	//Import raw, spki export spki but pass in raw key obj
	it("ImportTwoKeysExportDiffKey", function () {
		var error = undefined;
		var rawKey, spkiKey, exportedSpkiKeyData = undefined;
		var keyData = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]);

		//Importing raw key
		runs(function () {
			// TODO:
			// Once https://www.w3.org/Bugs/Public/show_bug.cgi?id=21435 is resolved, might need to pass in length as part of AlgorithmIdentifier
			var op = nfCrypto.importKey("raw", keyData, { name: "AES-CBC" }, true);
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				rawKey = e.target.result;
			};
		});

		waitsFor(function () {
			return rawKey || error;
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(rawKey).toBeDefined();
		});	

		//Importing spki key
		runs(function () {
			error = undefined;
			var op = nfCrypto.importKey("spki", spkiPubKeyData, { name: "RSAES-PKCS1-v1_5" }, true);
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				spkiKey = e.target.result;
			};
		});

		waitsFor(function () {
			return spkiKey || error;
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(spkiKey).toBeDefined();
		});

		//Export rawKey obj with spki algo
		runs(function () {
			key = null;
			var op = nfCrypto.exportKey("spki", rawKey);
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				exportedSpkiKeyData = e.target.result;
			};
		});

		waitsFor(function () {
			return error || exportedSpkiKeyData;
		});

		runs(function () {
			expect(error).toBe("ERROR");
			expect(exportedSpkiKeyData).toBeUndefined();
		});
	});//it("ImportTwoKeysExportDiffKey")

	//Import/export -tamper key then import again
	it("ImportMalformedSpkiKey", function () {
		var error = undefined;
		var key = undefined;
		var exportedSpkiKeyData = undefined;
		var importKey = undefined;

		runs(function () {
			error = undefined;
			var op = nfCrypto.importKey("spki", spkiPubKeyData, { name: "RSAES-PKCS1-v1_5" }, true);
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				key = e.target.result;
			};
		});

		waitsFor(function () {
			return key || error;
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(key).toBeDefined();
		});

		runs(function () {
			var op = nfCrypto.exportKey("spki", key);
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				exportedSpkiKeyData = e.target.result;
			};
		});

		waitsFor(function () {
			return error || exportedSpkiKeyData;
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(exportedSpkiKeyData).toBeDefined();
			expect(exportedSpkiKeyData).toEqual(spkiPubKeyData);
		});
		//Import again - tampering import key
		runs(function () {
			exportedSpkiKeyData[0] = exportedSpkiKeyData[0] ^ 0xFF;
			var op = nfCrypto.importKey("spki", exportedSpkiKeyData, { name: "RSAES-PKCS1-v1_5" }, true);
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				importKey = e.target.result;
			};
		});

		waitsFor(function () {
			return importKey || error;
		});

		runs(function () {
			expect(error).toBe("ERROR");
			expect(importKey).toBeUndefined();
		});

	});//it("ImportMalformedSpkiKey")

	it("ImportIncorrectAlgoForSignVerify", function () {
		var error = undefined;
		var KEY = undefined;

		runs(function () {
			var op = nfCrypto.importKey(
					"raw",
					new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]),
					{ name: "AES-GCM" },
					true,
					["sign", "verify"]
			);
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				KEY = e.target.result;
			};
		});

		waitsFor(function () {
			return KEY || error;
		});

		runs(function () {
			expect(error).toBe("ERROR");
			expect(KEY).toBeUndefined();
		});
	});//it("ImportIncorrectAlgoForSignVerify")
	
	it("ImportIncorrectAlgoForEncryptDecrypt", function () {
		var error = undefined;
		var KEY = undefined;

		runs(function () {
			var op = nfCrypto.importKey(
					"raw",
					new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]),
					{ name: "HMAC" },
					true,
					["encrypt", "decrypt"]
			);
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				KEY = e.target.result;
			};
		});

		waitsFor(function () {
			return KEY || error;
		});

		runs(function () {
			expect(error).toBe("ERROR");
			expect(KEY).toBeUndefined();
		});
	});//it("ImportIncorrectAlgoForEncrypt")
	
	it("ImportIncorrectAlgoForDerive", function () {
		var error = undefined;
		var KEY = undefined;

		runs(function () {
			var op = nfCrypto.importKey(
					"raw",
					new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]),
					{ name: "HMAC" },
					true,
					["derive"]
			);
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				KEY = e.target.result;
			};
		});

		waitsFor(function () {
			return KEY || error;
		});

		runs(function () {
			expect(error).toBe("ERROR");
			expect(KEY).toBeUndefined();
		});
	});//it("ImportIncorrectAlgoForDerive")
	
	it("ImportSpkiExportJwk", function() {
		var error = undefined;
		var key = undefined;
		var exportedJwkData = undefined,
			keyJwk = undefined,
			spkiExported = undefined;
        //Import SPKI
		runs(function () {
			error = undefined;
			var op = nfCrypto.importKey("spki", spkiPubKeyData, { name: "RSAES-PKCS1-v1_5" }, true, ["encrypt", "decrypt"]);
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				key = e.target.result;
			};
		});
		waitsFor(function () {
			return key || error;
		});
		runs(function () {
			expect(error).toBeUndefined();
			//Doing checks on keys to validate Key structure
			expect(key.algorithm.name).toEqual("RSAES-PKCS1-v1_5");
			expect(key.extractable).toBeTruthy();
			expect(key.keyUsages.length).toEqual(2);
			expect(key.keyUsages[0]).toEqual("encrypt");
			expect(key.keyUsages[1]).toEqual("decrypt");
			expect(key.type).toEqual("public");
			//Handle is how C++ correlates keys with JS
			//0 implies invalid key
			expect(key.handle).not.toEqual(0);
		});
        //Export JWK
		runs(function () {
			error = undefined;
			var op = nfCrypto.exportKey("jwk", key);
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				exportedJwkData = e.target.result;
			};
		})
		waitsFor(function () {
			return exportedJwkData || error;
		});
		runs(function () {
			expect(error).toBeUndefined();
			expect(exportedJwkData).toBeDefined();
		});	
        //Import JWK
		runs(function () {
			error = undefined;
			var op = nfCrypto.importKey("jwk", exportedJwkData, { name: "RSAES-PKCS1-v1_5" }, true);
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				keyJwk = e.target.result;
			};
		});

		waitsFor(function () {
			return keyJwk || error;
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(keyJwk).toBeDefined();	
			//Doing checks on keys to validate Key structure
			expect(keyJwk.algorithm.name).toEqual("RSAES-PKCS1-v1_5");
			expect(keyJwk.extractable).toBeTruthy();
			expect(key.keyUsages.length).toEqual(2);
			expect(key.keyUsages[0]).toEqual("encrypt");
			expect(key.keyUsages[1]).toEqual("decrypt");
			expect(keyJwk.type).toEqual("public");
			//Handle is how C++ correlates keys with JS
			//0 implies invalid key
			expect(keyJwk.handle).not.toEqual(0);
		});
        //Export JWK
		runs(function () {
			error = undefined;
			var op = nfCrypto.exportKey("spki", keyJwk);
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				spkiExported = e.target.result;
			};
		})
		waitsFor(function () {
			return spkiExported || error;
		});
		runs(function () {
			expect(error).toBeUndefined();
			expect(spkiExported).toBeDefined();
			expect(spkiExported).toEqual(spkiPubKeyData);
		});	
	});//it("ImportSpkiExportJwk")
	
	//Test should fail export of JWK since this is a pvt key
	it("ImportPKCS8ExportJwk", function() {
		var error = undefined;
		var privKey = undefined;
		var exportedJwkData = undefined;

		// import pkcs8-formatted private key
		runs(function () {
			var op = nfCrypto.importKey("pkcs8", pkcs8PrivKeyData, { name: "RSAES-PKCS1-v1_5" }, true);
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				privKey = e.target.result;
			};
		});

		waitsFor(function () {
			return privKey || error;
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(privKey.algorithm.name).toEqual("RSAES-PKCS1-v1_5");
			expect(privKey.keyUsages.length).toEqual(0);
			//TODO: need to confirm what the default value should be
			//expect(key.keyUsages[0]).toEqual("sign");
			//Handle is how C++ correlates keys with JS
			//0 implies invalid key
			expect(privKey.handle).not.toEqual(0);
			//TODO: need to confirm what the default value should be
			expect(privKey.type).toBe("private");
			expect(privKey.extractable).toBe(true);
		});
		//Export JWK
		runs(function () {
			error = undefined;
			var op = nfCrypto.exportKey("jwk", privKey);
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				exportedJwkData = e.target.result;
			};
		})
		waitsFor(function () {
			return exportedJwkData || error;
		});
		runs(function () {
			expect(error).toBeDefined();
			expect(exportedJwkData).toBeUndefined();
		});	
		
	});//it("ImportPKCS8ExportJwk"
	
	it("ImportRawExportJwk", function() {
		var error = undefined;
		var key = undefined;
		var keyData = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]);
		var keyData2 = undefined,
			exportedJwkData = undefined,
			keyJwk = undefined,
			rawExported = undefined;  

		runs(function () {
			// TODO:
			// Once https://www.w3.org/Bugs/Public/show_bug.cgi?id=21435 is resolved, might need to pass in length as part of AlgorithmIdentifier
			var op = nfCrypto.importKey("raw", keyData, { name: "AES-CBC" }, true, ["encrypt", "decrypt"]);
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				key = e.target.result;
			};
		});

		waitsFor(function () {
			return key || error;
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(key.algorithm.name).toEqual("AES-CBC");
			expect(key.extractable).toBeTruthy();
			expect(key.keyUsages.length).toEqual(2);
			expect(key.keyUsages[0]).toEqual("encrypt");
			expect(key.keyUsages[1]).toEqual("decrypt");
			expect(key.type).toBe("secret");
			//Handle is how C++ correlates keys with JS
			//0 implies invalid key
			expect(key.handle).not.toEqual(0);
		});
		 //Export JWK
		runs(function () {
			error = undefined;
			var op = nfCrypto.exportKey("jwk", key);
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				exportedJwkData = e.target.result;
			};
		})
		waitsFor(function () {
			return exportedJwkData || error;
		});
		runs(function () {
			expect(error).toBeUndefined();
			expect(exportedJwkData).toBeDefined();
		});	
        //Import JWK
		runs(function () {
			error = undefined;
			var op = nfCrypto.importKey("jwk", exportedJwkData, { name: "AES-CBC" }, true, ["encrypt", "decrypt"]);
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				keyJwk = e.target.result;
			};
		});

		waitsFor(function () {
			return keyJwk || error;
		});

		runs(function () {
			expect(error).toBeUndefined();
			expect(keyJwk.algorithm.name).toEqual("AES-CBC");
			expect(keyJwk.extractable).toBeTruthy();
			expect(keyJwk.keyUsages.length).toEqual(2);
			expect(keyJwk.keyUsages[0]).toEqual("encrypt");
			expect(keyJwk.keyUsages[1]).toEqual("decrypt");
			expect(keyJwk.type).toBe("secret");
			//Handle is how C++ correlates keys with JS
			//0 implies invalid key
			expect(keyJwk.handle).not.toEqual(0);
		});
        //Export JWK
		runs(function () {
			error = undefined;
			var op = nfCrypto.exportKey("raw", keyJwk);
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				rawExported = e.target.result;
			};
		})
		waitsFor(function () {
			return rawExported || error;
		});
		runs(function () {
			expect(error).toBeUndefined();
			expect(rawExported).toBeDefined();
			expect(rawExported).toEqual(keyData);
		});	
		
	});//it("ImportPKCS8ExportJwk"

});//describe