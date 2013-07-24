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

describe("encryptaes", function () {

	var OPINDEX = 0;
	var INDEXVALUE = 0;
	var ORG_IV = "562e17996d093d28ddb3ba695a2e6f58";
	var IV = base16.parse(ORG_IV);
	var IV_DECRYPT = base16.parse(ORG_IV);
	var SHORT_IV = base16.parse("ddb3ba695a2e6f58");
	var CLEARTEXT_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    	CLEARTEXT = base16.parse(CLEARTEXT_HEX);
	var LARGE_CLEARTEXT_NOTHEX = "eyJtZXNzYWdlaWQiOjQ2MDQwODM3Niwibm9ucmVwbGF5YWJsZSI6ZmFsc2UsInJlbmV3YWJsZSI6dHJ1ZSwiY2FwYWJpbGl0aWVzIjp7ImNvbXByZXNzaW9uYWxnb3MiOlsiTFpXIl19LCJrZXlyZXF1ZXN0ZGF0YSI6W3sic2NoZW1lIjoiQVNZTU1FVFJJQ19XUkFQUEVEIiwia2V5ZGF0YSI6eyJrZXlwYWlyaWQiOiJyc2FLZXlwYWlySWQiLCJtZWNoYW5pc20iOiJSU0EiLCJwdWJsaWNrZXkiOiJUVWxIU2tGdlIwSkJUMWxYVXpZMk5ubEhjazU1U0Vkbk4yMHZaMlJuYjBKMVJGaHpLM0JOU1dWTGNVNVBkMlZKYW5selRYSjRTVTk0WjJ4TVMzRkVOa2xsV2pkd01VSmlVRVY0V0ZoS2EzTlpOR2RUVGtNM01FTmxRVUpFVVRkRmIzRmlXR1V3UkRsVVZFNU9MMHBOVW01SmNtVnVaWFU1TldOeE5ucGhNSGcxVjFkemEzWkxTRTh6Y21GVk9YZEZjQzlaUlZNM2JWVnphMmx5V2s1QkswWlVUVlJhT1RKalUxaDZXUzlyTUZFMlpHVTNRV2ROUWtGQlJUMD0ifX1dfQ==",
		LARGE_CLEARTEXT = base64.parse(LARGE_CLEARTEXT_NOTHEX);

	var LISTOFOPERATIONS = [                  
	    {                    	
	    	name: "AESEncryptDecryptHappyPath",
	    	algo: {	name: "AES-CBC", params: { iv: IV } },
	        clearText: CLEARTEXT,
	        result: "pass"
	    },
	    
	    {   //Encryption algo(AES-CBC) does not match import key(AES-GCM)               	
	    	name: "AESMismatchedEncryptionAlgoImportKey",
	    	algo: {	name: "AES-CBC", params: { iv: IV } },
	        clearText: CLEARTEXT,
	        disableDecrypt: true,
	        encrypt: false
	    },
	    
	    {                    	
	    	name: "AESEncryptDecryptLargeData",
	    	algo: {	name: "AES-CBC", params: { iv: IV } },
	    	clearText: LARGE_CLEARTEXT,
	        result: "pass"
	    },
	    
	    {   //IV is changed just before decrypt
	    	//Uses different iv for decryption, expect decrypted clear text to be different
	    	//from original clear text
	    	name: "AESDifferentDecryptIV",
	    	algo: {	name: "AES-CBC", params: { iv: IV } },
	    	clearText: CLEARTEXT,
	        result: "pass"
	    },
	    
	    {   //Change encrypted data after encryption expect decryption to not match clear text               	
	    	name: "AESMangledEncryptionData",
	    	algo: {	name: "AES-CBC", params: { iv: IV } },
	    	clearText: CLEARTEXT,
	        result: "pass"
	    },
	    
	    {             	
	    	name: "AESEncryptNullData",
	    	algo: {	name: "AES-CBC", params: { iv: IV } },
	    	clearText: null,
	        disableDecrypt: true,
	        encrypt: false
	    },
	    
	    {             	
	    	name: "AESEncryptEmptyData",
	    	algo: {	name: "AES-CBC", params: { iv: IV } },
	    	clearText: new Uint8Array([]),
	        disableDecrypt: true,
	        encrypt: true
	    },
	    
	    {                    	
	    	name: "AESEncryptInvalidAlgoType",
	    	algo: {	name: "RSASSA_PKCS1_V1_5", params: { iv: IV } },
	        clearText: CLEARTEXT,
	        disableDecrypt: true,
	        encrypt: false
	    },
	    
	    {                    	
	    	name: "AESEncryptInvalidAlgo",
	    	algo: {	name: "cbc", params: { iv: IV } },
	        clearText: CLEARTEXT,
	        disableDecrypt: true,
	        encrypt: false
	    },
	    
	    {    //!!!!NOTE THIS TEST WILL NOT WORK WHEN REAL WEBCRYPTO COMES ALONG!!!!!!!                 	
	    	name: "AESEncryptInvalidKeyHandle",
	    	//key manipulation happens just before 
	    	algo: {	name: "AES-CBC", params: { iv: IV } },
	        clearText: CLEARTEXT,
	        disableDecrypt: true,
	        encrypt: false
	    },
	    
	    {   //8 byte IV is not allowed 16 bytes required by algo              	
	    	name: "AESEncryptShortIV",
	    	algo: {	name: "AES-CBC", params: { iv: SHORT_IV } },
	        clearText: CLEARTEXT,
	        disableDecrypt: true,
	        encrypt: false
	    },
	    
	    {   //Fails since encryption is done with a key where usage is incorrectly specified
	    	//as decrypt only
	    	name: "AESEncryptUsingKeyWithInvalidUsage",
	    	algo: {	name: "AES-CBC", params: { iv: IV } },
	        clearText: CLEARTEXT,
	        disableDecrypt: true,
	        encrypt: false
	    }
	    
	];
/*
	// This is a function that does a lot of the common stuff we do.
	// It runs a crypto operation with the given arguments, waits for
	// it to fail or succeed and then calls the 'after' function with
	// the result of the operation and the error, if any

	function runop(name, args, after) {
		var error,
			result;
		runs(function() {
			var op;
			try {
				op = nfCrypto[name].apply(nfCrypto, args);
				op.oncomplete = function(event) { result = event.target.result; };
				op.onerror = function() { error = true; };
			} catch(e) {
				error = true;
			}
		});

		waitsFor(function() {
			return error || result;
		});

		runs(function() {
			after(result, error);
		});
	}
*/	
	function wrapperForTest(OPINDEX) {	
		it(LISTOFOPERATIONS[OPINDEX].name, function () {
			INDEXVALUE = LISTOFOPERATIONS[OPINDEX];

			var error = undefined;
			var encrypted = undefined;
			var decrypted = undefined;
			var importedKey = undefined;
/*
			// If we use the 'runop' function above, we can shorten this
			// sequence to just this:

			runop('importKey', [
					"raw",
					new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]),
					"AES-CBC", true, ["encrypt", "decrypt"]
				], 
				function(result, error) {
					expect(error).toBeUndefined();
					expect(result).toBeDefined();
					importedKey = result;
				});
*/
			runs(function () {
				try {
					var op = undefined;
					if(INDEXVALUE.name == "AESMismatchedEncryptionAlgoImportKey") {
						op = nfCrypto.importKey(
								"raw",
								new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]),
								"AES-GCM",
								true,
								["encrypt", "decrypt"]
						);
						
					} else if (INDEXVALUE.name == "AESEncryptUsingKeyWithInvalidUsage") {
						op = nfCrypto.importKey(
								"raw",
								new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]),
								"AES-CBC",
								true,
								["decrypt"]
						);
					} else {
						op = nfCrypto.importKey(
								"raw",
								new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]),
								"AES-CBC",
								true,
								["encrypt", "decrypt"]
						);
					}
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
			
			runs(function () {
				try {
					error = undefined;
					if(INDEXVALUE.name == "AESEncryptInvalidKeyHandle") {
						importedKey.handle = 0;
					}
					var encryptOp = nfCrypto.encrypt(INDEXVALUE.algo, importedKey, INDEXVALUE.clearText);
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

			waitsFor(function () {
				return encrypted || error;
			});

			runs(function () {
				if(INDEXVALUE.encrypt == false) {
					expect(error).toBeDefined();
					expect(encrypted).toBeUndefined();
				} else {
					expect(error).toBeUndefined();
					expect(encrypted).toBeDefined();
					expect(encrypted).not.toBeNull();
					expect(base16.stringify(encrypted)).not.toBe(INDEXVALUE.clearText);
				}
			});
			
			if(INDEXVALUE.disableDecrypt != true) {
				runs(function () {
					try {
						error = undefined;
						if (INDEXVALUE.name == "AESMangledEncryptionData") {
							encrypted[0] = encrypted[0] ^ 0xFF;
						}
						if (INDEXVALUE.name == "AESDifferentDecryptIV") {
							var diff_iv = base16.parse("b63e541bc9ece19a1339df4f8720dcc3");
							INDEXVALUE.algo.params.iv = diff_iv
						} else {
							//Require a separate IV since encrypt was clobbering original IV
							INDEXVALUE.algo.params.iv = IV_DECRYPT;
						}
						var decryptOp = nfCrypto.decrypt(INDEXVALUE.algo, importedKey, encrypted);
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

				waitsFor(function () {
					return decrypted || error;
				});

				runs(function () {
					if(INDEXVALUE.decrypt == false) {
						expect(error).toBeDefined();
						expect(decrypted).toBeUndefined();
					} else {
						expect(error).toBeUndefined();
						expect(decrypted).toBeDefined();
						if (INDEXVALUE.name == "AESEncryptDecryptLargeData") {
							//converts back to string to compare
							expect(base64.stringify(decrypted)).toBe(LARGE_CLEARTEXT_NOTHEX);
						} else if (INDEXVALUE.name == "AESDifferentDecryptIV" || INDEXVALUE.name == "AESMangledEncryptionData") {
							expect(base16.stringify(decrypted)).not.toBe(CLEARTEXT_HEX);	
						} else {
							expect(base16.stringify(decrypted)).toBe(CLEARTEXT_HEX);
						}			
					}
				});
			}//if(INDEXVALUE.disableDecrypt 
		});//it
	}//function wrapperForTest
	for(OPINDEX = 0; OPINDEX < LISTOFOPERATIONS.length; OPINDEX++) {	
		wrapperForTest(OPINDEX);
	}
});//describe("EncryptAES")

describe("decryptaes", function () {

	var OPINDEX = 0;
	var INDEXVALUE = 0;
	var ORG_IV = "562e17996d093d28ddb3ba695a2e6f58";
	var IV = base16.parse(ORG_IV);
	var IV_DECRYPT = base16.parse(ORG_IV);
	var SHORT_IV = base16.parse("ddb3ba695a2e6f58");
	var CLEARTEXT_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
	var CLEARTEXT = base16.parse(CLEARTEXT_HEX);
	

	var LISTOFOPERATIONS = [                    	
	        {             	
	   	    	name: "AESDecryptNullData",
	   	    	algo: {	name: "AES-CBC", params: { iv: IV_DECRYPT } },	   	        
	   	        decrypt: false
	   	    },
	   	    
	   	    {             	
	   	    	name: "AESDecryptEmptyData",
	   	    	algo: {	name: "AES-CBC", params: { iv: IV_DECRYPT } },
	   	    	decrypt: false
	   	    },
	   	    
	   	    {                    	
	   	    	name: "AESDecryptInvalidAlgoType",
	   	    	algo: {	name: "RSASSA_PKCS1_V1_5", params: { iv: IV_DECRYPT } },
	   	    	decrypt: false
	   	    },
	   	    
	   	    {                    	
	   	    	name: "AESDecryptInvalidAlgo",
	   	    	algo: {	name: "cbc", params: { iv: IV_DECRYPT } },
	   	    	decrypt: false
	   	    },
		    
		    {    //!!!!NOTE THIS TEST WILL NOT WORK WHEN REAL WEBCRYPTO COMES ALONG!!!!!!!                 	
		    	name: "AESDecryptInvalidKeyHandle",
		    	//key manipulation happens just before decrypt
		    	algo: {	name: "AES-CBC", params: { iv: IV_DECRYPT } },	   	        
	   	        decrypt: false
		    },
		    
		    {   //8 byte IV is not allowed 16 bytes required by algo              	
		    	name: "AESDecryptShortIV",
		    	algo: {	name: "AES-CBC", params: { iv: SHORT_IV } },     
	   	        decrypt: false
		    },
		    
		    {   //Imported key has usage as only encrypt so decrypt should fail since 
		    	//key does not support decrypt
	   	    	name: "AESDecryptUsingKeyWithInvalidUsage",
	   	    	algo: {	name: "AES-CBC", params: { iv: IV_DECRYPT } },	   	        
	   	        decrypt: false
	   	    },
	   	    
	];
	function wrapperForTest(OPINDEX) {	
		it(LISTOFOPERATIONS[OPINDEX].name, function () {
			INDEXVALUE = LISTOFOPERATIONS[OPINDEX];

			var error = undefined;
			var encrypted = undefined;
			var decrypted = undefined;
			var importedKey = undefined;

			runs(function () {
				try {
					var op = undefined;
					if(INDEXVALUE.name == "AESDecryptUsingKeyWithInvalidUsage") {
						op = nfCrypto.importKey(
								"raw",
								new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]),
								"AES-CBC",
								true,
								["encrypt"]
							);
					} else {
						op = nfCrypto.importKey(
							"raw",
							new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]),
							"AES-CBC",
							true,
							["encrypt", "decrypt"]
						);
					}
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
			
			runs(function () {
				try {
					error = undefined;
					var encryptOp = nfCrypto.encrypt({name: "AES-CBC", params: { iv: IV } }, importedKey, CLEARTEXT);
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

			waitsFor(function () {
				return encrypted || error;
			});

			runs(function () {
				expect(error).toBeUndefined();
				expect(encrypted).toBeDefined();
				expect(encrypted).not.toBeNull();
				expect(base16.stringify(encrypted)).not.toBe(CLEARTEXT);
			});
			
			runs(function () {
				try {
					error = undefined;
					if(INDEXVALUE.name == "AESDecryptNullData") {
						encrypted = null;
					} else if (INDEXVALUE.name == "AESDecryptEmptyData") {
						encrypted = new Uint8Array([]);
					} else if (INDEXVALUE.name == "AESDecryptInvalidKeyHandle") {
						importedKey.handle = 0;
					}
					var decryptOp = nfCrypto.decrypt(INDEXVALUE.algo, importedKey, encrypted);
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

			waitsFor(function () {
				return decrypted || error;
			});

			runs(function () {
				if(INDEXVALUE.decrypt == false) {
					expect(error).toBeDefined();
					expect(decrypted).toBeUndefined();
				} else {
					expect(error).toBeUndefined();
					expect(decrypted).toBeDefined();
					expect(base16.stringify(decrypted)).toBe(CLEARTEXT_HEX);				
				}
			});
		});//it
	}//function wrapperForTest
	for(OPINDEX = 0; OPINDEX < LISTOFOPERATIONS.length; OPINDEX++) {	
		wrapperForTest(OPINDEX);
	}
});//describe("decryptaes")

describe("encryptrsa", function () {

	var OPINDEX = 0;
	var INDEXVALUE = 0;
	var SHORT_IV = base16.parse("ddb3ba695a2e6f58");
	var CLEARTEXT_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
	var CLEARTEXT = base16.parse(CLEARTEXT_HEX);
	var LARGE_CLEARTEXT_NOTHEX = "eyJtZXNzYWdlaWQiOjQ2MDQwODM3Niwibm9ucmVwbGF5YWJsZSI6ZmFsc2UsInJlbmV3YWJsZSI6dHJ1ZSwiY2FwYWJpbGl0aWVzIjp7ImNvbXByZXNzaW9uYWxnb3MiOlsiTFpXIl19LCJrZXlyZXF1ZXN0ZGF0YSI6W3sic2NoZW1lIjoiQVNZTU1FVFJJQ19XUkFQUEVEIiwia2V5ZGF0YSI6eyJrZXlwYWlyaWQiOiJyc2FLZXlwYWlySWQiLCJtZWNoYW5pc20iOiJSU0EiLCJwdWJsaWNrZXkiOiJUVWxIU2tGdlIwSkJUMWxYVXpZMk5ubEhjazU1U0Vkbk4yMHZaMlJuYjBKMVJGaHpLM0JOU1dWTGNVNVBkMlZKYW5selRYSjRTVTk0WjJ4TVMzRkVOa2xsV2pkd01VSmlVRVY0V0ZoS2EzTlpOR2RUVGtNM01FTmxRVUpFVVRkRmIzRmlXR1V3UkRsVVZFNU9MMHBOVW01SmNtVnVaWFU1TldOeE5ucGhNSGcxVjFkemEzWkxTRTh6Y21GVk9YZEZjQzlaUlZNM2JWVnphMmx5V2s1QkswWlVUVlJhT1RKalUxaDZXUzlyTUZFMlpHVTNRV2ROUWtGQlJUMD0ifX1dfQ==",
	    LARGE_CLEARTEXT = base64.parse(LARGE_CLEARTEXT_NOTHEX);

	var LISTOFOPERATIONS = [
	    {                    	
	    	name: "RSAEncryptDecryptHappyPath",
	    	algo: "RSAES-PKCS1-v1_5",
	        clearText: CLEARTEXT,
	        clearTextStr: CLEARTEXT_HEX,
	        result: "pass"
	    },
	    
	    {   //Encryption algo(RSAES-PKCS1-v1_5) does not match import key(RSASSA-PKCS1-v1_5)               	
	    	name: "RSAMismatchedEncryptionAlgoGenerateKey",
	    	algo: "RSAES-PKCS1-v1_5",
	        clearText: CLEARTEXT,
	        clearTextStr: CLEARTEXT_HEX,
	        encrypt: false
	    },
	    
	    {                    	
	    	name: "RSAEncryptLargeData",
	    	algo: "RSAES-PKCS1-v1_5",
	        clearText: LARGE_CLEARTEXT,
	        clearTextStr: LARGE_CLEARTEXT_NOTHEX,
	        encrypt: false
	    },
	    
	    {   //Corrupting data between encryption and decryption
	    	//Decryption succeeds but decrypted data will not match cleartext
	    	name: "RSAMangledEncryptionData",
	    	algo: "RSAES-PKCS1-v1_5",
	        clearText: CLEARTEXT,
	        clearTextStr: CLEARTEXT_HEX,
	        result: "pass"
	    },
	    
	    {                    	
	    	name: "RSAEncryptNullData",
	    	algo: "RSAES-PKCS1-v1_5",
	        clearText: CLEARTEXT,
	        clearTextStr: CLEARTEXT_HEX,
	        encrypt: false
	    },
	    
	    {                    	
	    	name: "RSAEncryptEmptyData",
	    	algo: "RSAES-PKCS1-v1_5",
	        clearText: CLEARTEXT,
	        clearTextStr: CLEARTEXT_HEX,
	        encrypt: true
	    },
	    
	    {   //Expect to fail since algo does not exist                 	
	    	name: "RSAEncryptInvalidAlgo",
	    	algo: "PKCS1-v1_5",
	        clearText: CLEARTEXT,
	        clearTextStr: CLEARTEXT_HEX,
	        encrypt: false
	    },
	    
	    {   //Expect to fail since its not an encryption algo                 	
	    	name: "RSAEncryptInvalidAlgoType",
	    	algo: "RSASSA_PKCS1_V1_5",
	        clearText: CLEARTEXT,
	        clearTextStr: CLEARTEXT_HEX,
	        encrypt: false
	    },
	    
	    {   //!!!!NOTE THIS TEST WILL NOT WORK WHEN REAL WEBCRYPTO COMES ALONG!!!!!!!                  	
	    	name: "RSAEncryptInvalidKeyHandle",
	    	//manipulation will happen later on in the code
	    	algo: "RSAES-PKCS1-v1_5",
	        clearText: CLEARTEXT,
	        clearTextStr: CLEARTEXT_HEX,
	        encrypt: false
	    },
	    
	    {   //Fails since the generated key only support decrypt           	
	    	name: "RSAEncryptUsingKeyWithInvalidUsage",
	    	algo: "RSAES-PKCS1-v1_5",
	        clearText: CLEARTEXT,
	        clearTextStr: CLEARTEXT_HEX,
	        encrypt: false
	    },
	    
	];
		
	function wrapperForTest(OPINDEX) {	
		it(LISTOFOPERATIONS[OPINDEX].name, function () {
			INDEXVALUE = LISTOFOPERATIONS[OPINDEX];
			
			var error = undefined,
				encrypted = undefined,
				decrypted = undefined,
			    pubKey = undefined,
				privKey = undefined;
			
			//Different modulus,publicExponent used than sign-verify rsa
			// equivalent to 257 
			//www.rsa.com/rsalabs/node.asp?id=2148
			var fermatF4 = new Uint8Array([0x00, 0x01]);
			var error;
			runs(function () {
				try {
					var genOp = undefined;
					if(INDEXVALUE.name == "RSAMismatchedEncryptionAlgoGenerateKey") {
						genOp = nfCrypto.generateKey({
							name: "RSASSA-PKCS1-v1_5",
							params: {
								//2048 bit RSA key can encrypt (n/8) - 11 bytes for PKCS
								//With given 2048 bit key it can encrypt 245 bytes
								modulusLength: 2048,
								publicExponent: fermatF4,
							}
						});
					} else if (INDEXVALUE.name == "RSAEncryptUsingKeyWithInvalidUsage")  {
						genOp = nfCrypto.generateKey({
							name: "RSAES-PKCS1-v1_5",
							params: {
								//2048 bit RSA key can encrypt (n/8) - 11 bytes for PKCS
								//With given 2048 bit key it can encrypt 245 bytes
								modulusLength: 2048,
								publicExponent: fermatF4,
							} },
							false,
							["decrypt"]);
					} else {
						genOp = nfCrypto.generateKey({
							name: "RSAES-PKCS1-v1_5",
							params: {
								//2048 bit RSA key can encrypt (n/8) - 11 bytes for PKCS
								//With given 2048 bit key it can encrypt 245 bytes
								modulusLength: 2048,
								publicExponent: fermatF4,
							}
						});
					}
					genOp.onerror = function (e) {
						error = "ERROR :: " + e.target.result;
					};
					genOp.oncomplete = function (e) {
						pubKey = e.target.result.publicKey;
						privKey = e.target.result.privateKey;
					};
				} catch(e) {
					error = "ERROR";
				}
			});

			waitsFor(function () {
				return pubKey || privKey || error;
			});

			runs(function () {
				expect(error).toBeUndefined();
				//Doing checks on keys to validate Public Key structure
				if(INDEXVALUE.name == "RSAMismatchedEncryptionAlgoGenerateKey") {
					expect(pubKey.algorithm.name).toEqual("RSASSA-PKCS1-v1_5");
				}
				else  {
					expect(pubKey.algorithm.name).toEqual("RSAES-PKCS1-v1_5");
				}
				//since all pub keys are extractable
				expect(pubKey.extractable).toBeTruthy();
				if (INDEXVALUE.name == "RSAEncryptUsingKeyWithInvalidUsage") {
					expect(pubKey.keyUsage.length).toEqual(1);
				} else {
					expect(pubKey.keyUsage.length).toEqual(0);
				}
				//TODO: Re-enable this check when we know what default values should be
				//expect(pubKey.keyUsage[0]).toEqual("verify");
				expect(pubKey.keyUsage).not.toBeNull();
				expect(pubKey.type).toEqual("public");
				//Handle is how C++ correlates keys with JS
				//0 implies invalid key
				expect(pubKey.handle).not.toEqual(0);

				//Doing checks on keys to validate Private Key structure
				if(INDEXVALUE.name == "RSAMismatchedEncryptionAlgoGenerateKey") {
					expect(pubKey.algorithm.name).toEqual("RSASSA-PKCS1-v1_5");
				}
				else  {
					expect(privKey.algorithm.name).toEqual("RSAES-PKCS1-v1_5");
				}
				expect(privKey.extractable).toBeFalsy();
				if (INDEXVALUE.name == "RSAEncryptUsingKeyWithInvalidUsage") {
					expect(privKey.keyUsage.length).toEqual(1);
				} else {
					expect(privKey.keyUsage.length).toEqual(0);
				}
				//TODO: Re-enable this check when we know what default values should be
				//expect(privKey.keyUsage[0]).toEqual("sign");
				expect(privKey.type).toEqual("private");
				expect(privKey.handle).not.toEqual(0);
				expect(privKey.handle).not.toEqual(pubKey.handle);
			});
			
			runs(function () {
				try {
					//Test manipulations
					if(INDEXVALUE.name == "RSAEncryptNullData") {
						INDEXVALUE.clearText = null;
					} else if(INDEXVALUE.name == "RSAEncryptEmptyData") {
						INDEXVALUE.clearText = new Uint8Array([]);
					} else if(INDEXVALUE.name == "RSAEncryptInvalidKeyHandle") {
						pubKey.handle = 0;
					}
					// encrypt clearText with the public key
					var encryptOp = nfCrypto.encrypt(INDEXVALUE.algo, pubKey, INDEXVALUE.clearText);
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

			waitsFor(function () {
				return encrypted || error;
			});

			runs(function () {
				if(INDEXVALUE.encrypt == false) {
					expect(error).toBeDefined();
					expect(encrypted).toBeUndefined();
				} else {
					expect(error).toBeUndefined();
					expect(encrypted).not.toBeNull();
					expect(base16.stringify(encrypted)).not.toBe(INDEXVALUE.clearText);
				}
			});

			if(INDEXVALUE.encrypt != false) {
				runs(function () {
					try {
						error = undefined;
						if(INDEXVALUE.name == "RSAMangledEncryptionData") {
							encrypted[5] = encrypted[5] ^ 0xFF;
						}
						var encryptOp = nfCrypto.decrypt(INDEXVALUE.algo, privKey, encrypted);
						encryptOp.onerror = function (e) {
							error = "ERROR";
						};
						encryptOp.oncomplete = function (e) {
							decrypted = e.target.result;
						};
					} catch(e) {
						error = "ERROR";
					}
				});

				waitsFor(function () {
					return decrypted || error;
				});

				runs(function () {
					if(INDEXVALUE.name == "RSAMangledEncryptionData") {
						expect(error).toBeDefined();
						expect(decrypted).toBeUndefined();
					} else if (INDEXVALUE.name == "RSAEncryptEmptyData") {
                        expect(error).toBeUndefined();
                        expect(decrypted).toBeDefined();
					} else {
						expect(error).toBeUndefined();
						expect(decrypted).toBeDefined();
						expect(base16.stringify(decrypted)).toEqual(INDEXVALUE.clearTextStr);
					}
				});
			}//if(INDEXVALUE.encrypt)
	
		});//it
	}//function wrapperForTest
for(OPINDEX = 0; OPINDEX < LISTOFOPERATIONS.length; OPINDEX++) {	
	wrapperForTest(OPINDEX);
}
});//describe("encryptrsa")

describe("decryptrsa", function () {

	var OPINDEX = 0;
	var INDEXVALUE = 0;
	var SHORT_IV = base16.parse("ddb3ba695a2e6f58");
	var CLEARTEXT_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
	var CLEARTEXT = base16.parse(CLEARTEXT_HEX);
	var LARGE_CLEARTEXT_NOTHEX = "eyJtZXNzYWdlaWQiOjQ2MDQwODM3Niwibm9ucmVwbGF5YWJsZSI6ZmFsc2UsInJlbmV3YWJsZSI6dHJ1ZSwiY2FwYWJpbGl0aWVzIjp7ImNvbXByZXNzaW9uYWxnb3MiOlsiTFpXIl19LCJrZXlyZXF1ZXN0ZGF0YSI6W3sic2NoZW1lIjoiQVNZTU1FVFJJQ19XUkFQUEVEIiwia2V5ZGF0YSI6eyJrZXlwYWlyaWQiOiJyc2FLZXlwYWlySWQiLCJtZWNoYW5pc20iOiJSU0EiLCJwdWJsaWNrZXkiOiJUVWxIU2tGdlIwSkJUMWxYVXpZMk5ubEhjazU1U0Vkbk4yMHZaMlJuYjBKMVJGaHpLM0JOU1dWTGNVNVBkMlZKYW5selRYSjRTVTk0WjJ4TVMzRkVOa2xsV2pkd01VSmlVRVY0V0ZoS2EzTlpOR2RUVGtNM01FTmxRVUpFVVRkRmIzRmlXR1V3UkRsVVZFNU9MMHBOVW01SmNtVnVaWFU1TldOeE5ucGhNSGcxVjFkemEzWkxTRTh6Y21GVk9YZEZjQzlaUlZNM2JWVnphMmx5V2s1QkswWlVUVlJhT1RKalUxaDZXUzlyTUZFMlpHVTNRV2ROUWtGQlJUMD0ifX1dfQ==",
	    LARGE_CLEARTEXT = base64.parse(LARGE_CLEARTEXT_NOTHEX);

	var LISTOFOPERATIONS = [
	    {                    	
	    	name: "RSADecryptNullData",
	    	algo: "RSAES-PKCS1-v1_5",
	        clearText: CLEARTEXT,
	        clearTextStr: CLEARTEXT_HEX,
	        decrypt: false
	    },
	    
	    {                    	
	    	name: "RSADecryptEmptyData",
	    	algo: "RSAES-PKCS1-v1_5",
	        clearText: CLEARTEXT,
	        clearTextStr: CLEARTEXT_HEX,
	        decrypt: false
	    },
	    
	    {   //Expect to fail since algo does not exist                 	
	    	name: "RSADecryptInvalidAlgo",
	    	algo: "PKCS1-v1_5",
	        clearText: CLEARTEXT,
	        clearTextStr: CLEARTEXT_HEX,
	        decrypt: false
	    },
	    
	    {   //Expect to fail since its not a decryption algo                 	
	    	name: "RSADecryptInvalidAlgoType",
	    	algo: "RSASSA_PKCS1_V1_5",
	        clearText: CLEARTEXT,
	        clearTextStr: CLEARTEXT_HEX,
	        decrypt: false
	    },
	   
	    {   //!!!!NOTE THIS TEST WILL NOT WORK WHEN REAL WEBCRYPTO COMES ALONG!!!!!!!                  	
	    	name: "RSADecryptInvalidKeyHandle",
	    	//manipulation will happen later on in the code
	    	algo: "RSAES-PKCS1-v1_5",
	        clearText: CLEARTEXT,
	        clearTextStr: CLEARTEXT_HEX,
	        decrypt: false
	    },
	    
	    {   //Fails since the generated key only supports encrypt              	
	    	name: "RSADecryptUsingKeyWithInvalidUsage",
	    	algo: "RSAES-PKCS1-v1_5",
	        clearText: CLEARTEXT,
	        clearTextStr: CLEARTEXT_HEX,
	        decrypt: false
	    },
	];
		
	function wrapperForTest(OPINDEX) {	
		it(LISTOFOPERATIONS[OPINDEX].name, function () {
			INDEXVALUE = LISTOFOPERATIONS[OPINDEX];
			
			var error = undefined,
				encrypted = undefined,
				decrypted = undefined,
			    pubKey = undefined,
				privKey = undefined;
			
			//Different modulus,publicExponent used than sign-verify rsa
			// equivalent to 257 
			//www.rsa.com/rsalabs/node.asp?id=2148
			var fermatF4 = new Uint8Array([0x00, 0x01]);
			runs(function () {
				try {
					var genOp = undefined;
					if(INDEXVALUE.name == "RSADecryptUsingKeyWithInvalidUsage") {
						genOp = nfCrypto.generateKey({
							name: "RSAES-PKCS1-v1_5",
					 	    params: {
					 	    	//2048 bit RSA key can encrypt (n/8) - 11 bytes for PKCS
					 	    	//With given 2048 bit key it can encrypt 245 bytes
					 	    	modulusLength: 2048,
					 	    	publicExponent: fermatF4,
						    } },
						    false,
						    ["encrypt"]);
					} else {
						genOp = nfCrypto.generateKey({
							name: "RSAES-PKCS1-v1_5",
							params: {
								//2048 bit RSA key can encrypt (n/8) - 11 bytes for PKCS
								//With given 2048 bit key it can encrypt 245 bytes
								modulusLength: 2048,
								publicExponent: fermatF4,
							},
						});
					}
					genOp.onerror = function (e) {
						error = "ERROR :: " + e.target.result;
					};
					genOp.oncomplete = function (e) {
						pubKey = e.target.result.publicKey;
						privKey = e.target.result.privateKey;
					};
				} catch(e) {
					error = "ERROR";
				}
			});

			waitsFor(function () {
				return pubKey || privKey || error;
			});

			runs(function () {
				expect(error).toBeUndefined();
				//Doing checks on keys to validate Public Key structure
				expect(pubKey.algorithm.name).toEqual("RSAES-PKCS1-v1_5");
				//since all pub keys are extractable
				expect(pubKey.extractable).toBeTruthy();
				if(INDEXVALUE.name == "RSADecryptUsingKeyWithInvalidUsage") {	
					expect(pubKey.keyUsage.length).toEqual(1);
				} else {
					expect(pubKey.keyUsage.length).toEqual(0);
				}
				//TODO: Re-enable this check when we know what default values should be
				//expect(pubKey.keyUsage[0]).toEqual("verify");
				expect(pubKey.keyUsage).not.toBeNull();
				expect(pubKey.type).toEqual("public");
				//Handle is how C++ correlates keys with JS
				//0 implies invalid key
				expect(pubKey.handle).not.toEqual(0);

				//Doing checks on keys to validate Private Key structure
				expect(privKey.algorithm.name).toEqual("RSAES-PKCS1-v1_5");
				expect(privKey.extractable).toBeFalsy();
				if(INDEXVALUE.name == "RSADecryptUsingKeyWithInvalidUsage") {	
					expect(privKey.keyUsage.length).toEqual(1);
				} else {
					expect(privKey.keyUsage.length).toEqual(0);
				}
				
				//TODO: Re-enable this check when we know what default values should be
				//expect(privKey.keyUsage[0]).toEqual("sign");
				expect(privKey.type).toEqual("private");
				expect(privKey.handle).not.toEqual(0);
				expect(privKey.handle).not.toEqual(pubKey.handle);
			});
			
			runs(function () {
				try {
					// encrypt clearText with the public key
					var encryptOp = nfCrypto.encrypt("RSAES-PKCS1-v1_5", pubKey, CLEARTEXT);
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

			waitsFor(function () {
				return encrypted || error;
			});

			runs(function () {
				expect(error).toBeUndefined();
				expect(encrypted).not.toBeNull();
				expect(base16.stringify(encrypted)).not.toBe(CLEARTEXT);
			});

			runs(function () {
				try {
					error = undefined;
					//Test manipulations
					if(INDEXVALUE.name == "RSADecryptNullData") {
						encrypted = null;
					} else if(INDEXVALUE.name == "RSADecryptEmptyData") {
						encrypted = new Uint8Array([]);
					} else if(INDEXVALUE.name == "RSADecryptInvalidKeyHandle") {
						privKey.handle = 0;
					}
					var encryptOp = nfCrypto.decrypt(INDEXVALUE.algo, privKey, encrypted);
					encryptOp.onerror = function (e) {
						error = "ERROR";
					};
					encryptOp.oncomplete = function (e) {
						decrypted = e.target.result;
					};
				} catch(e) {
					error = "ERROR";
				}
			});

			waitsFor(function () {
				return decrypted || error;
			});

			runs(function () {
				//Since all the tests are negative error is always defined
				expect(error).toBeDefined();
				expect(decrypted).toBeUndefined();
			});
	
		});//it
	}//function wrapperForTest
for(OPINDEX = 0; OPINDEX < LISTOFOPERATIONS.length; OPINDEX++) {	
	wrapperForTest(OPINDEX);
}
});//describe("decryptrsa")

