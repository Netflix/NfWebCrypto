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
	var ORG_IV = "562e17996d093d28ddb3ba695a2e6f58";
	var IV = base16.parse(ORG_IV);
	
		
	function wrapperForTest(OPINDEX) {	
		it("AESEncryptDecryptHappyPath", function () {

			var error = undefined;
			var encrypted = undefined;
			var decrypted = undefined;
			var importedKey = undefined;
			var pubkeyData = undefined;

			console.log("AESEncryptDecryptHappyPath called this many times " + OPINDEX);
			var output = "AESEncryptDecryptHappyPath called this many times: " + OPINDEX + "^";
			
			function randomBytes(buffer) {
				for (var i = 0; i < buffer.length; ++i)
					buffer[i] = Math.floor(Math.random() * (0xFF - 0 + 1)) + 0;
			}
		
			//Generating a random uint8 array of variable length from 1 to 100
			var randBuffer = new Uint8Array(Math.floor((Math.random()*100)+1));
			console.log("The length of randBuffer is " + randBuffer.length);
			output += "RandBuffer length:" + randBuffer.length + "^";
			randomBytes(randBuffer);
			
			runs(function () {
				var op = nfCrypto.importKey(
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
			});

			waitsFor(function () {
				return importedKey || error;
			});

			runs(function () {
				expect(error).toBeUndefined();
				expect(importedKey).toBeDefined();
			});
			
			runs(function () {
				error = undefined;
				var encryptOp = nfCrypto.encrypt({name: "AES-CBC", params: { iv: IV }}, importedKey, randBuffer);
				encryptOp.onerror = function (e) {
					error = "ERROR";
				};
				encryptOp.oncomplete = function (e) {
					encrypted = e.target.result;
				};
			});

			waitsFor(function () {
				return encrypted || error;
			});

			runs(function () {
				expect(error).toBeUndefined();
				expect(encrypted).toBeDefined();
				expect(encrypted).not.toBeNull();
				console.log("The cleartext data is " + abv2hex(randBuffer));
				console.log("The encrypted data is " + abv2hex(encrypted));
				expect(encrypted).not.toBe(randBuffer);
				output += "Cleartext: " + abv2hex(randBuffer) + "^";
				output += "AESCiphertext: " + abv2hex(encrypted) + "^";
			});
			
			//One time EXPORT KEY STUFF
			runs(function () {
				error = undefined;
				var op = nfCrypto.exportKey("raw", importedKey);
				op.onerror = function (e) {
					error = "ERROR";
				};
				op.oncomplete = function (e) {
					pubkeyData = e.target.result;
				};
			});

			waitsFor(function () {
				return pubkeyData || error;
			});
           
			runs(function () {
				expect(error).toBeUndefined();
				expect(pubkeyData).toBeDefined();
				//console.log("The encryption key is " + abv2hex(pubkeyData));
				output += "AESEncryptionKey: " + abv2hex(pubkeyData) + "^";
			});
			//END of: One time EXPORT KEY STUFF
			
			runs(function () {
				error = undefined;
				var decryptOp = nfCrypto.decrypt({name: "AES-CBC", params: { iv: IV }}, importedKey, encrypted);
				decryptOp.onerror = function (e) {
					error = "ERROR";
				};
				decryptOp.oncomplete = function (e) {
					decrypted = e.target.result;
				};
			});

			waitsFor(function () {
				return decrypted || error;
			});

			runs(function () {
				expect(error).toBeUndefined();
				expect(decrypted).toBeDefined();
				expect(decrypted).toEqual(randBuffer);
				
				var correctStrings = output.split("^");
				var response = $.ajax({
					type: "GET",
			        url: "save_contents.php?filename="+"AESEncryptDecrypt"+"&contents="+correctStrings,
			        async: false,
			        success: function(text, status) {
			        	console.log(" Was able to post successfully " + text);
			        },
			        error: function (xhr, ajaxOptions, thrownError) {
			        	console.log("Was NOT able to post successfully: xhr status " +  xhr.status + " error " + thrownError);
			        }
			    });
			});
		 
		});//it
	}//function wrapperForTest
for(OPINDEX = 0; OPINDEX < 2; OPINDEX++) {	
	wrapperForTest(OPINDEX);
}
});//describe("EncryptAES")


describe("encryptrsa", function () {

	var OPINDEX = 0;
	
	function wrapperForTest(OPINDEX) {	
		it("RSAEncryptDecryptHappyPath", function () {
			var error = undefined,
				encrypted = undefined,
				decrypted = undefined,
			    pubKey = undefined,
				privKey = undefined,
				privkeyData = undefined,
				pubkeyData = undefined;
			
			console.log("RSAEncryptDecryptHappyPath called this many times " + OPINDEX);
			var output = "RSAEncryptDecryptHappyPath called this many times: " + OPINDEX + "^";
			function randomBytes(buffer) {
				for (var i = 0; i < buffer.length; ++i)
					buffer[i] = Math.floor(Math.random() * (0xFF - 0 + 1)) + 0;
			}
		
			//Generating a random uint8 array of variable length from 1 to 100
			var randBuffer = new Uint8Array(Math.floor((Math.random()*100)+1));
			console.log("The length of randBuffer is " + randBuffer.length);
			output += "RandBuffer length:" + randBuffer.length + "^";
			randomBytes(randBuffer);
				
			//Different modulus,publicExponent used than sign-verify rsa
			// equivalent to 257 
			//www.rsa.com/rsalabs/node.asp?id=2148
			var fermatF4 = new Uint8Array([0x00, 0x01]);
			var error;
			runs(function () {
					var genOp = nfCrypto.generateKey({ name: "RSAES-PKCS1-v1_5", params: {
							//2048 bit RSA key can encrypt (n/8) - 11 bytes for PKCS
							//With given 2048 bit key it can encrypt 245 bytes
							modulusLength: 2048,
							publicExponent: fermatF4 } }, true);
					genOp.onerror = function (e) {
						error = "ERROR :: " + e.target.result;
					};
					genOp.oncomplete = function (e) {
						pubKey = e.target.result.publicKey;
						privKey = e.target.result.privateKey;
					};
			});

			waitsFor(function () {
				return pubKey || privKey || error;
			});

			runs(function () {
				expect(error).toBeUndefined();
				expect(pubKey.algorithm.name).not.toBeNull();
				expect(privKey.algorithm.name).not.toBeNull();
			});
			
			//EXPORT KEY STUFF
			runs(function () {
				error = undefined;
				var op = nfCrypto.exportKey("spki", pubKey);
				op.onerror = function (e) {
					error = "ERROR";
				};
				op.oncomplete = function (e) {
					pubkeyData = e.target.result;
				};
			});

			waitsFor(function () {
				return pubkeyData || error;
			});
           
			runs(function () {
				expect(error).toBeUndefined();
				expect(pubkeyData).not.toBeUndefined();
				console.log("The RSA public key is " + b64encode(pubkeyData));
				output += "RSAPublicKey: " + b64encode(pubkeyData) + "^";
			});
			
			runs(function () {
				error = undefined;
				var op = nfCrypto.exportKey("pkcs8", privKey);
				op.onerror = function (e) {
					error = "ERROR";
				};
				op.oncomplete = function (e) {
					privkeyData = e.target.result;
				};
			});

			waitsFor(function () {
				return privkeyData || error;
			});
           
			runs(function () {
				expect(error).toBeUndefined();
				expect(privkeyData).not.toBeUndefined();
				console.log("The RSA private key is " + b64encode(privkeyData));
				output += "RSAPrivateKey: " + b64encode(privkeyData) + "^";
			});
			//END OF EXPORT KEY STUFF
			
			runs(function () {
				// encrypt clearText with the public key
				var encryptOp = nfCrypto.encrypt("RSAES-PKCS1-v1_5", pubKey, randBuffer);
				encryptOp.onerror = function (e) {
					error = "ERROR";
				};
				encryptOp.oncomplete = function (e) {
					encrypted = e.target.result;
				};
			});

			waitsFor(function () {
				return encrypted || error;
			});

			runs(function () {
				expect(error).toBeUndefined();
				expect(encrypted).not.toBeNull();
				console.log("The cleartext data is " + abv2hex(randBuffer));
				console.log("The encrypted data is " + abv2hex(encrypted));
				expect(base16.stringify(encrypted)).not.toEqual(randBuffer);
				output += "Cleartext: " + abv2hex(randBuffer) + "^";
				output += "RSACiphertext: " + abv2hex(encrypted) + "^";
				var correctStrings = output.split("^");
				var response = $.ajax({
					type: "GET",
			        url: "save_contents.php?filename="+"RSAEncryptDecrypt"+"&contents="+correctStrings,
			        async: false,
			        success: function(text, status) {
			        	console.log(" Was able to post successfully " + text);
			        },
			        error: function (xhr, ajaxOptions, thrownError) {
			        	console.log("Was NOT able to post successfully: xhr status " +  xhr.status + " error " + thrownError);
			        }
			    });
			});

			runs(function () {
				error = undefined;
				var encryptOp = nfCrypto.decrypt("RSAES-PKCS1-v1_5", privKey, encrypted);
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
				expect(decrypted).toEqual(randBuffer);
			});

		});//it
	}//function wrapperForTest
for(OPINDEX = 0; OPINDEX < 2; OPINDEX++) {	
	wrapperForTest(OPINDEX);
}
});//describe("encryptrsa")
	    	
