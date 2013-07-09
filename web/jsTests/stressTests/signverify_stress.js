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

describe("SignRSA", function () {

	//Globals
	var OPINDEX = 0;
	
	function wrapperForTest(OPINDEX) {	

		it("SignVerifyRSAHappyPath", function () {
			var error = undefined,
				signature = undefined,
				verified = undefined,
				pubKey = undefined,
				privKey = undefined,
				privkeyData = undefined,
				pubkeyData = undefined;
			
			console.log("SignVerifyRSAHappyPath called this many times " + OPINDEX);
			var output = "SignVerifyRSAHappyPath called this many times: " + OPINDEX + "^";
			
		
			function randomBytes(buffer) {
				for (var i = 0; i < buffer.length; ++i)
					//Returns a rand value from 0 to 0xFF 
					buffer[i] = Math.floor(Math.random() * (0xFF - 0 + 1)) + 0;
				   //console.log("The contexts of randBuffer is " + buffer[i]);
			}
		
			//Generating a random uint8 array of variable length from 1 to 100
			var randBuffer = new Uint8Array(Math.floor((Math.random()*100)+1));
			console.log("The length of randBuffer is " + randBuffer.length);
			output += "RandBuffer Length: " + randBuffer.length + "^";
			randomBytes(randBuffer);

			//First generate the keys before each test
			var fermatF4 = new Uint8Array([0x01, 0x00, 0x01]);
			var error;

			runs(function () {
				var genOp = nfCrypto.generateKey({
					name: "RSASSA-PKCS1-v1_5",
					params: {
						modulusLength: 512,
						publicExponent: fermatF4,
					} }, true);
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
				expect(pubKey.handle).not.toEqual(0);
				expect(privKey.handle).not.toEqual(0);
				
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
			

			// sign data with the private key
			runs(function () {
				error = undefined;
				var signOp = nfCrypto.sign({name: "RSASSA-PKCS1-v1_5", params: { hash: "SHA-256" }}, privKey, randBuffer);
				signOp.onerror = function (e) {
					error = "ERROR :: " + e.target.result;
				};
				signOp.oncomplete = function (e) {
					signature = e.target.result;
				};
			});

			waitsFor(function () {
				return signature || error;
			});

			runs(function () {
				expect(error).toBeUndefined();
				expect(signature).toBeDefined();
				console.log("The randomStr(in hex) before signature " + abv2hex(randBuffer));
				console.log("The SHA-256 signature " + abv2hex(signature));
				output += "RandomBuffer: " + abv2hex(randBuffer) + "^";
				output += "SignOutput: " + abv2hex(signature) + "^";
			});

			// verify data with the public key
			runs(function () {
				error = undefined;
				var verifyOp = nfCrypto.verify({name: "RSASSA-PKCS1-v1_5", params: { hash: "SHA-256" }}, pubKey, signature, randBuffer);
				verifyOp.onerror = function (e) {
					error = "ERROR :: " + e.target.result;
				};
				verifyOp.oncomplete = function (e) {
					verified = e.target.result;
				};
			});

			waitsFor(function () {
				return verified || error;
			});

			runs(function () {
				expect(error).toBeUndefined();
				expect(verified).toBe(true);
				var correctStrings = output.split("^");
				var response = $.ajax({
					type: "GET",
			        url: "save_contents.php?filename="+"SignVerifyRSA"+"&contents="+correctStrings,
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
});//describe("SignRSA")		

describe("SignHMAC", function () {

	//Globals
	var DATA = hex2abv("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
	var OPINDEX = 0;

	function wrapperForTest(OPINDEX) {	

		it("SignVerifyHMACHappyPath", function () {
			var error = undefined,
			signature = undefined,
			verified = undefined,
			importKey = undefined,
			importkeyData = undefined;

			var op, result, error, complete;
			
			console.log("SignVerifyHMACHappyPath called this many times " + OPINDEX);
			var output = "SignVerifyHMACHappyPath called this many times: " + OPINDEX + "^";
			
		
			function randomBytes(buffer) {
				for (var i = 0; i < buffer.length; ++i)
					buffer[i] = Math.floor(Math.random() * (0xFF - 0 + 1)) + 0;
			}
		
			//Generating a random uint8 array of variable length from 1 to 100
			var randBuffer = new Uint8Array(Math.floor((Math.random()*100)+1));
			console.log("The length of randBuffer is " + randBuffer.length);
			output += "RandBuffer length: " + randBuffer.length + "^";
			randomBytes(randBuffer);
			
			var keyData = new Uint8Array([
			                              0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
			                              0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
			                              ]);
			//First import the key to sign/verify with
			runs(function () {
				error = undefined;
				var op = nfCrypto.importKey("raw", keyData, { name: "HMAC", params: { hash: "SHA-256" } }, true, ["sign", "verify"]);
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
				expect(error).toBeUndefined();
				expect(importKey).toBeDefined();
			});
			

			//EXPORT KEY STUFF
			runs(function () {
				error = undefined;
				var op = nfCrypto.exportKey("raw", importKey);
				op.onerror = function (e) {
					error = "ERROR";
				};
				op.oncomplete = function (e) {
					importkeyData = e.target.result;
				};
			});

			waitsFor(function () {
				return importkeyData || error;
			});
           
			runs(function () {
				expect(error).toBeUndefined();
				expect(importkeyData).toBeDefined();
				console.log("The signing key is " + abv2hex(importkeyData));
				output += "SigningKey: " + abv2hex(importkeyData) + "^";
			});
			//END OF EXPORT KEY STUFF

			runs(function () {
				error = undefined;

				var signOp = nfCrypto.sign({ name: "HMAC", params: { hash: "SHA-256" }}, importKey, randBuffer);
				signOp.onerror = function (e) {
					error = "ERROR";
				};
				signOp.oncomplete = function (e) {
					signature = e.target.result;
				};
			});

			waitsFor(function () {
				return signature || error;
			});

			runs(function () {
				expect(error).toBeUndefined();
				expect(signature).toBeDefined();
				console.log("The randomStr(in hex) before signature " + abv2hex(randBuffer));
				console.log("The SHA-256 signature " + abv2hex(signature));
				output += "RandomBuffer: " + abv2hex(randBuffer) + "^";
				output += "Signature: " + abv2hex(signature) + "^";
			});

			runs(function () {
				error = undefined;
				var signOp = nfCrypto.verify({ name: "HMAC", params: { hash: "SHA-256" }}, importKey, signature, randBuffer);
				signOp.onerror = function (e) {
					error = "ERROR";
				};
				signOp.oncomplete = function (e) {
					verified = e.target.result;
				};
			});

			waitsFor(function () {
				return verified !== undefined || error;
			});

			runs(function () {
				expect(error).toBeUndefined();
				expect(verified).toBe(true);
				var correctStrings = output.split("^");
				var response = $.ajax({
					type: "GET",
			        url: "save_contents.php?filename="+"SignVerifyHMAC"+"&contents="+correctStrings,
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
});//describe("SignHMAC")

	