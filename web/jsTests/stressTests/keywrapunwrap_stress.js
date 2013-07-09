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

describe("keywrapunwraprsa", function () {

	var OPINDEX = 0;
	//For wrap/unwrap 1. Generate the wrapping keys(wrappor)
	//2. Generate the wrapee key
	//3. Wrap/unwrap the keys
	//The algos supported for wrapping/generating keys are RSA-OAEP, AES-KW
	//Algos supported for wrapee key are: any symmetric key(AES, HMAC), asymmetric public key RSA, DH
	function wrapperForTest(OPINDEX) {	
		it("KeyWrapUnwrapRSAStress", function () {
			
			var error = undefined,
			keyToWrap = undefined,
			unwrappedKey = undefined,
			exportKeyData = undefined,
			jweData = undefined,
			pubKey = undefined,
			privKey = undefined,
			pubkeyData = undefined,
			privkeyData = undefined,
			wrapeeData = undefined;
			
			console.log("KeyWrapUnwrapRSAStress called this many times " + OPINDEX);
			var output = "KeyWrapUnwrapRSAStress called this many times: " + OPINDEX + "^";
			
			function randomBytes(buffer) {
				for (var i = 0; i < buffer.length; ++i) {
					//Generating random hex content from 0x00 to 0xFF
					buffer[i] = (Math.floor(Math.random() * (0xFF - 0 + 1)) + 0);
					//console.log("Output of the buffer is " + buffer[i])
				}
			}
		
			var validWrapeeLen = new Array(16, 32, 48, 64);
			//Generating a random uint8 array of variable length from allowed wrapee lengths
			var randBuffer = new Uint8Array(validWrapeeLen[Math.floor(Math.random() * validWrapeeLen.length)]);
			console.log("The length of randBuffer for wrapee key is " + randBuffer.length);
			output += "WrapeeKeyLength: " + randBuffer.length + "^";
			randomBytes(randBuffer);


			// generate RSA pub/priv key pair for wrapping with
			runs(function () {
				var genOp = nfCrypto.generateKey({name: "RSA-OAEP", params: { modulusLength: 1024, publicExponent: new Uint8Array([0x01, 0x00, 0x01])}},
						true,
						["wrap", "unwrap"]
				);
				genOp.onerror = function (e) {
					error = "ERROR";
				};
				genOp.oncomplete = function (e) {
					pubKey  = e.target.result.publicKey;
					privKey = e.target.result.privateKey;
				};
			});
			waitsFor(function () {
				return (pubKey && privKey) || error;
			});
			runs(function () {
				expect(error).toBeUndefined();
				expect(pubKey).toBeDefined();
				expect(privKey).toBeDefined();
			});

			//Export RSA key pair(wrappor keys)
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
				console.log("The RSA public key(wrappor) is " + b64encode(pubkeyData));
				output += "WrapporPublicKey: " + b64encode(pubkeyData) + "^";
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
				console.log("The RSA private key(wrappor) is " + b64encode(privkeyData));
				output += "WrapporPrivateKey: " + b64encode(privkeyData) + "^";
			});
			//END Export RSA key pair(wrappor keys)

			// create the key to be wrapped
			runs(function () {
				error = undefined;
				var op = undefined;
				op = nfCrypto.importKey("raw", randBuffer, { name: "AES-CBC" }, true);
				op.onerror = function (e) {
					error = "ERROR";
				};
				op.oncomplete = function (e) {
					keyToWrap = e.target.result;
				};
			});
			waitsFor(function () {
				return keyToWrap || error;
			});
			runs(function () {
				expect(error).toBeUndefined();
				expect(keyToWrap).toBeDefined();
			});

			//EXPORT Wrapee key
			runs(function () {
				error = undefined;
				var op = nfCrypto.exportKey("raw", keyToWrap);
				op.onerror = function (e) {
					error = "ERROR";
				};
				op.oncomplete = function (e) {
					wrapeeData = e.target.result;
				};
			});

			waitsFor(function () {
				return wrapeeData || error;
			});

			runs(function () {
				expect(error).toBeUndefined();
				expect(wrapeeData).toBeDefined();
				console.log("The wrapee key is " + b64encode(wrapeeData));
				output += "WrapeeKey: " + b64encode(wrapeeData) + "^";
			});
			//END OF EXPORT Wrapee key

			// wrap the wrap-ee key using the public wrapping key
			runs(function () {
				error = undefined;
				var op = undefined;
				op = nfCrypto.wrapKey(keyToWrap, pubKey, { name: "RSA-OAEP" });		

				op.onerror = function (e) {
					error = "ERROR";
				};
				op.oncomplete = function (e) {
					jweData = e.target.result;
				};
			});
			waitsFor(function () {
				return jweData || error;
			});
			runs(function () {
				expect(error).toBeUndefined();
				expect(jweData).toBeDefined();
				console.log("The output of wrap is " + abv2hex(jweData));
				output += "WrapOutput: " + abv2hex(jweData) + "^";
			});


			// now unwrap the jwe data received from wrapKey, using the private wrapping key
			// this gives us a new key in the key store
			runs(function () {
				error = undefined;
				var op = undefined;		
				op = nfCrypto.unwrapKey(jweData, null, privKey, true);

				op.onerror = function (e) {
					error = "ERROR";
				};
				op.oncomplete = function (e) {
					unwrappedKey = e.target.result;
				};
			});
			waitsFor(function () {
				return unwrappedKey || error;
			});
			runs(function () {
				expect(error).toBeUndefined();
				expect(unwrappedKey).toBeDefined();	
			});

			// finally, export this new key and verify the raw key data
			runs(function () {
				error = undefined;
				var op = nfCrypto.exportKey("raw", unwrappedKey);
				op.onerror = function (e) {
					error = "ERROR";
				};
				op.oncomplete = function (e) {
					exportKeyData = e.target.result;
				};
			});
			waitsFor(function () {
				return exportKeyData || error;
			});
			runs(function () {
				expect(error).toBeUndefined();
				expect(exportKeyData).toBeDefined();
				expect(exportKeyData).toEqual(wrapeeData);	
				output += "UnwrapOutput: " + abv2hex(exportKeyData) + "^";
				var correctStrings = output.split("^");
				var response = $.ajax({
					type: "GET",
			        url: "save_contents.php?filename="+"RSAKeyWrapUnwrap"+"&contents="+correctStrings,
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
});//describe("keywrapunwraprsa")

describe("keywrapunwrapaes", function () {

	var OPINDEX = 0;
	//For wrap/unwrap 1. Generate the wrapping keys(wrappor)
	//2. Generate the wrapee key
	//3. Wrap/unwrap the keys
	//The algos supported for wrapping/generating keys are RSA-OAEP, AES-KW
	//Algos supported for wrapee key are: any symmetric key(AES, HMAC), asymmetric public key RSA, DH
	function wrapperForTest(OPINDEX) {	
		it("WrapUnwrapAES_KWStress", function () {
			var error = undefined,
			wrapeeKey = undefined,
			wrapeeKeyData = undefined,
			wrapporKey = undefined,
			wrappedKeyJwe = undefined,
			unwrappedWrappeeKey = undefined,
			unwrappedWrappeeKeyData= undefined,
			wrapporkeyData = undefined;

			console.log("WrapUnwrapAES_KWStress called this many times " + OPINDEX);
			var output = "WrapUnwrapAES_KWStress called this many times: " + OPINDEX + "^";

			// generate a key to be wrapped
			runs(function () {
				error = undefined;
				//Permissible SHA256, SHA384, SHA512
				var validSHA = new Array("SHA-256", "SHA-384", "SHA-512");
				var specificSHA = validSHA[Math.floor(Math.random() * validSHA.length)];
				var op = nfCrypto.generateKey({ name: "HMAC", params: { hash: {name: specificSHA} } }, true);
				console.log("The SHA being used is " + specificSHA);
				output += "WrapeeAlgo: " + specificSHA + "^";
				op.onerror = function (e) {
					error = "ERROR";
				};
				op.oncomplete = function (e) {
					wrapeeKey = e.target.result;
				};
			});
			waitsFor(function () {
				return wrapeeKey || error;
			});
			runs(function () {
				expect(error).toBeUndefined();
				expect(wrapeeKey).toBeDefined();
			});

			// export the wrap-ee key data for later checking only if extractable is set to true
			runs(function () {
				error = undefined;
				var op = nfCrypto.exportKey("raw", wrapeeKey);
				op.onerror = function (e) {
					error = "ERROR";
				};
				op.oncomplete = function (e) {
					wrapeeKeyData = e.target.result;
				};
			});
			waitsFor(function () {
				return wrapeeKeyData || error;
			});
			runs(function () {
				expect(error).toBeUndefined();
				expect(wrapeeKeyData).toBeDefined();
				console.log("The HMAC wrapee key is " + abv2hex(wrapeeKeyData));
				output += "WrapeeKey: " + abv2hex(wrapeeKeyData) + "^";
			});

			// generate a wrapping key
			runs(function () {
				error = undefined;
				//Permissible key lengths 128, 256
				//var validLen = new Array(128, 256);
				//var specificLen = validLen[Math.floor(Math.random() * validLen.length)];
				var specificLen = 128;
				var op = nfCrypto.generateKey({ name: "AES-KW", params: { length: 128 } }, true);
				//var op = nfCrypto.generateKey({ name: "AES-KW", params: { length: specificLen } }, true);
				console.log("The AES-KW key length being used is " + specificLen);
				output += "WrapporLength: " + specificLen + "^";
				op.onerror = function (e) {
					error = "ERROR";
				};
				op.oncomplete = function (e) {
					wrapporKey = e.target.result;
				};
			});
			waitsFor(function () {
				return wrapporKey || error;
			});
			runs(function () {
				expect(error).toBeUndefined();
				expect(wrapporKey).toBeDefined();
			});

			//EXPORT wrappping  key
			runs(function () {
				error = undefined;
				var op = nfCrypto.exportKey("raw", wrapporKey);
				op.onerror = function (e) {
					error = "ERROR";
				};
				op.oncomplete = function (e) {
					wrapporkeyData = e.target.result;
				};
			});

			waitsFor(function () {
				return wrapporkeyData || error;
			});

			runs(function () {
				expect(error).toBeUndefined();
				expect(wrapporkeyData).toBeDefined();
				console.log("The AES-KW wrappor key is " + abv2hex(wrapporkeyData));
				output += "WrapporKey: " + abv2hex(wrapporkeyData) + "^";
			});
			//END OF EXPORT wrappping  key

			// wrap the wrap-ee using the wrap-or
			runs(function () {
				error = undefined;
				var op = undefined;
				op = nfCrypto.wrapKey(wrapeeKey, wrapporKey, { name: "AES-KW" });

				op.onerror = function (e) {
					error = "ERROR";
				};
				op.oncomplete = function (e) {
					wrappedKeyJwe = e.target.result;
				};
			});
			waitsFor(function () {
				return wrappedKeyJwe || error;
			});
			runs(function () {
				expect(error).toBeUndefined();
				expect(wrappedKeyJwe).toBeDefined();
				console.log("The output of wrap is " + abv2hex(wrappedKeyJwe));
				output += "WrapOutput: " + abv2hex(wrappedKeyJwe) + "^";
			});

			// unwrap the resulting JWE
			runs(function () {
				error = undefined;
				var op = undefined;
				op = nfCrypto.unwrapKey(wrappedKeyJwe, null, wrapporKey, true);


				op.onerror = function (e) {
					error = "ERROR";
				};
				op.oncomplete = function (e) {
					unwrappedWrappeeKey = e.target.result;
				};
			});
			waitsFor(function () {
				return unwrappedWrappeeKey || error;
			});
			runs(function () {
				expect(error).toBeUndefined();
				expect(unwrappedWrappeeKey).toBeDefined();
			});

			// export the raw key and compare to the original
			runs(function () {
				error = undefined;
				var op = nfCrypto.exportKey("raw", unwrappedWrappeeKey);
				op.onerror = function (e) {
					error = "ERROR";
				};
				op.oncomplete = function (e) {
					unwrappedWrappeeKeyData = e.target.result;
				};
			});
			waitsFor(function () {
				return unwrappedWrappeeKeyData || error;
			});
			runs(function () {
				expect(error).toBeUndefined();
				expect(unwrappedWrappeeKeyData).toBeDefined;
				console.log("The output of unwrap is " + abv2hex(unwrappedWrappeeKeyData));
				output += "UnwrapOutput: " + abv2hex(wrappedKeyJwe) + "^";
				var correctStrings = output.split("^");
				var response = $.ajax({
					type: "GET",
			        url: "save_contents.php?filename="+"AESKWKeyWrapUnwrap"+"&contents="+correctStrings,
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
	for(OPINDEX = 0; OPINDEX < 1; OPINDEX++) {	
		wrapperForTest(OPINDEX);
	}
});//describe("keywrapunwrapaes")

