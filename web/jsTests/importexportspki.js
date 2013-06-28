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

describe("importspki", function () {

	//Globals
	var OPINDEX = 0;
	var INDEXVALUE = 0;
	//Global key data
	// SPKI - Simple Public Key Infrastructure
	// openssl genrsa -out pair.pem 2048
	// openssl rsa -in pair.pem -out pubkey.der -outform DER -pubout
	// openssl enc -base64 -in pubkey.der
	var SPKIPUBKEY = base64.parse(
			"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsjUf4UZyuZ5JKazU0Kq/" +
			"dbaVY0oQxYZcsCQxRrjKF6yQaHACzeubHHaXRLwXkCVvBf2V0HBdJ/xCiIqwos3X" +
			"CMgMWu0mzlSxfv0kyAuH46SzTZdAt5hJPMSjt+eTJI+9hYq6DNqN09ujBwlhQM2J" +
			"hI9V3tZhBD5nQPTNkXYRD3aZp5wWtErIdXDP4ZXFcPdu6sLjH68WZuR9M6Q5Xztz" +
			"O9DA7+m/7CHDvWWhlvuN15t1a4dwBuxlY0eZh1JjM6OPH9zJ2OKJIVOLNIE2WejQ" +
			"E5a7IarLOHM8bYtBZ7/tSyx3MkN40OjPA7ZWiEpyT/wDiZo45aLlN4vsWJpIcdqS" +
			"RwIDAQAB"
	);

	
	var LISTOFTESTS = [
	    {
	         test: "ImportExportSpkiHappyPath",
	         keyFormat: "spki",
	         algo: { name: "RSAES-PKCS1-v1_5" },
	         key: SPKIPUBKEY,
	         usages: [],
	         extractable: true,
	         type: "public",
	         result: "pass"
	    },
	    {    //Since this is a public key it will always be exportable
	         test: "ImportExportSpkiNonExtractable",
	         keyFormat: "spki",
	         algo: { name: "RSAES-PKCS1-v1_5" },
	         key: SPKIPUBKEY,
	         usages: [],
	         extractable: false,
	         type: "public",
	         result: "pass"
	    },
	    {
	         test: "ImportSpkiInvalidUsage",
	         keyFormat: "spki",
	         algo: { name: "RSAES-PKCS1-v1_5" },
	         key: SPKIPUBKEY,
	         usages: ["derive"],
	         extractable: true,
	         type: "public",
	         importKey: false
	    },
	    {
	         test: "ImportSpkiInvalidAlgo",
	         keyFormat: "spki",
	         algo: { name: "PKCS1-v1_5" },
	         key: SPKIPUBKEY,
	         usages: [],
	         extractable: true,
	         type: "public",
	         importKey: false
	    },
	    {
	         test: "ImportSpkiIncorrectAlgo",
	         keyFormat: "spki",
	         algo: { name: "SHA-256" },
	         key: SPKIPUBKEY,
	         usages: [],
	         extractable: true,
	         type: "public",
	         importKey: false
	    },
	    {
	         test: "ImportSpkiInvalidKeyFormat",
	         keyFormat: "jwk",
	         algo: { name: "PKCS1-v1_5" },
	         key: SPKIPUBKEY,
	         usages: [],
	         extractable: true,
	         type: "public",
	         importKey: false
	    },
	    {
	         test: "ImportSpkiInvalidKey",
	         keyFormat: "spki",
	         algo: { name: "RSAES-PKCS1-v1_5" },
	         key: new Uint8Array([]),
	         usages: [],
	         extractable: true,
	         type: "public",
	         importKey: false
	    }
	];

	function wrapperForTest(OPINDEX) {	
		it(LISTOFTESTS[OPINDEX].test, function () {
			INDEXVALUE = LISTOFTESTS[OPINDEX];
			
			var error = undefined;
			var key = undefined;
			var exportedSpkiKeyData = undefined;

			runs(function () {
				try {
					error = undefined;
					var op = nfCrypto.importKey(INDEXVALUE.keyFormat, INDEXVALUE.key, INDEXVALUE.algo, INDEXVALUE.extractable, INDEXVALUE.usages);
					op.onerror = function (e) {
						error = "ERROR";
					};
					op.oncomplete = function (e) {
						key = e.target.result;
					};
				} catch(e) {
					error = "ERROR";
				}
			});

			waitsFor(function () {
				return key || error;
			});

			runs(function () {
				if(INDEXVALUE.importKey == false) {
					expect(error).toBeDefined();
					expect(key).toBeUndefined();
				} else {
					expect(error).toBeUndefined();
					//Doing checks on keys to validate Key structure
					expect(key.algorithm.name).toEqual(INDEXVALUE.algo.name);
					if (INDEXVALUE.test == "ImportExportSpkiNonExtractable") {
						expect(key.extractable).toBeTruthy();
					} else {
						expect(key.extractable).toEqual(INDEXVALUE.extractable);
					}
					expect(key.keyUsage.length).toEqual(INDEXVALUE.usages.length);
					if(INDEXVALUE.usages.length > 1) {
						expect(key.keyUsage[0]).toEqual(INDEXVALUE.usages[0]);
						expect(key.keyUsage[1]).toEqual(INDEXVALUE.usages[1]);
					} else {
						expect(key.keyUsage[0]).toEqual(INDEXVALUE.usages[0]);
					}
					//TODO: need to confirm what the default value should be
					//expect(key.keyUsage[0]).toEqual("sign");
					expect(key.type).toEqual(INDEXVALUE.type);
					//Handle is how C++ correlates keys with JS
					//0 implies invalid key
					expect(key.handle).not.toEqual(0);
				}
			});
			
			if(INDEXVALUE.importKey != false) {
				runs(function () {
					try {
						var op = nfCrypto.exportKey(INDEXVALUE.keyFormat, key);
						op.onerror = function (e) {
							error = "ERROR";
						};
						op.oncomplete = function (e) {
							exportedSpkiKeyData = e.target.result;
						};
					} catch(e) {
						error = "ERROR";
					}
				});

				waitsFor(function () {
					return error || exportedSpkiKeyData;
				});

				runs(function () {
					if(INDEXVALUE.exportKey == false) {
						expect(error).toBeDefined();
						expect(exportedSpkiKeyData).toBeUndefined();
					} else {
						expect(error).toBeUndefined();
						expect(base16.stringify(exportedSpkiKeyData)).toEqual(base16.stringify(INDEXVALUE.key));
					}
				});
		}//if(INDEXVALUE.importKey)
	});//it
}//function wrapperForTest
for(OPINDEX = 0; OPINDEX < LISTOFTESTS.length; OPINDEX++) {	
	wrapperForTest(OPINDEX);
}
});//describe("importspki")

describe("exportspki", function () {

	//Globals
	var OPINDEX = 0;
	var INDEXVALUE = 0;
	//Global key data
	// SPKI - Simple Public Key Infrastructure
	// openssl genrsa -out pair.pem 2048
	// openssl rsa -in pair.pem -out pubkey.der -outform DER -pubout
	// openssl enc -base64 -in pubkey.der
	var SPKIPUBKEY = base64.parse(
			"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsjUf4UZyuZ5JKazU0Kq/" +
			"dbaVY0oQxYZcsCQxRrjKF6yQaHACzeubHHaXRLwXkCVvBf2V0HBdJ/xCiIqwos3X" +
			"CMgMWu0mzlSxfv0kyAuH46SzTZdAt5hJPMSjt+eTJI+9hYq6DNqN09ujBwlhQM2J" +
			"hI9V3tZhBD5nQPTNkXYRD3aZp5wWtErIdXDP4ZXFcPdu6sLjH68WZuR9M6Q5Xztz" +
			"O9DA7+m/7CHDvWWhlvuN15t1a4dwBuxlY0eZh1JjM6OPH9zJ2OKJIVOLNIE2WejQ" +
			"E5a7IarLOHM8bYtBZ7/tSyx3MkN40OjPA7ZWiEpyT/wDiZo45aLlN4vsWJpIcdqS" +
			"RwIDAQAB"
	);

	
	var LISTOFTESTS = [
	                {
	          	         test: "ExportSpkiInvalidKeyFormat",
	          	         keyFormat: "jwk",
	          	         algo: { name: "PKCS1-v1_5" },
	          	         key: SPKIPUBKEY,
	          	         usages: [],
	          	         extractable: true,
	          	         type: "public",
	          	         exportKey: false
	          	    },
	          	    {
	          	         test: "ExportSpkiInvalidKey",
	          	         keyFormat: "spki",
	          	         algo: { name: "RSAES-PKCS1-v1_5" },
	          	         key: new Uint8Array([]),
	          	         usages: [],
	          	         extractable: true,
	          	         type: "public",
	          	         exportKey: false
	          	    }
		];

	function wrapperForTest(OPINDEX) {	
		it(LISTOFTESTS[OPINDEX].test, function () {
			INDEXVALUE = LISTOFTESTS[OPINDEX];
			
			var error = undefined;
			var key = undefined;
			var exportedSpkiKeyData = undefined;

			runs(function () {
				try {
					error = undefined;
					var op = nfCrypto.importKey("spki", SPKIPUBKEY, { name: "RSAES-PKCS1-v1_5" }, true);
					op.onerror = function (e) {
						error = "ERROR";
					};
					op.oncomplete = function (e) {
						key = e.target.result;
					};
				} catch(e) {
					error = "ERROR";
				}
			});

			waitsFor(function () {
				return key || error;
			});

			runs(function () {
				if(INDEXVALUE.importKey == false) {
					expect(error).toBeDefined();
					expect(key).toBeUndefined();
				} else {
					expect(error).toBeUndefined();
					//Doing checks on keys to validate Key structure
					expect(key.algorithm.name).toEqual("RSAES-PKCS1-v1_5");
					expect(key.extractable).toEqual(true);
					expect(key.keyUsage.length).toEqual(0);
					//TODO: need to confirm what the default value should be
					//expect(key.keyUsage[0]).toEqual("sign");
					expect(key.type).toEqual("public");
					//Handle is how C++ correlates keys with JS
					//0 implies invalid key
					expect(key.handle).not.toEqual(0);
				}
			});
			
			runs(function () {
				try {
					var op = nfCrypto.exportKey(INDEXVALUE.keyFormat, INDEXVALUE.key);
					op.onerror = function (e) {
						error = "ERROR";
					};
					op.oncomplete = function (e) {
						exportedSpkiKeyData = e.target.result;
					};
				} catch(e) {
					error = "ERROR";
				}				
			});

			waitsFor(function () {
				return error || exportedSpkiKeyData;
			});

			runs(function () {
				expect(error).toBeDefined();
				expect(exportedSpkiKeyData).toBeUndefined();
			});
		});//it
}//function wrapperForTest
for(OPINDEX = 0; OPINDEX < LISTOFTESTS.length; OPINDEX++) {	
	wrapperForTest(OPINDEX);
}
});//describe("exportspki")
