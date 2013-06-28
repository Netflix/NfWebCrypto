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

describe("importraw", function () {

	//Globals
	var OPINDEX = 0;
	var INDEXVALUE = 0;
	var KEYDATA = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]);
	var BAD_KEYDATA = new Uint8Array([]); 
	var LISTOFTESTS = [
	    {
	         test: "ImportExportRawHappyPath",
	         keyFormat: "raw",
	         algo: { name: "AES-CBC" },
	         key: KEYDATA,
	         usages: [],
	         extractable: true,
	         type: "secret",
	         result: "pass"
	    },
	    {
	         test: "ImportRawNonExtractable",
	         keyFormat: "raw",
	         algo: { name: "AES-CBC" },
	         key: KEYDATA,
	         usages: [],
	         extractable: false,
	         type: "secret",
	         //Since extractable is false export will fail
	         exportKey: false
	    },
	    {
	         test: "ImportRawInvalidUsage",
	         keyFormat: "raw",
	         algo: { name: "AES-CBC" },
	         key: KEYDATA,
	         usages: ["derive"],
	         extractable: true,
	         type: "secret",
	         importKey: false
	    },
	    {
	         test: "ImportRawInvalidAlgo",
	         keyFormat: "raw",
	         algo: { name: "PKCS1-v1_5" },
	         key: KEYDATA,
	         usages: [],
	         extractable: true,
	         type: "secret",
	         importKey: false
	    },
	    {
	         test: "ImportRawIncorrectAlgo",
	         keyFormat: "raw",
	         algo: { name: "SHA-384" },
	         key: KEYDATA,
	         usages: [],
	         extractable: true,
	         type: "secret",
	         importKey: false
	    },
	    {    //Specifying jwk instead of raw
	         test: "ImportRawIncorrectKeyFormat",
	         keyFormat: "jwk",
	         algo: { name: "AES-CBC" },
	         key: KEYDATA,
	         usages: [],
	         extractable: true,
	         type: "secret",
	         importKey: false
	    },
	    {    //Invalidate KEYDATA input to import
	         test: "ImportRawInvalidKey",
	         keyFormat: "raw",
	         algo: { name: "AES-CBC" },
	         key: BAD_KEYDATA,
	         usages: [],
	         extractable: true,
	         type: "secret",
	         importKey: false
	    },

	];

	function wrapperForTest(OPINDEX) {	
		it(LISTOFTESTS[OPINDEX].test, function () {
			INDEXVALUE = LISTOFTESTS[OPINDEX];

			var error = undefined;
			var key = undefined;
			var keyData2 = undefined;    

			runs(function () {
				// TODO:
				// Once https://www.w3.org/Bugs/Public/show_bug.cgi?id=21435 is resolved, might need to pass in length as part of AlgorithmIdentifier
				try {
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
					expect(key.algorithm.name).toEqual(INDEXVALUE.algo.name);
					expect(key.extractable).toEqual(INDEXVALUE.extractable);
					expect(key.keyUsage.length).toEqual(INDEXVALUE.usages.length);
					if(INDEXVALUE.usages.length > 1) {
						expect(key.keyUsage[0]).toEqual(INDEXVALUE.usages[0]);
						expect(key.keyUsage[1]).toEqual(INDEXVALUE.usages[1]);
					} else {
						expect(key.keyUsage[0]).toEqual(INDEXVALUE.usages[0]);
					}
					//TODO: need to confirm what the default value should be
					//expect(key.keyUsage[0]).toEqual("sign");
					expect(key.type).toBe(INDEXVALUE.type);
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
							keyData2 = e.target.result;
						};
					} catch(e) {
						error = "ERROR";
					}
				});

				waitsFor(function () {
					return keyData2 || error;
				});

				runs(function () {
					if(INDEXVALUE.exportKey == false) {
						expect(error).toBeDefined();
						expect(keyData2).toBeUndefined();
					} else {
						expect(error).toBeUndefined();
						expect(keyData2).toBeDefined();
						expect(base16.stringify(keyData2)).toEqual(base16.stringify(INDEXVALUE.key));
					}
				});
			}//if(INDEXVALUE.importKey)
		});//it
	}//function wrapperForTest
	for(OPINDEX = 0; OPINDEX < LISTOFTESTS.length; OPINDEX++) {	
		wrapperForTest(OPINDEX);
	}
});//describe("importraw")

describe("exportraw", function () {

	//Globals
	var OPINDEX = 0;
	var INDEXVALUE = 0;
	var KEYDATA = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]);
	var BAD_KEYDATA = new Uint8Array([]); 
	var LISTOFTESTS = [
		    {    //Specifying jwk instead of raw
		         test: "ExportRawIncorrectKeyFormat",
		         keyFormat: "jwk",
		         algo: { name: "AES-CBC" },
		         key: KEYDATA,
		         usages: [],
		         extractable: true,
		         type: "secret",
		         exportKey: false
		    },
		    {    //Invalidate KEYDATA input to import
		         test: "ExportRawInvalidKey",
		         keyFormat: "raw",
		         algo: { name: "AES-CBC" },
		         key: BAD_KEYDATA,
		         usages: [],
		         extractable: true,
		         type: "secret",
		         exportKey: false
		    }
	];

	function wrapperForTest(OPINDEX) {	
		it(LISTOFTESTS[OPINDEX].test, function () {
			INDEXVALUE = LISTOFTESTS[OPINDEX];

			var error = undefined;
			var key = undefined;
			var keyData2 = undefined;    

			runs(function () {
				// TODO:
				// Once https://www.w3.org/Bugs/Public/show_bug.cgi?id=21435 is resolved, might need to pass in length as part of AlgorithmIdentifier
				try {
					var op = nfCrypto.importKey("raw", KEYDATA, { name: "AES-CBC" }, true);
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
				expect(error).toBeUndefined();
				expect(key.algorithm.name).toEqual("AES-CBC");
				expect(key.extractable).toEqual(true);
				expect(key.keyUsage.length).toEqual(0);
				//TODO: need to confirm what the default value should be
				//expect(key.keyUsage[0]).toEqual("sign");
				expect(key.type).toBe("secret");
				//Handle is how C++ correlates keys with JS
				//0 implies invalid key
				expect(key.handle).not.toEqual(0);
				
			});
			
			runs(function () {
				try {
					var op = nfCrypto.exportKey(INDEXVALUE.keyFormat, INDEXVALUE.key);
					op.onerror = function (e) {
						error = "ERROR";
					};
					op.oncomplete = function (e) {
						keyData2 = e.target.result;
					};
				} catch(e) {
					error = "ERROR";
				}
			});

			waitsFor(function () {
				return keyData2 || error;
			});

			runs(function () {
				//Since all the cases are negative there will only be errors
				expect(error).toBeDefined();
				expect(keyData2).toBeUndefined();
			});
		});//it
	}//function wrapperForTest
	for(OPINDEX = 0; OPINDEX < LISTOFTESTS.length; OPINDEX++) {	
		wrapperForTest(OPINDEX);
	}
});//describe("exportraw")
