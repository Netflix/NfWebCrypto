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

describe("importpkcs8", function () {

	//Globals
	var OPINDEX = 0;
	var INDEXVALUE = 0;
	// PKCS #8: Private Key Information Syntax Standard #8
	// <private key of pair generated above>
	// openssl pkcs8 -topk8 -inform PEM -outform DER -in pair.pem -out privkey.der -nocrypt
	// openssl enc -base64 -in privkey.der
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

	
	var LISTOFTESTS = [
	    {
	         test: "ImportExportPkcs8HappyPath",
	         keyFormat: "pkcs8",
	         algo: { name: "RSAES-PKCS1-v1_5" },
	         key: PKCS8KEY,
	         usages: [],
	         extractable: true,
	         type: "private",
	         result: "pass"
	    },
	    {    //Import will pass export will fail
	         test: "ImportExportPkcs8NonExtractable",
	         keyFormat: "pkcs8",
	         algo: { name: "RSAES-PKCS1-v1_5" },
	         key: PKCS8KEY,
	         usages: [],
	         extractable: false,
	         type: "private",
	         exportKey: false
	    },
	    {
	         test: "ImportInvalidUsage",
	         keyFormat: "pkcs8",
	         algo: { name: "RSAES-PKCS1-v1_5" },
	         key: PKCS8KEY,
	         usages: ["derive"],
	         extractable: true,
	         type: "private",
	         importKey: false
	    },
	    {
	         test: "ImportInvalidAlgo",
	         keyFormat: "pkcs8",
	         algo: { name: "PKCS1-v1_5" },
	         key: PKCS8KEY,
	         usages: [],
	         extractable: true,
	         type: "private",
	         importKey: false
	    },
	    {
	         test: "ImportIncorrectAlgo",
	         keyFormat: "pkcs8",
	         algo: { name: "SHA-256" },
	         key: PKCS8KEY,
	         usages: [],
	         extractable: false,
	         type: "private",
	         importKey: false
	    },
	    {
	         test: "ImportIncorrectKeyFormat",
	         keyFormat: "raw",
	         algo: { name: "RSAES-PKCS1-v1_5" },
	         key: PKCS8KEY,
	         usages: [],
	         extractable: true,
	         type: "private",
	         importKey: false
	    },
	    {
	         test: "ImportEmptyKey",
	         keyFormat: "pkcs8",
	         algo: { name: "RSAES-PKCS1-v1_5" },
	         //Empty key being supplied
	         key: new Uint8Array([]),
	         usages: [],
	         extractable: true,
	         type: "private",
	         importKey: false
	    }  
	    
	];

	function wrapperForTest(OPINDEX) {	
		it(LISTOFTESTS[OPINDEX].test, function () {
			INDEXVALUE = LISTOFTESTS[OPINDEX];
			
			var error = undefined;
			var privKey = undefined;
			var pkcs8PrivKeyData2 = undefined;

			// import pkcs8-formatted private key
			runs(function () {
				try {
					var op = nfCrypto.importKey(INDEXVALUE.keyFormat, INDEXVALUE.key, INDEXVALUE.algo, INDEXVALUE.extractable, INDEXVALUE.usages);
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
				return privKey || error;
			});

			runs(function () {
				if(INDEXVALUE.importKey == false) {
					expect(error).toBeDefined();
					expect(privKey).toBeUndefined();
				} else {
					expect(error).toBeUndefined();
					expect(privKey.algorithm.name).toEqual(INDEXVALUE.algo.name);
					expect(privKey.keyUsage.length).toEqual(INDEXVALUE.usages.length);
					if(INDEXVALUE.usages.length > 1) {
						expect(privKey.keyUsage[0]).toEqual(INDEXVALUE.usages[0]);
						expect(privKey.keyUsage[1]).toEqual(INDEXVALUE.usages[1]);
					} else {
						expect(privKey.keyUsage[0]).toEqual(INDEXVALUE.usages[0]);
					}
					//TODO: need to confirm what the default value should be
					//expect(key.keyUsage[0]).toEqual("sign");
					//Handle is how C++ correlates keys with JS
					//0 implies invalid key
					expect(privKey.handle).not.toEqual(0);
					//TODO: need to confirm what the default value should be
					expect(privKey.type).toBe(INDEXVALUE.type);
					expect(privKey.extractable).toBe(INDEXVALUE.extractable);
				}
			});

			if(INDEXVALUE.importKey != false) {
				// export the private key back out, raw pkcs8 data should be the same
				runs(function () {
					try {
						error = undefined;
						var op = nfCrypto.exportKey(INDEXVALUE.keyFormat, privKey);
						op.onerror = function (e) {
							error = "ERROR";
						};
						op.oncomplete = function (e) {
							pkcs8PrivKeyData2 = e.target.result;
						};
					} catch(e) {
						error = "ERROR";
					}
				});

				waitsFor(function () {
					return pkcs8PrivKeyData2 || error;
				});

				runs(function () {
					if(INDEXVALUE.exportKey == false) {
						expect(error).toBeDefined();
						expect(pkcs8PrivKeyData2).toBeUndefined();
					} else {
						expect(error).toBeUndefined();
						expect(pkcs8PrivKeyData2).toBeDefined();
						expect(base16.stringify(PKCS8KEY)).toEqual(base16.stringify(PKCS8KEY));
					}
				});
			}//if(INDEXVALUE.importKey)
	});//it
}//function wrapperForTest
for(OPINDEX = 0; OPINDEX < LISTOFTESTS.length; OPINDEX++) {	
	wrapperForTest(OPINDEX);
}
});//describe("importspki")

describe("exportpkcs8", function () {

	//Globals
	var OPINDEX = 0;
	var INDEXVALUE = 0;
	// PKCS #8: Private Key Information Syntax Standard #8
	// <private key of pair generated above>
	// openssl pkcs8 -topk8 -inform PEM -outform DER -in pair.pem -out privkey.der -nocrypt
	// openssl enc -base64 -in privkey.der
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

	
	var LISTOFTESTS = [
	   {
	   	   test: "ExportIncorrectKeyFormat",
	   	   keyFormat: "raw",
	   	   algo: { name: "RSAES-PKCS1-v1_5" },
	   	   key: PKCS8KEY,
	   	   usages: [],
	   	   extractable: true,
	   	   type: "private"
	    },
	    {
	       test: "ExportEmptyKey",
	       keyFormat: "pkcs8",
	       algo: { name: "RSAES-PKCS1-v1_5" },
	       //Empty key being supplied
	       key: new Uint8Array([]),
	       usages: [],
	       extractable: true,
	       type: "private"
	     }  
	];

	function wrapperForTest(OPINDEX) {	
		it(LISTOFTESTS[OPINDEX].test, function () {
			INDEXVALUE = LISTOFTESTS[OPINDEX];

			var error = undefined;
			var privKey = undefined;
			var pkcs8PrivKeyData2 = undefined;

			// import pkcs8-formatted private key
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
				return privKey || error;
			});

			runs(function () {
				expect(error).toBeUndefined();
				expect(privKey.algorithm.name).toEqual("RSAES-PKCS1-v1_5");
				expect(privKey.keyUsage.length).toEqual(0);
				//TODO: need to confirm what the default value should be
				//expect(key.keyUsage[0]).toEqual("sign");
				//Handle is how C++ correlates keys with JS
				//0 implies invalid key
				expect(privKey.handle).not.toEqual(0);
				//TODO: need to confirm what the default value should be
				expect(privKey.type).toBe("private");
				expect(privKey.extractable).toBe(true);
			});

			// export the private key back out, raw pkcs8 data should be the same
			runs(function () {
				try {
					error = undefined;
					var op = nfCrypto.exportKey(INDEXVALUE.keyFormat, INDEXVALUE.key);
					op.onerror = function (e) {
						error = "ERROR";
					};
					op.oncomplete = function (e) {
						pkcs8PrivKeyData2 = e.target.result;
					};
				} catch(e) {
					error = "ERROR";
				}
			});

			waitsFor(function () {
				return pkcs8PrivKeyData2 || error;
			});

			runs(function () {
				expect(error).toBeDefined();
				expect(pkcs8PrivKeyData2).toBeUndefined();
			});
		});//it
	}//function wrapperForTest
	for(OPINDEX = 0; OPINDEX < LISTOFTESTS.length; OPINDEX++) {	
		wrapperForTest(OPINDEX);
	}
});//describe("exportspki")
