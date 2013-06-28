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

describe("ImportExport", function () {

	it("ImportExportImportHappyPath", function () {

		var error = undefined;
		var key = undefined;
		var exportedKeyData = undefined;
		var importedKey = undefined;

		runs(function () {
			var op = crypto.importKey(
					"raw",
					new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]),
					"AES-GCM",
					true,
					["encrypt", "decrypt"]
			);
			op.onerror = function (e) {
				error = "ERROR :: " + e.target.result
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
			expect(key.algorithm).toEqual("AES-GCM");
			expect(key.extractable).toBeTruthy();
			expect(key.keyUsage.length).toEqual(1);
			expect(key.keyUsage[0]).toEqual("encrypt");
			expect(key.keyUsage[1]).toEqual("decrypt");
			expect(key.type).toEqual("secret");
			//Handle is how C++ correlates keys with JS
			//0 implies invalid key
			expect(key.handle).not.toEqual(0);
		});

		runs(function () {
			var op = crypto.exportKey("local-storage", key);
			op.onerror = function (e) {
				error = "ERROR :: " + e.target.result;
			};
			op.oncomplete = function (e) {
				exportedKeyData = e.target.result;
			};
		});

		waitsFor(function () {
			return exportedKeyData || error;
		});

		runs(function () {
			expect(error).toBeUndefined();
			//Doing checks on keys to validate Key structure
			expect(exportedKeyData.algorithm).toEqual("AES-GCM");
			expect(exportedKeyData.extractable).toBeTruthy();
			expect(exportedKeyData.keyUsage.length).toEqual(1);
			expect(exportedKeyData.keyUsage[0]).toEqual("encrypt");
			expect(exportedKeyData.keyUsage[1]).toEqual("decrypt");
			expect(exportedKeyData.type).toEqual("secret");
			//Handle is how C++ correlates keys with JS
			//0 implies invalid key
			expect(exportedKeyData.handle).not.toEqual(0);
		});

		//Importing the key back
		runs(function () {
			var op = crypto.importKey("local-storage", exportedKeyData);
			op.onerror = function (e) {
				error = "ERROR :: " + e.target.result;
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
			//Since we're checking that they are identical no need to verify all params
			expect(importedKey).toBe(key);
		});
	});//it("ImportExportImportHappyPath")

	it("ImportTamperedExportImport", function () {

		var error = undefined;
        var exportedKeyData = undefined;
        var key = undefined;
        var importKey = undefined;

		// create an AES key
		var keyData = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]),
		key;

		runs(function () {
			var op = nfCrypto.importKey("raw", keyData, { name: "AES-CBC" }, false, ["encrypt", "decrypt"]);
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
			expect(key.algorithm).toEqual("AES-CBC");
			expect(key.extractable).toBeFalsy();
			expect(key.keyUsage.length).toEqual(1);
			expect(key.keyUsage[0]).toEqual("encrypt");
			expect(key.keyUsage[1]).toEqual("decrypt");
			expect(key.type).toEqual("secret");
			//Handle is how C++ correlates keys with JS
			//0 implies invalid key
			expect(key.handle).not.toEqual(0);
		});

		runs(function () {
			var op = nfCrypto.exportKey("local-storage", key);
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				exportedKeyData = e.target.result;
			};
		});

		waitsFor(function () {
			return exportedKeyData || error;
		});

		runs(function () {
			expect(error).toBeUndefined();
			//Doing checks on keys to validate Key structure
			expect(exportedKeyData.algorithm).toEqual("AES-CBC");
			expect(exportedKeyData.extractable).toBeFalsy();
			expect(exportedKeyData.keyUsage.length).toEqual(1);
			expect(exportedKeyData.keyUsage[0]).toEqual("encrypt");
			expect(exportedKeyData.keyUsage[1]).toEqual("decrypt");
			expect(exportedKeyData.type).toEqual("secret");
			//Handle is how C++ correlates keys with JS
			//0 implies invalid key
			expect(exportedKeyData.handle).not.toEqual(0);
		});
		//Import the key
		runs(function () {
			error = undefined;
            //Tampering exported data
			exportedKeyData[10] = exportedKeyData[10] ^ 0xFF;
			var op = nfCrypto.importKey("local-storage", exportedKeyData);
			op.onerror = function (e) {
				error = "ERROR";
			};
			op.oncomplete = function (e) {
				importedKey = e.target.result;
			};
		});

		waitsFor(function () {
			return importedKey || error;
		});

		runs(function () {
			expect(error).toBeDefined();
			expect(importedKey).toBeUndefined();
		});
	});//it("ImportTamperedExportImport")
	
	it("ImportExportImportRawHMAC", function () {

        var error = undefined;
        var exportedKeyData = undefined;
        var key = undefined;
        var importKey = undefined;

        // create an AES key
        var keyData = new Uint8Array([
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
            ]),
            key;

        runs(function () {
            var op = importKey("raw", keyData, { name: "HMAC", params: { hash: "SHA-256" } }, false, ["sign", "verify"]);
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
			expect(key.algorithm).toEqual("HMAC");
			expect(key.extractable).toBeFalsy();
			expect(key.keyUsage.length).toEqual(1);
			expect(key.keyUsage[0]).toEqual("sign");
			expect(key.keyUsage[1]).toEqual("verify");
			expect(key.type).toEqual("secret");
			//Handle is how C++ correlates keys with JS
			//0 implies invalid key
			expect(key.handle).not.toEqual(0);
        });

        runs(function () {
            var op = nfCrypto.exportKey("local-storage", key);
            op.onerror = function (e) {
                error = "ERROR";
            };
            op.oncomplete = function (e) {
                exportedKeyData = e.target.result;
            };
        });

        waitsFor(function () {
            return exportedKeyData || error;
        });

        runs(function () {
            expect(error).toBeUndefined();
            //Doing checks on keys to validate Key structure
			expect(exportedKeyData.algorithm).toEqual("HMAC");
			expect(exportedKeyData.extractable).toBeFalsy();
			expect(exportedKeyData.keyUsage.length).toEqual(1);
			expect(exportedKeyData.keyUsage[0]).toEqual("sign");
			expect(exportedKeyData.keyUsage[1]).toEqual("verify");
			expect(exportedKeyData.type).toEqual("secret");
			//Handle is how C++ correlates keys with JS
			//0 implies invalid key
			expect(exportedKeyData.handle).not.toEqual(0);
        });

        runs(function () {
            var op = nfCrypto.importKey("local-storage", exportedKeyData);
            op.onerror = function (e) {
                error = "ERROR";
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
            expect(importKey).toBe(key);
        });
    });//it("ImportExportImportRawHMAC")
	
	//Using import-export with RAW AES-CBC key
	it("ImportExportRawAES", function () {
        var error = undefined;
        var key = undefined;
        var keyData = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]);
        var exportKeyData = undefined;

        runs(function () {
            error = undefined;
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
            //Doing checks on keys to validate Key structure
			expect(key.algorithm).toEqual("AES-CBC");
			expect(key.extractable).toBeTruthy();
			expect(key.keyUsage.length).toEqual(0);
			//TODO: determine what default values should be
			expect(key.keyUsage[0]).toEqual("sign");
			expect(key.type).toEqual("secret");
			//Handle is how C++ correlates keys with JS
			//0 implies invalid key
			expect(key.handle).not.toEqual(0);
        });

        runs(function () {
            error = undefined;
            var op = nfCrypto.exportKey("raw", key);
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
            //Since they are identical then need to check each value
            expect(exportKeyData).toEqual(keyData);
        });
    });//it("ImportExportRawAES")
});