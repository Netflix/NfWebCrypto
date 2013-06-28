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
describe("StressSHA384", function () {
	var OPINDEX = 0;
	
	function wrapperForTest(OPINDEX) {	
		it("DigestStressSHA384", function () {
			var op, result, error, complete;
			
			console.log(" DigestStressSHA384 called this many times " + OPINDEX);
			var output = "DigestStressSHA384 called this many times: " + OPINDEX + "^";
		
			function randomBytes(buffer) {
				for (var i = 0; i < buffer.length; ++i)
					buffer[i] = Math.floor(Math.random() * (0xFF - 0 + 1)) + 0;
			}
		
			//Generating a random uint8 array of variable length from 1 to 100
			var randBuffer = new Uint8Array(Math.floor((Math.random()*100)+1));
			console.log(" The length of randBuffer is " + randBuffer.length);
			output += "RandBuffer length:" + randBuffer.length + "^";
			randomBytes(randBuffer);
		
			runs(function () {
				op = nfCrypto.digest("SHA-384", randBuffer);
				op.onerror = function (e) {
					error = "ERROR :: " + e.target.result;
				};
				op.oncomplete = function (e) {
					complete = true;
					result = e.target.result;
				};
			});

			waitsFor(function () {
				return error || complete;
			});

			runs(function () {
				expect(error).toBeUndefined();
				expect(complete).toBeTruthy();
				//for (var j = 0; j < randBuffer.length; j++) {
					//console.log("The randomStr before SHA " + randBuffer.join());
				//}
				console.log(" The randomStr(in hex) before in SHA384 " + abv2hex(randBuffer));
				output += "RandomBuffer: " + abv2hex(randBuffer) + "^";
				console.log(" The randomStr after SHA384 " + abv2hex(result));
				output += "SHA384: " + abv2hex(result) + "^";
				var correctStrings = output.split("^");
							
				var response = $.ajax({
					type: "GET",
			        url: "save_contents.php?filename="+"DigestStressSHA384"+"&contents="+correctStrings,
			        async: false,
			        success: function(text, status) {
			        	console.log(" Was able to post successfully " + text);
			        },
			        error: function (xhr, ajaxOptions, thrownError) {
			        	console.log("Was NOT able to post successfully: xhr status " +  xhr.status + " error " + thrownError);
			        }
			    });
			});
		});//end of it("DigestStressSHA384")
	}	
	for(OPINDEX = 0; OPINDEX < 2; OPINDEX++) {	
		console.log("Calling wrapperForTest " + OPINDEX);
		wrapperForTest(OPINDEX);
	}
		
});//describe("DigestStressSHA384)

describe("StressSHA1", function () {
	var OPINDEX = 0;
	
	function wrapperForTest(OPINDEX) {
		it("DigestStressSHA1", function () {
			
			var op, result, error, complete;
			
			console.log("DigestStressSHA1 called this many times " + OPINDEX);
			var output = "DigestStressSHA1 called this many times: " + OPINDEX + "^";
			
		
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
				op = nfCrypto.digest("SHA-1", randBuffer)
				op.onerror = function (e) {
					error = "ERROR :: " + e.target.result;
				};
				op.oncomplete = function (e) {
					complete = true;
					result = e.target.result;
				};
			});

			waitsFor(function () {
				return error || complete;
			});

			runs(function () {
				expect(error).toBeUndefined();
				expect(complete).toBeTruthy();
				
				console.log("The randomStr(in hex) before in SHA1 " + abv2hex(randBuffer));
				console.log("The randomStr after SHA1 " + abv2hex(result));
				output += "RandomBuffer: " + abv2hex(randBuffer) + "^";
				output += "SHA1: " + abv2hex(result) + "^";
				var correctStrings = output.split("^");
							
				var response = $.ajax({
					type: "GET",
			        url: "save_contents.php?filename="+"DigestStressSHA1"+"&contents="+correctStrings,
			        async: false,
			        success: function(text, status) {
			        	console.log(" Was able to post successfully " + text);
			        },
			        error: function (xhr, ajaxOptions, thrownError) {
			        	console.log("Was NOT able to post successfully: xhr status " +  xhr.status + " error " + thrownError);
			        }
			    });
			});
		});//end of it("DigestStressSHA1")
	}
	for(OPINDEX = 0; OPINDEX < 2; OPINDEX++) {	
		console.log("Calling wrapperForTest " + OPINDEX);
		wrapperForTest(OPINDEX);
	}
})//describe("Digest")


describe("StressSHA256", function () {
	var OPINDEX = 0;
	
	function wrapperForTest(OPINDEX) {
		it("DigestStressSHA256", function () {
			
			var op, result, error, complete;
			
			console.log("DigestStressSHA256 called this many times " + OPINDEX);
			var output = "DigestStressSHA256 called this many times: " + OPINDEX + "^";
			
		
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
				op = nfCrypto.digest("SHA-256", randBuffer)
				op.onerror = function (e) {
					error = "ERROR :: " + e.target.result;
				};
				op.oncomplete = function (e) {
					complete = true;
					result = e.target.result;
				};
			});

			waitsFor(function () {
				return error || complete;
			});

			runs(function () {
				expect(error).toBeUndefined();
				expect(complete).toBeTruthy();
				console.log("The randomStr(in hex) before in SHA256 " + abv2hex(randBuffer));
				console.log("The randomStr after SHA256 " + abv2hex(result));
				
				output += "RandomBuffer: " + abv2hex(randBuffer) + "^";
				output += "SHA256: " + abv2hex(result) + "^";
				var correctStrings = output.split("^");
							
				var response = $.ajax({
					type: "GET",
			        url: "save_contents.php?filename="+"DigestStressSHA256"+"&contents="+correctStrings,
			        async: false,
			        success: function(text, status) {
			        	console.log(" Was able to post successfully " + text);
			        },
			        error: function (xhr, ajaxOptions, thrownError) {
			        	console.log("Was NOT able to post successfully: xhr status " +  xhr.status + " error " + thrownError);
			        }
			    });
			});
		});//end of it("DigestStressSHA256")
	}
	for(OPINDEX = 0; OPINDEX < 2; OPINDEX++) {	
		console.log("Calling wrapperForTest " + OPINDEX);
		wrapperForTest(OPINDEX);
	}
})//describe("Digest")

describe("StressSHA512", function () {
	var OPINDEX = 0;
	
	function wrapperForTest(OPINDEX) {
		it("DigestStressSHA512", function () {
			
			var op, result, error, complete;
			console.log("DigestStressSHA512 called this many times " + OPINDEX);
			var output = "DigestStressSHA512 called this many times: " + OPINDEX + "^";
		
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
				op = nfCrypto.digest("SHA-512", randBuffer)
				op.onerror = function (e) {
					error = "ERROR :: " + e.target.result;
				};
				op.oncomplete = function (e) {
					complete = true;
					result = e.target.result;
				};
			});

			waitsFor(function () {
				return error || complete;
			});

			runs(function () {
				expect(error).toBeUndefined();
				expect(complete).toBeTruthy();
				console.log("The randomStr(in hex) before in SHA512 " + abv2hex(randBuffer));
				console.log("The randomStr after SHA512 " + abv2hex(result));
				
				output += "RandomBuffer: " + abv2hex(randBuffer) + "^";
				output += "SHA512: " + abv2hex(result) + "^";
				var correctStrings = output.split("^");
							
				var response = $.ajax({
					type: "GET",
			        url: "save_contents.php?filename="+"DigestStressSHA512"+"&contents="+correctStrings,
			        async: false,
			        success: function(text, status) {
			        	console.log(" Was able to post successfully " + text);
			        },
			        error: function (xhr, ajaxOptions, thrownError) {
			        	console.log("Was NOT able to post successfully: xhr status " +  xhr.status + " error " + thrownError);
			        }
			    });
			});
		});//end of it("DigestStressSHA512")
	}
	for(OPINDEX = 0; OPINDEX < 2; OPINDEX++) {	
		console.log("Calling wrapperForTest " + OPINDEX);
		wrapperForTest(OPINDEX);
	}
})//describe("Digest")
