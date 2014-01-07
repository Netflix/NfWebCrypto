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

/*
Some of the code in this one source file borrows from PolyCrypt (polycrypt.net).
A big thank you to the folks at Raytheon BBN Technologies for providing source
inspiration for this javascript-challenged programmer.

The PolyCrypt license follows:

Copyright (C) Raytheon BBN Technologies Corp. 2013 All Rights Reserved.

Development of this software program, WHAC, is sponsored by the Cyber Security
Division of the United States Department of Homeland Security's Science and
Technology Directorate. 

This software is licensed pursuant to the following license terms and
conditions: Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
(1) Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer. (2) Redistributions in binary
form must reproduce the above copyright notice, this list of conditions and the
following disclaimer in the documentation and/or other materials provided with
the distribution. (3) Neither the name of Raytheon BBN Technologies Corp. nor
the names of its contributors may be used to endorse or promote products derived
from this software without specific prior written permission. 

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS  "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT  LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 

End of (PolyCrypt) License Terms and Conditions.
*/

(function (window) {
    'use strict';

    var operationId = 0,
        that = {};

    //--------------------------------------------------------------------------
    // bridge for talking to the native code via post/handle message

    var bridge = {

        pendingPosts: [],
        messageHandlers: [],

        // start out by accumulating the posts, 
        // this will be replaced once bridge is ready, to post to actual bridge
        postMessage: function postMessage(messageJson) {
            this.pendingPosts.push(messageJson);
        },

        addMessageHandler: function addMessageHandler(handler) {
            this.messageHandlers.push(handler);
        },

        removeMessageHandler: function removeMessageHandler(handler) {
            var messageHandlers = this.messageHandlers;
            var index = messageHandlers.lastIndexOf(handler);
            if (index >= 0) {
                messageHandlers.splice(index, 1);
            }
        },

        dispatchMessageHandlers: function dispatchMessageHandlers(messageJson) {
            // make a copy, to cover the scenario of "removeMessageHandler" being called from inside the handler
            var handlers = this.messageHandlers.slice();
            var length = handlers.length;
            for (var i = 0; i < length; i++) {
                handlers[i](messageJson);
            }
        },

        // wires the post message to actual plugin
        wirePostMessage: function (realPostMessage) {
            // grab the pending posts
            var pendingPosts = this.pendingPosts;
            this.pendingPosts = undefined;

            // re-wire the post message function
            this.postMessage = realPostMessage;

            // replay accumulated message posts
            for (var i = 0; i < pendingPosts.length; i++) {
                this.postMessage(pendingPosts[i]);
            }
        }

    };

    //--------------------------------------------------------------------------
    // wire the bridge

    if (!tryLoadPlugin()) {
        // nothing to wire the bridge to...

        // don't throw inline, not to block further scripts from executing
        window.setTimeout(function () {
            throw new Error('NfWebCrypto plugin not found, unable to create nfCrypt');
        }, 0);
        return;

    }

    // public api root
    // TODO: remove the methods from nfCrypto, they should only be on nfCrypto.subtle
    window.nfCrypto = that;
    window.nfCrypto.subtle = that;
    window.nfCryptoKeys = that;

    //--------------------------------------------------------------------------

    /*** Convert an arbitrary ArrayBufferView to a Uint8Array ***/
    var abv2u8 = function (abv) {
        return new Uint8Array(abv.buffer, abv.byteOffset, abv.byteLength);
    }

    /*** Convert between ArrayBufferView and Base64url encoding ***/
    var b64a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    var b64encode = function (abv) {
        var u8 = abv2u8(abv);
        var b64 = "";

        var i = 0;
        while (i < u8.length - 2) {
            var x1 = u8[i++], x2 = u8[i++], x3 = u8[i++];
            b64 += b64a.charAt(x1 >> 2) +
                 b64a.charAt(((x1 & 3) << 4) | (x2 >> 4)) +
                 b64a.charAt(((x2 & 15) << 2) | (x3 >> 6)) +
                 b64a.charAt(x3 & 63);
        }
        if (i === u8.length - 2) {
            var x1 = u8[i++], x2 = u8[i++];
            b64 += b64a.charAt(x1 >> 2) +
                 b64a.charAt(((x1 & 3) << 4) | (x2 >> 4)) +
                 b64a.charAt(((x2 & 15) << 2)) +
                 "=";
        } else if (i === u8.length - 1) {
            var x1 = u8[i++];
            b64 += b64a.charAt(x1 >> 2) +
                 b64a.charAt(((x1 & 3) << 4)) +
                 "==";
        }

        return b64;
    }

    var b64decode = function (b64) {
        var u8 = [];
        b64 = b64.replace(/[^A-Za-z0-9\=\/\+]/g, "");

        var i = 0;
        while (i < b64.length) {
            var x1 = b64a.indexOf(b64[i++]);
            var x2 = b64a.indexOf(b64[i++]);
            var x3 = b64a.indexOf(b64[i++]);
            var x4 = b64a.indexOf(b64[i++]);

            var y1 = (x1 << 2) | (x2 >> 4);
            var y2 = ((x2 & 15) << 4) | (x3 >> 2);
            var y3 = ((x3 & 3) << 6) | x4;

            u8.push(y1);
            if (0 <= x3 && x3 < 64) { u8.push(y2); }
            if (0 <= x4 && x4 < 64) { u8.push(y3); }
        }

        return new Uint8Array(u8);
    }

    //--------------------------------------------------------------------------
    var createPluginDelegate = function (op, setResult) {
        var that = {},
            listeners = {},
            lastEvent = {},
            myOpid = operationId++;

        // ---- DOM4 EventTarget begin

        var addEventListener = function (type, listener, useCapture) {
            // (ignore useCapture)
            //console.log("TRACE addEventListener enter");
            if (!(type in listeners)) {
                listeners[type] = [];
            }
            listeners[type].push(listener);
            // Events are cached to allow deferred listener registration, one
            // event per event type. Here, when a listener is registered, if
            // there is a cached event, the listener is fired immediately with
            // the cached event.  This allows listeners to be registered after
            // an event has arrived, avoiding certain race conditions.
            if (lastEvent[type]) {
                _fireListener(listener, lastEvent[type]);
                // no need to clear cache, as we want any future added listener
                // also to be notified of the last event that happened
            }
        };
        that.addEventListener = addEventListener;

        var removeEventListener = function (type, listener, useCapture) {
            //console.log("TRACE removeEventListener enter");
            //console.log("ERROR removeEventListener not implemented");
        };
        that.removeEventListener = removeEventListener;

        var dispatchEvent = function (e) {
            //console.log("TRACE dispatchEvent enter");
            var listenersForEvent = listeners[e.type];
            for (var l in listenersForEvent) {
            	if (listenersForEvent.hasOwnProperty(l)) {
            	    _fireListener(listenersForEvent[l], e);
            	}
            }
            // Cache the latest event received of each type
            lastEvent[e.type] = e;
        };
        that.dispatchEvent = dispatchEvent;

        // listeners may be either DOM4 EventListener objects or just functions
        // that take the event as its argument
        var _fireListener = function (listener, e) {
            //console.log("TRACE _fireListener enter");
            var typeofListener = typeof (listener);
            if (typeofListener === 'function') {
                listener(e);
            } else if ((typeofListener === 'object') &&
                listener.hasOwnProperty('handleEvent') &&
                (typeof (listener.handleEvent) === 'function')) {
                listener.handleEvent(e);
            } else {
                console.log("ERROR listener of unknown type ", typeof (listener));
                console.log(listener);
            }
        };

        // ---- DOM4 EventTarget end

        // handler for messages coming FROM the plugin
        var _handleMessage = function (data) {
            if (data.idx != myOpid) {
                return; // message not for me
            }
            //console.log("TRACE _handleMessage enter");
            //console.log(message.data);
            bridge.removeMessageHandler(_handleMessage);
            var event = {};
            event.target = op;
            if (data.success == false) {
                event.type = 'error';
                setResult(data.errorMessage);
            } else {
                // when there is no deviceID, the plugin returns Base64-encoded, Base32-encoded zeros
                if ( (data.method == "getDeviceId") && (data.payload.buffer == "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ==") ) {
                    event.type = 'error';
                    setResult("device ID not found");
                } else {
                    if (data.payload.hasOwnProperty('buffer')) {
                        var dataBin = b64decode(data.payload.buffer);
                        data.payload = dataBin;
                    }
                    event.type = 'complete';
                    setResult(data.payload);
                }
            }
            that.dispatchEvent(event);
        };

        // Register for events coming back
        bridge.addMessageHandler(_handleMessage);

        // send messages TO the plugin
        var postMessage = function (method, args) {
            //console.log("TRACE postMessage enter");
            var msg = {
                idx: myOpid,
                method: method,
                argsObj: args
            }
            bridge.postMessage(msg);
        };
        that.postMessage = postMessage;

        return that;
    };
    //--------------------------------------------------------------------------


    //--------------------------------------------------------------------------
    var createCryptoOp = function (type, algorithm, key, signature, buffer) {
        //console.log("TRACE createCryptoOp enter");

        var op = {};
        var result = null;
        var messenger = createPluginDelegate(op, function (x) { result = x; });


        op.addEventListener = function (type, listener, useCapture) {
            messenger.addEventListener(type, listener, useCapture);
        };
        op.removeEventListener = function (type, listener) {
            messenger.removeEventListener(type, listener);
        };
        op.dispatchEvent = function (e) { messenger.dispatchEvent(e); };

        // define the CryptoOperation interface
        // attributes
        Object.defineProperty(op, 'algorithm', {
            enumerable: true,
            get: function get() { return algorithm; }
        });
        Object.defineProperty(op, 'key', {
            enumerable: true,
            get: function get() { return key; }
        });
        Object.defineProperty(op, 'result', {
            enumerable: true,
            get: function get() { return result; }
        });

        // the methods of the CryptoOperation interface (NOT IMPLEMENTED)
        op.process = function (buffer) { }
        op.finish = function () { }
        op.abort = function () { }

        // callback methods
        Object.defineProperty(op, 'onabort', {
            enumerable: true,
            configurable: false,
            set: function (listener) {
                op.addEventListener('abort', listener, false);
            }
        });

        Object.defineProperty(op, 'onerror', {
            enumerable: true,
            configurable: false,
            set: function (listener) {
                op.addEventListener('error', listener, false);
            }
        });

        Object.defineProperty(op, 'onprogress', {
            enumerable: true,
            configurable: false,
            set: function (listener) {
                op.addEventListener('progress', listener, false);
            }
        });

        Object.defineProperty(op, 'oncomplete', {
            enumerable: true,
            configurable: true,
            set: function (listener) {
                op.addEventListener('complete', listener, false);
            }
        });

        // Post the message to the plugin
        var args = {
            algorithm: algorithm,
            keyHandle: (key == null) ? key : key.handle,
            signature: (signature == null) ? signature : b64encode(signature),
            buffer: (buffer == null) ? buffer : b64encode(buffer),
        };
        messenger.postMessage(type, args);

        return op;
    };

    //--------------------------------------------------------------------------
    var createKeyOp = function (type, format, keyData, algorithm,
            extractable, keyUsage, baseKey, derivedKeyType, key, keyName) {

        var op = {},
        result = null,
        messenger = createPluginDelegate(op, function (x) { result = x; });

        op.addEventListener = function (type, listener, useCapture) {
            messenger.addEventListener(type, listener, useCapture);
        };
        op.removeEventListener = function (type, listener) {
            messenger.removeEventListener(type, listener);
        };
        op.dispatchEvent = function (e) { messenger.dispatchEvent(e); };

        // define the KeyOperation interface
        // attributes
        Object.defineProperty(op, 'result', {
            enumerable: true,
            get: function get() { return result; }
        });

        // callback methods
        Object.defineProperty(op, 'onerror', {
            enumerable: true,
            configurable: false,
            set: function (listener) {
                op.addEventListener('error', listener, false);
            }
        });

        Object.defineProperty(op, 'oncomplete', {
            enumerable: true,
            configurable: true,
            set: function (listener) {
                op.addEventListener('complete', listener, false);
            }
        });

        // Post the message to the plugin
        var args = {
            format: format,
            keyData: keyData && b64encode(keyData),
            algorithm: algorithm,
            extractable: extractable,
            keyUsage: keyUsage,
            baseKeyHandle: (baseKey == null) ? baseKey : baseKey.handle,
            derivedAlgorithm : derivedKeyType,
            keyHandle: (key == null) ? key : key.handle,
            keyName: keyName,
        };
        messenger.postMessage(type, args);

        return op;
    };

    //--------------------------------------------------------------------------
    function copy(buffer)
    {
        var bytes = new Uint8Array(buffer);
        var output = new ArrayBuffer(buffer.byteLength);
        var outputBytes = new Uint8Array(output);
        for (var i = 0; i < bytes.length; i++)
            outputBytes[i] = bytes[i];
        return outputBytes;
    }
    
    Object.prototype.clone = function() {
        var newObj;
        if (this instanceof Uint8Array) {
            newObj = copy(this);
        } else {
            if (this instanceof Array) {
                newObj = [];
            } else {
                newObj = {};
            }
            for (i in this) {
              if (i == 'clone') continue;
              if (this[i] && typeof this[i] == "object") {
                newObj[i] = this[i].clone();
              } else newObj[i] = this[i]
            }
        }
        return newObj;
      };
      
      function fixAlgorithmParams(algorithm) {
          if (algorithm && !algorithm.params) {
              algorithm.params = algorithm.clone();
          } 
      }

    //--------------------------------------------------------------------------
      
    // add wc methods here

    that.digest = function (algorithm, buffer) {
        fixAlgorithmParams(algorithm);
        return createCryptoOp('digest', algorithm, null, null, buffer);
    };

    that.importKey = function (format, keyData, algorithm, extractable, keyUsage) {
        fixAlgorithmParams(algorithm);
        return createKeyOp('import', format, keyData, algorithm, extractable, keyUsage);
    };

    that.exportKey = function (format, key) {
        return createKeyOp('export', format, null, null, null, null, null, null, key);
    };

    that.encrypt = function (algorithm, key, buffer) {
        fixAlgorithmParams(algorithm);
        if (algorithm.hasOwnProperty('params') && algorithm.params.hasOwnProperty("iv")) {
            algorithm.params.iv = b64encode(algorithm.params.iv);
        }
        if (algorithm.hasOwnProperty('params') && algorithm.params.hasOwnProperty("additionalData")) {
            algorithm.params.additionalData = b64encode(algorithm.params.additionalData);
        }
        return createCryptoOp('encrypt', algorithm, key, null, buffer);
    };

    that.decrypt = function (algorithm, key, buffer) {
        fixAlgorithmParams(algorithm);
        if (algorithm.hasOwnProperty('params') && algorithm.params.hasOwnProperty("iv")) {
            algorithm.params.iv = b64encode(algorithm.params.iv);
        }
        if (algorithm.hasOwnProperty('params') && algorithm.params.hasOwnProperty("additionalData")) {
            algorithm.params.additionalData = b64encode(algorithm.params.additionalData);
        }
        return createCryptoOp('decrypt', algorithm, key, null, buffer);
    };

    that.sign = function (algorithm, key, buffer) {
        fixAlgorithmParams(algorithm);
        return createCryptoOp('sign', algorithm, key, null, buffer);
    };

    that.verify = function (algorithm, key, signature, buffer) {
        fixAlgorithmParams(algorithm);
        return createCryptoOp('verify', algorithm, key, signature, buffer);
    };

    that.generateKey = function (algorithm, extractable, keyUsage) {
        fixAlgorithmParams(algorithm);
        var tob64 = ["publicExponent", "prime", "generator"];
        var propName;
        if (algorithm.hasOwnProperty('params')) {
            for (var i = 0; i < tob64.length; i++) {
                propName = tob64[i];
                if (algorithm.params.hasOwnProperty(propName)) {
                    algorithm.params[propName] = b64encode(algorithm.params[propName]);
                }
            }
        }
        return createKeyOp('generate', null, null, algorithm, extractable, keyUsage);
    };

    that.deriveKey = function (algorithm, baseKey, derivedKeyAlgorithm, extractable, keyUsage) {
        fixAlgorithmParams(algorithm);
        if (algorithm.hasOwnProperty('params') && algorithm.params.hasOwnProperty("public")) {
            algorithm.params["public"] = b64encode(algorithm.params["public"]);
        }
        return createKeyOp("derive", null, null, algorithm, extractable, keyUsage, baseKey, derivedKeyAlgorithm, null)
    };

    that.wrapKey = function (keyToWrap, wrappingKey, wrappingAlgorithm) {
        fixAlgorithmParams(wrappingAlgorithm);
        return createKeyOp('wrapKey', null, null, wrappingAlgorithm, null, null, keyToWrap, null, wrappingKey);
    };

    that.unwrapKey = function (jweKeyData, algorithm, wrappingKey, extractable, usage) {
        fixAlgorithmParams(algorithm);
        return createKeyOp('unwrapKey', null, jweKeyData, algorithm, extractable, usage, null, null, wrappingKey);
    };

    that.getRandomValues = function (abv) {
        var l = abv.length;
        while (l--) {
            abv[l] = Math.floor(Math.random() * 256);
        }
        return abv;
    };
    
    that.getDeviceId = function () {
        return createKeyOp('getDeviceId', null, null, null, null, null, null, null, null);
    }
    
    that.getKeyByName = function (keyName) {
        return createKeyOp('getKeyByName', null, null, null, null, null, null, null, null, keyName);
    }

    //--------------------------------------------------------------------------


    //--------------------------------------------------------------------------

    // Once window is loaded... 
    // Load the plugin, start the native code, and wire the bridge to it.

    function tryLoadPlugin() {
        var navPlugin = window.navigator.plugins['NfWebCrypto'] || window.navigator.plugins['NetflixHelper'];
        if (navPlugin) {
            window.addEventListener('load', onLoad);
            return true;
        }

        function onLoad() {
            window.removeEventListener('load', onLoad);

            var pluginObject = window.document.createElement('object');
            pluginObject.setAttribute('type', navPlugin[0].type);
            pluginObject.setAttribute('style', 'position:fixed;left:0;top:0;width:1px;height:1px;visibility:hidden');
            pluginObject.addEventListener('message', onPluginMessage, false);

            function handleReadyMessage(messageJson) {
                if (messageJson.success && messageJson.method === 'ready') {
                    bridge.removeMessageHandler(handleReadyMessage);
                    setTimeout(function () {
                        onPluginReady(pluginObject);
                    }, 1);
                }
            };
            bridge.addMessageHandler(handleReadyMessage);

            // Insert the plugin object into the document body. This starts the
            // native code. This should be done last.
            window.document.body.appendChild(pluginObject);
        };
    };

    function onPluginMessage(e) {
        var messageString = e.data;
        var messageJson = JSON.parse(messageString);
        // console.log('Message from plugin: ' + messageString);
        bridge.dispatchMessageHandlers(messageJson);
    };

    function onPluginReady(pluginObject) {
        bridge.wirePostMessage(function postMessageToPlugin(messageJson) {
            var messageString = JSON.stringify(messageJson);
            // console.log('Message to plugin: ' + messageString);
            pluginObject.postMessage(messageString);
        });
    };

})(window);
