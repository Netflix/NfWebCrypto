var nfCrypto = {};

(function () {
  'use strict';

  var TARGET_DOMAIN = 'https://secure.netflix.com';
  var IFRAME_URL = TARGET_DOMAIN + '/us/ffe/player/webCryptoIframe/nfcrypto-iframe-inner-2162229.html'; 
  var LOAD_TIMEOUT = 8000;  // 8 seconds to load IFrame or else it's an error.
  var lastId = 0;
  var messageHandlers = [];

  var getNewId = function() {
    return ++lastId;
  };

  // A Promise that fulfills when the host document is loaded.
  var loadDocument = new Promise(function(resolve) {
    function onDOMContentLoaded() {
      document.removeEventListener('DOMContentLoaded', onDOMContentLoaded);
      resolve();
    }
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', onDOMContentLoaded);
    } else {
      resolve();
    }
  });

/*
  // A Promise that settles when a test img is loaded.
  var IMAGE_URL = TARGET_DOMAIN + '/webcryptoframe/1x1.gif';
  var loadImage = loadDocument
  .then(function() {
    return new Promise(function(resolve, reject) {
      function onload(event) {
        if (this.naturalHeight + this.naturalWidth === 0) {
          this.onerror(event);
        } else {
          resolve();
        }
      }
      function onerror(event) {
        reject(Error('error loading test image'));
      }
      var img = document.createElement('img');
      img.onload = onload;
      img.onerror = onerror;
      img.setAttribute('src', IMAGE_URL);  // This kicks off the img load
    });
  });
*/

  // A Promise that settles when an async XHR of the IFrame src completes.
  var doXhr = loadDocument
  .then(function() {
    return new Promise(function(resolve, reject) {
      var req = new XMLHttpRequest();
      req.open('GET', IFRAME_URL, true);
      req.onload = function() {
        if (req.status == 200) {
          resolve(req.response);
        } else {
          reject(Error('http error ' + req.statusText));
        }
      };
      req.onerror = function() {
        reject(Error('http error ' + req.statusText));
      };
      req.send();
    });
  });

  // A Promise that fulfills when the IFrame is loaded, or else rejects if doXhr
  // rejects or a timeout occurs before the loaded IFrame sends a 'ready'
  // message.
  var loadIframe = loadDocument
  .then(function() {
    return new Promise(function(resolve, reject) {
      var iframe = document.createElement('iframe');
      iframe.setAttribute('src', IFRAME_URL);
      iframe.setAttribute('style', 'display:none');
      iframe.height = 1;
      iframe.width = 1;
      // Reject if no 'ready' message is received from the iframe whithin timeout.
      var timeout = window.setTimeout(function() {
        reject(Error('timeout waiting for iframe to load'));
      }, LOAD_TIMEOUT);
      // Also reject if doXhr rejects. We are not interested in whether doXhr
      // resolves because the 'ready' message from the IFrame is the ultimate
      // goal.
      doXhr.catch(reject); // FIXME: Should have delayed reject in case the real iframe resolves later?
      function onMessage(event) {
        if (event.data == 'ready') {
          window.clearTimeout(timeout);
          resolve(iframe);
        }
        window.removeEventListener('message', onMessage);
        window.addEventListener('message', onIframeMessage);
      }
      window.addEventListener('message', onMessage);
      document.body.appendChild(iframe);  // This kicks off the IFrame load
    });
  });

  // Invokes a command in the IFrame once the IFrame is initialized.
  function invoke(cmd, args) {
    return loadIframe
    .then(function(iframe) {
      return new Promise(function(resolve, reject) {
        var message = {
            cmd: cmd,
            msgId: getNewId(),
            arguments: args,
        };
        function onMessage(event) {
          var msg = event.data;
          msg.success ? resolve(msg.result) : reject(msg.result);
        }
        // Send a message to the IFrame to invoke the desired command there. The
        // result will be sent back some time later, received by |onIframeMessage|,
        // and dispatched to this Promise's |onMessage| via a lookup on
        // |messageHandlers|.
        messageHandlers.push({
          msgId:message.msgId,
          handler:onMessage,
        });
        iframe.contentWindow.postMessage(message, TARGET_DOMAIN);
      });
    });
  }

  // Central handler for messages from the IFrame. Validates the message,
  // dispatches the correct message handler by |event.data.msgId|, and removes
  // the spent handler from |messageHandlers|.
  function onIframeMessage(event) {
    var handler;
    var idx = messageHandlers.length;
    while (idx--) {
      if (messageHandlers[idx].msgId === event.data.msgId) {
        break;
      };
    }
    if (idx < 0 || !validateMessage(event)) {
      return;
    }
    handler = messageHandlers[idx].handler;
    messageHandlers.splice(idx, 1);
    handler(event);
  }

  // Validates a message from the IFrame by ensuring the message is from the
  // expected origin and has the required fields.
  function validateMessage(event) {
    var data = event.data;
    return (event.origin === TARGET_DOMAIN) &&
            data &&
            data.hasOwnProperty('success') &&
            data.hasOwnProperty('result') &&
            data.hasOwnProperty('msgId');
  }

  // Exported methods on |nfCrypto|
  if (window.crypto.getRandomValues) {
    nfCrypto.getRandomValues = function(a) {
      return window.crypto.getRandomValues(a);
    };
  }
  nfCrypto.subtle = {};
  [
    'encrypt',
    'decrypt',
    'sign',
    'verify',
    'digest',
    'generateKey',
    'deriveKey',
    'deriveBits',
    'importKey',
    'exportKey',
    'wrapKey',
    'unwrapKey'
  ].map(function(command) {
    nfCrypto.subtle[command] = function() {
      return invoke(command, Array.prototype.slice.call(arguments));
    };
  });

})();
