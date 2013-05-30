#!/bin/bash

mkdir -p ~/nfcrypt

PLUGIN_PATH=~/nfcrypt/libnfwebcrypto.so

wget http://cadmium.netflix.com/cadmium/dev/Plugin/NfWebCrypto/linux/debug/Latest/libnfwebcrypto.so --output-document=$PLUGIN_PATH

google-chrome --register-pepper-plugins="$PLUGIN_PATH#Netflix##1.0.3;application/x-ppapi-nfwebcrypto" --ppapi-out-of-process http://cadmium.netflix.com/cadmium/dev/Plugin/NfWebCrypto/linux/debug/Latest/test.html