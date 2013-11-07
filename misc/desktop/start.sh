#!/bin/bash

PWD=`pwd`
PLUGINHOME="$PWD"
INFO_FILE="$PLUGINHOME/nfwebcrypto.info"

export LD_LIBRARY_PATH="$PLUGINHOME"

# Assemble the chrome command line.

CHROME="/opt/google/chrome/chrome"

# This snippet was copied from /sbin/session_manager_setup.sh on Chrome OS.
# It parses data from the .info file to put into the command line to register
# the plugin, including making the version number and other info visible
# visible in chrome://plugins
FILE_NAME=
PLUGIN_NAME=
DESCRIPTION=
VERSION=
MIME_TYPES=
. $INFO_FILE
PLUGIN_STRING="${PLUGIN}${FILE_NAME}"
if [ -n "$PLUGIN_NAME" ]; then
    PLUGIN_STRING="${PLUGIN_STRING}#${PLUGIN_NAME}"
    PLUGIN_STRING="${PLUGIN_STRING}#"
    [ -n "$VERSION" ] && PLUGIN_STRING="${PLUGIN_STRING}#${VERSION}"
fi
PLUGIN_STRING="${PLUGIN_STRING};${MIME_TYPES}"
REGISTER_PLUGINS="${REGISTER_PLUGINS}${COMMA}${PLUGIN_STRING}"
COMMA=","
# end snippet

# NOTE: Can't put "CrOS" in user agent or else chrome://plugins won't work (known chrome bug)
USERAGENT="Mozilla/5.0 (X11; CrOS armv7l 2876.0.0) AppleWebKit/537.10 (KHTML, like Gecko) Chrome/30.0.1262.2 Safari/537.10"

#URL="http://localhost/nfwebcrypto/test_qa.html?spec=SignVerifyRSA%20SignVerifyLargeData.#"
URL="http://netflix.github.io/NfWebCrypto/web/test_qa.html"

OPT=(
--register-pepper-plugins=$REGISTER_PLUGINS
--profile-directory="nfwc"
--ppapi-out-of-process
--user-agent="$USERAGENT"
)
#--enable-dcheck
#--enable-accelerated-plugins
#--enable-logging
#--user-agent="$USERAGENT"

# Finally, echo and then run the command to launch chrome
echo $CHROME "${OPT[@]}" "$URL"
$CHROME "${OPT[@]}" "$URL"
