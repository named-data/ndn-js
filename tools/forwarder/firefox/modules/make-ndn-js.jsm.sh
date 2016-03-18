#!/bin/sh
# A hack to remove the last two lines of the file which is Dexie.
cp ../../../../build/ndn.js /tmp/ndn-no-Dexie.js
sed -i '' '$d' /tmp/ndn-no-Dexie.js
sed -i '' '$d' /tmp/ndn-no-Dexie.js
cat ndn-js-header.txt /tmp/ndn-no-Dexie.js ../../../../js/transport/xpcom-transport.js > ndn-js.jsm
