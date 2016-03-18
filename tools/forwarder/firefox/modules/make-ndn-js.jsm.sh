#!/bin/sh
# A hack to remove the last two lines of the file which is Dexie.
cp ../../../../build/ndn.js ndn-no-Dexie.js
sed -i '' '$d' ndn-no-Dexie.js
sed -i '' '$d' ndn-no-Dexie.js
cat ndn-js-header.txt ndn-no-Dexie.js ../../../../js/transport/xpcom-transport.js > ndn-js.jsm
rm ndn-no-Dexie.js
