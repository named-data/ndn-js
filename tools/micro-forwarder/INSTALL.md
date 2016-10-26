Micro Forwarder: A light-weight forwarder in the browser based on NDN-JS
========================================================================

Native Messaging for multicast
==============================

Native Messaging allows a browser to use an authorized application on the computer.
The Micro Forwarder uses the ndn_multicast.py application to send and receive
packets in the NDN multicast group. To authorize it, follow these steps for your platform.

## Firefox on macOS

Native Messaging requires Firefox 50. In a terminal change directory to
`ndn-js/tools/micro-forwarder` . Enter:

    mkdir -p ~/Library/Application\ Support/Mozilla/NativeMessagingHosts
    cp ndn_multicast.json ~/Library/Application\ Support/Mozilla/NativeMessagingHosts

Edit `~/Library/Application\ Support/Mozilla/NativeMessagingHosts/ndn_multicast.json` and
change the line

    "path": "ndn-js/tools/micro-forwarder/ndn_multicast.py",

to have the full path of the ndn-js project. For example:

    "path": "/Users/username/ndn-js/tools/micro-forwarder/ndn_multicast.py",

Installing during development
=============================

To install the Micro Forwarder extension during development, in a terminal change
directory to `ndn-js/tools/micro-forwarder` . Enter:

    ./make-ndn-micro-forwarder.sh

This copies ndn.js from the build directory so that the extension can use it.

## Firefox

In the Firefox address bar, enter `about:debugging` . Click "Load Temporary Add-on".
Browse to the directory `ndn-js/tools/micro-forwarder/extension` and click
`manifest.json` .
