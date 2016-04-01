#!/bin/sh
cp ../../build/ndn.js extension
cd extension; zip -r ../ndn-micro-forwarder.xpi . ; cd ..
