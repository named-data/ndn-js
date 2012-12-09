#!/bin/sh
cd modules; ./make-ndn-js.jsm.sh; cd .. ; zip -r ../ndnProtocol.xpi .
