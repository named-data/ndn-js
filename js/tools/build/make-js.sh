#!/bin/sh

rm ndn-js-uncomp.js

cat ../../Closure.js \
  ../../NDN.js \
  ../../WebSocketTransport.js \
  ../../util/CCNProtocolDTags.js \
  ../../util/CCNTime.js \
  ../../Name.js \
  ../../ContentObject.js \
  ../../encoding/DateFormat.js \
  ../../Interest.js \
  ../../Key.js \
  ../../PublisherID.js \
  ../../PublisherPublicKeyDigest.js \
  ../../FaceInstance.js \
  ../../ForwardingEntry.js \
  ../../encoding/BinaryXMLEncoder.js \
  ../../encoding/BinaryXMLDecoder.js \
  ../../encoding/BinaryXMLStructureDecoder.js \
  ../../encoding/DataUtils.js \
  ../../encoding/EncodingUtils.js \
  ../../security/KeyManager.js \
  ../../securityLib/sha256.js \
  ../../securityLib/base64.js \
  ../../securityLib/rsa.js \
  ../../securityLib/rsa2.js \
  ../../securityLib/rsapem-1.1.js \
  ../../securityLib/rsasign-1.2.js \
  ../../securityLib/asn1hex-1.1.js \
  ../../securityLib/jsbn.js \
  ../../securityLib/jsbn2.js \
  > ndn-js-uncomp.js

java -jar compiler/compiler.jar --js ndn-js-uncomp.js --js_output_file ndn-js.js