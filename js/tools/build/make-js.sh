#!/bin/sh

rm ndn-js-uncomp.js

cat ../../Closure.js \
  ../../WebSocketTransport.js \
  ../../util/CCNProtocolDTags.js \
  ../../util/CCNTime.js \
  ../../util/ExponentialReExpressClosure.js \
  ../../Name.js \
  ../../ContentObject.js \
  ../../encoding/DateFormat.js \
  ../../Interest.js \
  ../../Key.js \
  ../../PublisherID.js \
  ../../PublisherPublicKeyDigest.js \
  ../../FaceInstance.js \
  ../../ForwardingEntry.js \
  ../../encoding/DynamicUint8Array.js \
  ../../encoding/BinaryXMLEncoder.js \
  ../../encoding/BinaryXMLDecoder.js \
  ../../encoding/BinaryXMLStructureDecoder.js \
  ../../encoding/DataUtils.js \
  ../../encoding/EncodingUtils.js \
  ../../security/KeyManager.js \
  ../../security/Witness.js \
  ../../securityLib/sha256.js \
  ../../securityLib/base64.js \
  ../../securityLib/rsa.js \
  ../../securityLib/rsa2.js \
  ../../securityLib/rsapem-1.1.js \
  ../../securityLib/rsasign-1.2.js \
  ../../securityLib/asn1hex-1.1.js \
  ../../securityLib/x509-1.1.js \
  ../../securityLib/jsbn.js \
  ../../securityLib/jsbn2.js \
  ../../NDN.js \
  > ndn-js-uncomp.js

java -jar compiler/compiler.jar --js ndn-js-uncomp.js --js_output_file ndn-js.js
