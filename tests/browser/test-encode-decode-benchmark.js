var Name = require('../..').Name;
var Data = require('../..').Data;
var MetaInfo = require('../..').MetaInfo;
var KeyLocator = require('../..').KeyLocator;
var KeyLocatorType = require('../..').KeyLocatorType;
var KeyName = require('../..').KeyName;
var PublisherPublicKeyDigest = require('../..').PublisherPublicKeyDigest;
var NDNTime = require('../..').NDNTime;
var globalKeyManager = require('../..').globalKeyManager;

var TestEncodeDecodeBenchmark = function TestEncodeDecodeBenchmark() 
{
};

exports.TestEncodeDecodeBenchmark = TestEncodeDecodeBenchmark;

function getNowSeconds()
{
  return new Date().getTime() / 1000.0;
}

/**
 * Loop to encode a data packet nIterations times.
 * @param {number} nIterations The number of iterations.
 * @param {boolean} useComplex If true, use a large name, large content and all fields.  If false, use a small name, small content
 * and only required fields.
 * @param {boolean} useCrypto If true, sign the data packet.  If false, use a blank signature.
 * @param {Array<Buffer>} encoding Set encoding[0] to the wire encoding.
 * @return {number} The number of seconds for all iterations.
 */
TestEncodeDecodeBenchmark.benchmarkEncodeDataSeconds = function(nIterations, useComplex, useCrypto, encoding)
{
  var name;
  var content;
  if (useComplex) {
    // Use a large name and content.
    name = new Name("/ndn/ucla.edu/apps/lwndn-test/numbers.txt/%FD%05%05%E8%0C%CE%1D/%00"); 

    var contentString = "";
    var count = 1;
    contentString += "" + (count++);
    while (contentString.length < 1170)
      contentString += " " + (count++);
    content = new Buffer(contentString);
  }
  else {
    // Use a small name and content.
    name = new Name("/test");
    content = new Buffer("abc");
  }
  var finalBlockId = new Buffer("\0");

  /*
  // Initialize the KeyChain storage in case useCrypto is true.
  shared_ptr<MemoryIdentityStorage> identityStorage(new MemoryIdentityStorage());
  shared_ptr<MemoryPrivateKeyStorage> privateKeyStorage(new MemoryPrivateKeyStorage());
  KeyChain keyChain
    (make_shared<IdentityManager>(identityStorage, privateKeyStorage), 
     make_shared<SelfVerifyPolicyManager>(identityStorage.get()));
  */
  var keyName = new Name("/testname/DSK-123");
  var certificateName = keyName.getSubName(0, keyName.size() - 1).append("KEY").append
    (keyName.get(keyName.size() - 1)).append("ID-CERT").append("0");
  /*
  privateKeyStorage->setKeyPairForKeyName
    (keyName, DEFAULT_PUBLIC_KEY_DER, sizeof(DEFAULT_PUBLIC_KEY_DER), DEFAULT_PRIVATE_KEY_DER, sizeof(DEFAULT_PRIVATE_KEY_DER));
  */

  // Set up publisherPublicKeyDigest and signatureBits in case useCrypto is false.
  var publisherPublicKeyDigest = new Buffer(32);
  for (var i = 0; i < publisherPublicKeyDigest.length; ++i)
    publisherPublicKeyDigest[i] = 0;
  var signatureBits = new Buffer(128);
  for (var i = 0; i < signatureBits.length; ++i)
    signatureBits[i] = 0;

  var start = getNowSeconds();
  for (var i = 0; i < nIterations; ++i) {
    var data = new Data(name);
    data.setContent(content);
    data.signedInfo = new MetaInfo();
    if (useComplex) {
      // timestamp is deprecated.
      data.getMetaInfo().timestamp = new NDNTime(1.3e+12);
      data.getMetaInfo().setFreshnessPeriod(30000);
      data.getMetaInfo().setFinalBlockID(finalBlockId);
    }

    var keyLocator = new KeyLocator();    
    keyLocator.setType(KeyLocatorType.KEYNAME);
    keyLocator.setKeyName(certificateName);
    data.getSignature().setKeyLocator(keyLocator);
    // publisherPublicKeyDigest is deprecated.
    data.getMetaInfo().publisher = new PublisherPublicKeyDigest(publisherPublicKeyDigest);
    if (useCrypto)
      data.sign();
    else
      // Set the signature, but don't sign.
      data.signature.signature = signatureBits;

    encoding[0] = data.wireEncode().buf();
  }
  var finish = getNowSeconds();

  return finish - start;    
}

/**
 * Loop to decode a data packet nIterations times.
 * @param {number} nIterations The number of times to decode.
 * @param {boolean} useCrypto If true, verify the signature.  If false, don't verify.
 * @param {Buffer} encoding The encoded data packet to decode.
 * @returns {number} The number of seconds for the benchmark.
 */
TestEncodeDecodeBenchmark.benchmarkDecodeDataSeconds = function(nIterations, useCrypto, encoding)
{
  var start = getNowSeconds();
  for (var i = 0; i < nIterations; ++i) {
    var data = new Data();
    data.wireDecode(encoding);
    
    if (useCrypto) {
      if (!data.verify(globalKeyManager.key))
        throw new Error("Signature verification: FAILED");
    }
  }
  var finish = getNowSeconds();

  return finish - start;  
};
