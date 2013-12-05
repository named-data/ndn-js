/**
 * Copyright (C) 2013 Regents of the University of California.
 * @author: Meki Cheraoui
 * See COPYING for copyright and distribution information.
 * This class represents Data Objects
 */

var DataUtils = require('./encoding/data-utils.js').DataUtils;
var Name = require('./name.js').Name;
var BinaryXMLEncoder = require('./encoding/binary-xml-encoder.js').BinaryXMLEncoder;
var BinaryXMLDecoder = require('./encoding/binary-xml-decoder.js').BinaryXMLDecoder;
var NDNProtocolDTags = require('./util/ndn-protoco-id-tags.js').NDNProtocolDTags;
var NDNTime = require('./util/ndn-time.js').NDNTime;
var Key = require('./key.js').Key;
var KeyLocator = require('./key.js').KeyLocator;
var KeyLocatorType = require('./key.js').KeyLocatorType;
var PublisherPublicKeyDigest = require('./publisher-public-key-digest.js').PublisherPublicKeyDigest;
var globalKeyManager = require('./security/key-manager.js').globalKeyManager;
var LOG = require('./log.js').Log.LOG;

/**
 * Create a new Data with the optional values.
 * 
 * @constructor
 * @param {Name} name
 * @param {SignedInfo} signedInfo
 * @param {Buffer} content
 */
var Data = function Data(name, signedInfo, content) 
{
  if (typeof name == 'string')
    this.name = new Name(name);
  else
    //TODO Check the class of name
    this.name = name;
  
  this.signedInfo = signedInfo;
  
  if (typeof content == 'string') 
    this.content = DataUtils.toNumbersFromString(content);
  else 
    this.content = content;
  
  this.signature = new Signature();
  
  this.startSIG = null;
  this.endSIG = null;
  
  this.endContent = null;
  
  this.rawSignatureData = null;
};

exports.Data = Data;

Data.prototype.sign = function() 
{
  var n1 = this.encodeObject(this.name);
  var n2 = this.encodeObject(this.signedInfo);
  var n3 = this.encodeContent();
  
  var rsa = require("crypto").createSign('RSA-SHA256');
  rsa.update(n1);
  rsa.update(n2);
  rsa.update(n3);
    
  var sig = new Buffer(rsa.sign(globalKeyManager.privateKey));

  this.signature.signature = sig;
};

Data.prototype.verify = function(/*Key*/ key) 
{
  if (key == null || key.publicKeyPem == null)
    throw new Error('Cannot verify Data without a public key.');

  var verifier = require('crypto').createVerify('RSA-SHA256');
  verifier.update(this.rawSignatureData);
  return verifier.verify(key.publicKeyPem, this.signature.signature);
};

Data.prototype.encodeObject = function encodeObject(obj) 
{
  var enc = new BinaryXMLEncoder(); 
  obj.to_ndnb(enc);
  var num = enc.getReducedOstream();

  return num;
};

Data.prototype.encodeContent = function encodeContent() 
{
  var enc = new BinaryXMLEncoder();   
  enc.writeElement(NDNProtocolDTags.Content, this.content);
  var num = enc.getReducedOstream();

  return num;
};

Data.prototype.saveRawData = function(bytes) 
{  
  var sigBits = bytes.slice(this.startSIG, this.endSIG);
  this.rawSignatureData = new Buffer(sigBits);
};

Data.prototype.getElementLabel = function() { return NDNProtocolDTags.Data; };

/**
 * Create a new Signature with the optional values.
 * @constructor
 */
var Signature = function Signature(witness, signature, digestAlgorithm) 
{
  this.witness = witness;
  this.signature = signature;
  this.digestAlgorithm = digestAlgorithm
};

exports.Signature = Signature;

Signature.prototype.from_ndnb = function(decoder) 
{
  decoder.readStartElement(this.getElementLabel());
    
  if (LOG > 4) console.log('STARTED DECODING SIGNATURE');
    
  if (decoder.peekStartElement(NDNProtocolDTags.DigestAlgorithm)) {
    if (LOG > 4) console.log('DIGIEST ALGORITHM FOUND');
    this.digestAlgorithm = decoder.readUTF8Element(NDNProtocolDTags.DigestAlgorithm); 
  }
  if (decoder.peekStartElement(NDNProtocolDTags.Witness)) {
    if (LOG > 4) console.log('WITNESS FOUND');
    this.witness = decoder.readBinaryElement(NDNProtocolDTags.Witness); 
  }
    
  //FORCE TO READ A SIGNATURE

  if (LOG > 4) console.log('SIGNATURE FOUND');
  this.signature = decoder.readBinaryElement(NDNProtocolDTags.SignatureBits);

  decoder.readEndElement();
};

Signature.prototype.to_ndnb = function(encoder) 
{      
  if (!this.validate())
    throw new Error("Cannot encode: field values missing.");
  
  encoder.writeElementStartDTag(this.getElementLabel());
  
  if (null != this.digestAlgorithm && !this.digestAlgorithm.equals(NDNDigestHelper.DEFAULT_DIGEST_ALGORITHM))
    encoder.writeElement(NDNProtocolDTags.DigestAlgorithm, OIDLookup.getDigestOID(this.DigestAlgorithm));
  
  if (null != this.witness)
    // needs to handle null witness
    encoder.writeElement(NDNProtocolDTags.Witness, this.witness);

  encoder.writeElement(NDNProtocolDTags.SignatureBits, this.signature);

  encoder.writeElementClose();       
};

Signature.prototype.getElementLabel = function() { return NDNProtocolDTags.Signature; };

Signature.prototype.validate = function() 
{
  return null != this.signature;
};

var ContentType = {DATA:0, ENCR:1, GONE:2, KEY:3, LINK:4, NACK:5};
var ContentTypeValue = {0:0x0C04C0, 1:0x10D091,2:0x18E344,3:0x28463F,4:0x2C834A,5:0x34008A};
var ContentTypeValueReverse = {0x0C04C0:0, 0x10D091:1,0x18E344:2,0x28463F:3,0x2C834A:4,0x34008A:5};

exports.ContentType = ContentType;

/**
 * Create a new SignedInfo with the optional values.
 * @constructor
 */
var SignedInfo = function SignedInfo(publisher, timestamp, type, locator, freshnessSeconds, finalBlockID) 
{
  this.publisher = publisher; //publisherPublicKeyDigest
  this.timestamp=timestamp; // NDN Time
  this.type=type; // ContentType
  this.locator =locator;//KeyLocator
  this.freshnessSeconds =freshnessSeconds; // Integer
  this.finalBlockID=finalBlockID; //byte array
    
  this.setFields();
};

exports.SignedInfo = SignedInfo;

SignedInfo.prototype.setFields = function() 
{
  var key = new Key();
  key.fromPemString(globalKeyManager.publicKey, globalKeyManager.privateKey);
  this.publisher = new PublisherPublicKeyDigest(key.getKeyID());

  var d = new Date();
    
  var time = d.getTime();  

  this.timestamp = new NDNTime(time);
    
  if (LOG > 4) console.log('TIME msec is');

  if (LOG > 4) console.log(this.timestamp.msec);

  //DATA
  this.type = 0;//0x0C04C0;//ContentTypeValue[ContentType.DATA];
  
  if (LOG > 4) console.log('PUBLIC KEY TO WRITE TO DATA PACKET IS ');
  if (LOG > 4) console.log(key.publicToDER().toString('hex'));

  this.locator = new KeyLocator(key.publicToDER(), KeyLocatorType.KEY);
  //this.locator = new KeyLocator(DataUtils.toNumbersFromString(stringCertificate)  ,KeyLocatorType.CERTIFICATE);
};

SignedInfo.prototype.from_ndnb = function(decoder) 
{
  decoder.readStartElement(this.getElementLabel());
  
  if (decoder.peekStartElement(NDNProtocolDTags.PublisherPublicKeyDigest)) {
    if (LOG > 4) console.log('DECODING PUBLISHER KEY');
    this.publisher = new PublisherPublicKeyDigest();
    this.publisher.from_ndnb(decoder);
  }

  if (decoder.peekStartElement(NDNProtocolDTags.Timestamp)) {
    if (LOG > 4) console.log('DECODING TIMESTAMP');
    this.timestamp = decoder.readDateTime(NDNProtocolDTags.Timestamp);
  }

  if (decoder.peekStartElement(NDNProtocolDTags.Type)) {
    var binType = decoder.readBinaryElement(NDNProtocolDTags.Type);//byte [] 
    
    if (LOG > 4) console.log('Binary Type of of Signed Info is '+binType);

    this.type = binType;
    
    //TODO Implement type of Key Reading
    if (null == this.type)
      throw new Error("Cannot parse signedInfo type: bytes.");
  } 
  else
    this.type = ContentType.DATA; // default
  
  if (decoder.peekStartElement(NDNProtocolDTags.FreshnessSeconds)) {
    this.freshnessSeconds = decoder.readIntegerElement(NDNProtocolDTags.FreshnessSeconds);
    if (LOG > 4) console.log('FRESHNESS IN SECONDS IS '+ this.freshnessSeconds);
  }
  
  if (decoder.peekStartElement(NDNProtocolDTags.FinalBlockID)) {
    if (LOG > 4) console.log('DECODING FINAL BLOCKID');
    this.finalBlockID = decoder.readBinaryElement(NDNProtocolDTags.FinalBlockID);
  }
  
  if (decoder.peekStartElement(NDNProtocolDTags.KeyLocator)) {
    if (LOG > 4) console.log('DECODING KEY LOCATOR');
    this.locator = new KeyLocator();
    this.locator.from_ndnb(decoder);
  }
      
  decoder.readEndElement();
};

SignedInfo.prototype.to_ndnb = function(encoder)  {
  if (!this.validate())
    throw new Error("Cannot encode : field values missing.");

  encoder.writeElementStartDTag(this.getElementLabel());
  
  if (null != this.publisher) {
    if (LOG > 3) console.log('ENCODING PUBLISHER KEY' + this.publisher.publisherPublicKeyDigest);
    this.publisher.to_ndnb(encoder);
  }

  if (null != this.timestamp)
    encoder.writeDateTime(NDNProtocolDTags.Timestamp, this.timestamp);
  
  if (null != this.type && this.type != 0)
    encoder.writeElement(NDNProtocolDTags.type, this.type);
  
  if (null != this.freshnessSeconds)
    encoder.writeElement(NDNProtocolDTags.FreshnessSeconds, this.freshnessSeconds);

  if (null != this.finalBlockID)
    encoder.writeElement(NDNProtocolDTags.FinalBlockID, this.finalBlockID);

  if (null != this.locator)
    this.locator.to_ndnb(encoder);

  encoder.writeElementClose();       
};
  
SignedInfo.prototype.valueToType = function() 
{
  return null;  
};

SignedInfo.prototype.getElementLabel = function() { 
  return NDNProtocolDTags.SignedInfo;
};

SignedInfo.prototype.validate = function() 
{
  // We don't do partial matches any more, even though encoder/decoder
  // is still pretty generous.
  if (null ==this.publisher || null==this.timestamp ||null== this.locator)
    return false;
  return true;
};

// Since binary-xml-wire-format.js includes this file, put these at the bottom to avoid problems with cycles of require.
var BinaryXmlWireFormat = require('./encoding/binary-xml-wire-format.js').BinaryXmlWireFormat;

/**
 * @deprecated Use BinaryXmlWireFormat.decodeData.
 */
Data.prototype.from_ndnb = function(/*XMLDecoder*/ decoder) 
{
  BinaryXmlWireFormat.decodeData(this, decoder);
};

/**
 * @deprecated Use BinaryXmlWireFormat.encodeData.
 */
Data.prototype.to_ndnb = function(/*XMLEncoder*/ encoder)
{
  BinaryXmlWireFormat.encodeData(this, encoder);
};

/**
 * Encode this Data for a particular wire format.
 * @param {WireFormat} wireFormat if null, use BinaryXmlWireFormat.
 * @returns {Buffer}
 */
Data.prototype.encode = function(wireFormat) 
{
  wireFormat = (wireFormat || BinaryXmlWireFormat.instance);
  return wireFormat.encodeData(this);
};

/**
 * Decode the input using a particular wire format and update this Data.
 * @param {Buffer} input
 * @param {WireFormat} wireFormat if null, use BinaryXmlWireFormat.
 */
Data.prototype.decode = function(input, wireFormat) 
{
  wireFormat = (wireFormat || BinaryXmlWireFormat.instance);
  wireFormat.decodeData(this, input);
};

/**
 * @deprecated Use new Data.
 */
var ContentObject = function ContentObject(name, signedInfo, content) 
{
  // Call the base constructor.
  Data.call(this, name, signedInfo, content); 
}

ContentObject.prototype = new Data();

exports.ContentObject = ContentObject;
