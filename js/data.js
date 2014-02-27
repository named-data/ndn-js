/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Meki Cheraoui
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 * This class represents an NDN Data object.
 */

var Blob = require('./util/blob.js').Blob;
var SignedBlob = require('./util/signed-blob.js').SignedBlob;
var BinaryXMLEncoder = require('./encoding/binary-xml-encoder.js').BinaryXMLEncoder;
var NDNProtocolDTags = require('./util/ndn-protoco-id-tags.js').NDNProtocolDTags;
var DataUtils = require('./encoding/data-utils.js').DataUtils;
var Name = require('./name.js').Name;
var Signature = require('./signature.js').Signature;
var MetaInfo = require('./meta-info.js').MetaInfo;
var globalKeyManager = require('./security/key-manager.js').globalKeyManager;
var WireFormat = require('./encoding/wire-format.js').WireFormat;

/**
 * Create a new Data with the optional values.
 * 
 * @constructor
 * @param {Name} name
 * @param {MetaInfo} metaInfo
 * @param {Buffer} content
 */
var Data = function Data(name, metaInfo, content) 
{
  if (typeof name === 'string')
    this.name = new Name(name);
  else
    this.name = typeof name === 'object' && name instanceof Name ?
       new Name(name) : new Name();

  // Use signedInfo instead of metaInfo for backward compatibility.
  this.signedInfo = typeof metaInfo === 'object' && metaInfo instanceof MetaInfo ?
       new MetaInfo(metaInfo) : new MetaInfo();
  
  if (typeof content === 'string') 
    this.content = DataUtils.toNumbersFromString(content);
  else if (typeof content === 'object' && content instanceof Blob)
    this.content = content.buf();
  else 
    this.content = content;
  
  this.signature = new Signature();
  
  // Only used by BinaryXMLWireFormat.
  this.startSIG = null;
  this.endSIG = null;
  
  this.endContent = null;
  
  this.rawSignatureData = null;
};

exports.Data = Data;

/**
 * Get the data packet's name.
 * @returns {Name} The name.
 */
Data.prototype.getName = function() 
{
  return this.name;
};

/**
 * Get the data packet's meta info.
 * @returns {MetaInfo} The meta info.
 */
Data.prototype.getMetaInfo = function() 
{
  return this.signedInfo;
};

/**
 * Get the data packet's signature object.
 * @returns {Signature} The signature object.
 */
Data.prototype.getSignature = function() 
{
  return this.signature;
};

/**
 * Get the data packet's content.
 * @returns {Buffer} The content as a Buffer, which is null if unspecified.
 */
Data.prototype.getContent = function() 
{
  return this.content;
};

/**
 * Set name to a copy of the given Name.
 * @param {Name} name The Name which is copied.
 * @returns {Data} This Data so that you can chain calls to update values.
 */
Data.prototype.setName = function(name) 
{
  this.name = typeof name === 'object' && name instanceof Name ?
    new Name(name) : new Name();
  return this;
};

/**
 * Set metaInfo to a copy of the given MetaInfo.
 * @param {MetaInfo} metaInfo The MetaInfo which is copied.
 * @returns {Data} This Data so that you can chain calls to update values.
 */
Data.prototype.setMetaInfo = function(metaInfo) 
{
  this.signedInfo = typeof metaInfo === 'object' && metaInfo instanceof MetaInfo ?
    new MetaInfo(metaInfo) : new MetaInfo();
  return this;
};

/**
 * Set the signature to a copy of the given signature.
 * @param {Signature} signature The signature object which is cloned.
 * @returns {Data} This Data so that you can chain calls to update values.
 */
Data.prototype.setSignature = function(signature) 
{
  this.signature = typeof signature === 'object' && signature instanceof Signature ?
    signature.clone() : new Signature();
  return this;
};

/**
 * Set the content to the given value.
 * @param {type} content The array this is copied.
 * @returns {Data} This Data so that you can chain calls to update values.
 */
Data.prototype.setContent = function(content) 
{
  if (typeof content === 'string') 
    this.content = DataUtils.toNumbersFromString(content);
  else if (typeof content === 'object' && content instanceof Blob)
    this.content = content.buf();
  else 
    this.content = content;
  return this;
};

Data.prototype.sign = function() 
{
  // TODO: Use SignedBlob.
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
  enc.writeDTagElement(NDNProtocolDTags.Content, this.content);
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
 * Encode this Data for a particular wire format.
 * @param {a subclass of WireFormat} wireFormat (optional) A WireFormat object 
 * used to encode this object. If omitted, use WireFormat.getDefaultWireFormat().
 * @returns {SignedBlob} The encoded buffer in a SignedBlob object.
 */
Data.prototype.wireEncode = function(wireFormat) 
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
  var result = wireFormat.encodeData(this);
  return new SignedBlob
    (result.encoding, result.signedPortionBeginOffset, 
     result.signedPortionEndOffset);
};

/**
 * Decode the input using a particular wire format and update this Data.
 * @param {Buffer} input The buffer with the bytes to decode.
 * @param {a subclass of WireFormat} wireFormat (optional) A WireFormat object 
 * used to decode this object. If omitted, use WireFormat.getDefaultWireFormat().
 */
Data.prototype.wireDecode = function(input, wireFormat) 
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
  // If input is a blob, get its buf().
  var decodeBuffer = typeof input === 'object' && input instanceof Blob ? 
                     input.buf() : input;
  wireFormat.decodeData(this, decodeBuffer);
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
 * @deprecated Use wireEncode.  If you need binary XML, use
 * wireEncode(BinaryXmlWireFormat.get()).
 */
Data.prototype.encode = function(wireFormat) 
{
  wireFormat = (wireFormat || BinaryXmlWireFormat.get());
  return wireFormat.encodeData(this).buf();
};

/**
 * @deprecated Use wireDecode.  If you need binary XML, use
 * wireDecode(input, BinaryXmlWireFormat.get()).
 */
Data.prototype.decode = function(input, wireFormat) 
{
  wireFormat = (wireFormat || BinaryXmlWireFormat.get());
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
