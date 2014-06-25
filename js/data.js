/**
 * This class represents an NDN Data object.
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Meki Cheraoui
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var Blob = require('./util/blob.js').Blob;
var SignedBlob = require('./util/signed-blob.js').SignedBlob;
var BinaryXMLEncoder = require('./encoding/binary-xml-encoder.js').BinaryXMLEncoder;
var NDNProtocolDTags = require('./util/ndn-protoco-id-tags.js').NDNProtocolDTags;
var DataUtils = require('./encoding/data-utils.js').DataUtils;
var Name = require('./name.js').Name;
var Signature = require('./signature.js').Signature;
var MetaInfo = require('./meta-info.js').MetaInfo;
var KeyLocator = require('./key-locator.js').KeyLocator;
var globalKeyManager = require('./security/key-manager.js').globalKeyManager;
var WireFormat = require('./encoding/wire-format.js').WireFormat;

/**
 * Create a new Data with the optional values.  There are 2 forms of constructor:
 * new Data([name] [, content]);
 * new Data(name, metaInfo [, content]);
 * 
 * @constructor
 * @param {Name} name
 * @param {MetaInfo} metaInfo
 * @param {Buffer} content
 */
var Data = function Data(name, metaInfoOrContent, arg3) 
{
  if (typeof name === 'string')
    this.name = new Name(name);
  else
    this.name = typeof name === 'object' && name instanceof Name ?
       new Name(name) : new Name();

  var metaInfo;
  var content;
  if (typeof metaInfoOrContent === 'object' && 
      metaInfoOrContent instanceof MetaInfo) {
    metaInfo = metaInfoOrContent;
    content = arg3;
  }
  else {
    metaInfo = null;
    content = metaInfoOrContent;
  }
    
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
  
  this.wireEncoding = SignedBlob();
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
 * @returns {Blob} The data packet content as a Blob.
 */
Data.prototype.getContent = function() 
{
  // For temporary backwards compatibility, leave this.content as a Buffer but return a Blob.
  return new Blob(this.content, false);
};

/**
 * @deprecated Use getContent. This method returns a Buffer which is the former
 * behavior of getContent, and should only be used while updating your code.
 */
Data.prototype.getContentAsBuffer = function() 
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

  // The object has changed, so the wireEncoding is invalid.
  this.wireEncoding = SignedBlob();
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

  // The object has changed, so the wireEncoding is invalid.
  this.wireEncoding = SignedBlob();
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

  // The object has changed, so the wireEncoding is invalid.
  this.wireEncoding = SignedBlob();
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
    this.content = new Buffer(content);

  // The object has changed, so the wireEncoding is invalid.
  this.wireEncoding = SignedBlob();
  return this;
};

Data.prototype.sign = function(wireFormat) 
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
 
  if (this.getSignatureOrMetaInfoKeyLocator() == null ||
      this.getSignatureOrMetaInfoKeyLocator().getType() == null)
    this.getMetaInfo().setFields();
  
  if (this.wireEncoding == null || this.wireEncoding.isNull()) {
    // Need to encode to set wireEncoding.
    // Set an initial empty signature so that we can encode.
    this.getSignature().setSignature(new Buffer(128));
    this.wireEncode(wireFormat);
  }
  
  var rsa = require("crypto").createSign('RSA-SHA256');
  rsa.update(this.wireEncoding.signedBuf());
    
  var sig = new Buffer
    (DataUtils.toNumbersIfString(rsa.sign(globalKeyManager.privateKey)));
  this.signature.setSignature(sig);
};

// The first time verify is called, it sets this to determine if a signature
//   buffer needs to be converted to a string for the crypto verifier.
Data.verifyUsesString = null;
Data.prototype.verify = function(/*Key*/ key) 
{
  if (key == null || key.publicKeyPem == null)
    throw new Error('Cannot verify Data without a public key.');

  if (Data.verifyUsesString == null) {
    var hashResult = require("crypto").createHash('sha256').digest();
    // If the has result is a string, we assume that this is a version of
    //   crypto where verify also uses a string signature.
    Data.verifyUsesString = (typeof hashResult === 'string');
  }

  if (this.wireEncoding == null || this.wireEncoding.isNull())
    // Need to encode to set wireEncoding.
    this.wireEncode();
  var verifier = require('crypto').createVerify('RSA-SHA256');
  verifier.update(this.wireEncoding.signedBuf());
  var signatureBytes = Data.verifyUsesString ? 
    DataUtils.toString(this.signature.signature) : this.signature.signature;
  return verifier.verify(key.publicKeyPem, signatureBytes);
};

Data.prototype.getElementLabel = function() { return NDNProtocolDTags.Data; };

/**
 * Encode this Data for a particular wire format.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode 
 * this object. If omitted, use WireFormat.getDefaultWireFormat().
 * @returns {SignedBlob} The encoded buffer in a SignedBlob object.
 */
Data.prototype.wireEncode = function(wireFormat) 
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
  var result = wireFormat.encodeData(this);
  // TODO: Implement setDefaultWireEncoding with getChangeCount support.
  this.wireEncoding = new SignedBlob
    (result.encoding, result.signedPortionBeginOffset, 
     result.signedPortionEndOffset);
  return this.wireEncoding;
};

/**
 * Decode the input using a particular wire format and update this Data.
 * @param {Blob|Buffer} input The buffer with the bytes to decode.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to decode 
 * this object. If omitted, use WireFormat.getDefaultWireFormat().
 */
Data.prototype.wireDecode = function(input, wireFormat) 
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
  // If input is a blob, get its buf().
  var decodeBuffer = typeof input === 'object' && input instanceof Blob ? 
                     input.buf() : input;
  var result = wireFormat.decodeData(this, decodeBuffer);
  // TODO: Implement setDefaultWireEncoding with getChangeCount support.
  // In the Blob constructor, set copy true, but if input is already a Blob, it 
  //   won't copy.
  this.wireEncoding = new SignedBlob
    (new Blob(input, true), result.signedPortionBeginOffset, 
     result.signedPortionEndOffset);
};

/**
 * If getSignature() has a key locator, return it.  Otherwise, use
 * the key locator from getMetaInfo() for backward compatibility and print
 * a warning to console.log that the key locator has moved to the Signature
 * object.  If neither has a key locator, return an empty key locator.
 * When we stop supporting the key locator in MetaInfo, this function is not
 * necessary and we will just use the key locator in the Signature.
 * @returns {KeyLocator} The key locator to use.
 */
Data.prototype.getSignatureOrMetaInfoKeyLocator = function()
{
  if (this.signature != null && this.signature.getKeyLocator() != null &&
      this.signature.getKeyLocator().getType() != null &&
      this.signature.getKeyLocator().getType() >= 0)
    // The application is using the key locator in the correct object.
    return this.signature.getKeyLocator();
  
  if (this.signedInfo != null && this.signedInfo.locator != null &&
      this.signedInfo.locator.type != null &&
      this.signedInfo.locator.type >= 0) {
    console.log("WARNING: Temporarily using the key locator found in the MetaInfo - expected it in the Signature object.");
    console.log("WARNING: In the future, the key locator in the Signature object will not be supported.");
    return this.signedInfo.locator;
  }
  
  // Return the empty key locator from the Signature object if possible.
  if (this.signature != null && this.signature.getKeyLocator() != null)
    return this.signature.getKeyLocator();
  else
    return new KeyLocator();
}

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
