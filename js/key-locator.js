/**
 * This class represents an NDN KeyLocator object.
 * Copyright (C) 2014 Regents of the University of California.
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
var Name = require('./name.js').Name;
var NDNProtocolDTags = require('./util/ndn-protoco-id-tags.js').NDNProtocolDTags;
var PublisherID = require('./publisher-id.js').PublisherID;
var LOG = require('./log.js').Log.LOG;

/**
 * KeyLocator
 */
var KeyLocatorType = {
  KEYNAME: 1,
  KEY_LOCATOR_DIGEST: 2,
  KEY: 3,
  CERTIFICATE: 4
};

exports.KeyLocatorType = KeyLocatorType;

/**
 * @constructor
 */
var KeyLocator = function KeyLocator(input,type) 
{ 
  if (typeof input === 'object' && input instanceof KeyLocator) {
    // Copy from the input KeyLocator.
    this.type = input.type;
    this.keyName = new KeyName();
    if (input.keyName != null) {
      this.keyName.contentName = input.keyName.contentName == null ? 
        null : new Name(input.keyName.contentName);
      this.keyName.publisherID = input.keyName.publisherID;
    }
    this.keyData = input.keyData == null ? null : new Buffer(input.keyData);
    this.publicKey = input.publicKey == null ? null : new Buffer(input.publicKey);
    this.certificate = input.certificate == null ? null : new Buffer(input.certificate);
  }
  else {
    this.type = type;
    this.keyName = new KeyName();

    if (type == KeyLocatorType.KEYNAME)
      this.keyName = input;
    else if (type == KeyLocatorType.KEY_LOCATOR_DIGEST)
      this.keyData = new Buffer(input);
    else if (type == KeyLocatorType.KEY) {
      this.keyData = new Buffer(input);
      // Set for backwards compatibility.
      this.publicKey = this.keyData;
    }
    else if (type == KeyLocatorType.CERTIFICATE) {
      this.keyData = new Buffer(input);
      // Set for backwards compatibility.
      this.certificate = this.keyData;
    }
  }
};

exports.KeyLocator = KeyLocator;

/**
 * Get the key locator type. If KeyLocatorType.KEYNAME, you may also
 * getKeyName().  If KeyLocatorType.KEY_LOCATOR_DIGEST, you may also
 * getKeyData() to get the digest.
 * @returns {number} The key locator type, or null if not specified.
 */
KeyLocator.prototype.getType = function() { return this.type; };

/**
 * Get the key name.  This is meaningful if getType() is KeyLocatorType.KEYNAME.
 * @returns {Name} The key name. If not specified, the Name is empty.
 */
KeyLocator.prototype.getKeyName = function() 
{ 
  if (this.keyName == null)
    this.keyName = new KeyName();
  if (this.keyName.contentName == null)
    this.keyName.contentName = new Name();
  
  return this.keyName.contentName;
};

/**
 * Get the key data. If getType() is KeyLocatorType.KEY_LOCATOR_DIGEST, this is 
 * the digest bytes. If getType() is KeyLocatorType.KEY, this is the DER 
 * encoded public key. If getType() is KeyLocatorType.CERTIFICATE, this is the 
 * DER encoded certificate. 
 * @returns {Blob} The key data, or null if not specified.
 */
KeyLocator.prototype.getKeyData = function() 
{ 
  // For temporary backwards compatibility, leave the fields as a Buffer but return a Blob.
  return new Blob(this.getKeyDataAsBuffer(), false);
};

/**
 * @deprecated Use getKeyData. This method returns a Buffer which is the former
 * behavior of getKeyData, and should only be used while updating your code.
 */
KeyLocator.prototype.getKeyDataAsBuffer = function() 
{ 
  if (this.type == KeyLocatorType.KEY)
    return this.publicKey;
  else if (this.type == KeyLocatorType.CERTIFICATE)
    return this.certificate;
  else
    return this.keyData;
};

/**
 * Set the key locator type.  If KeyLocatorType.KEYNAME, you must also
 * setKeyName().  If KeyLocatorType.KEY_LOCATOR_DIGEST, you must also
 * setKeyData() to the digest.
 * @param {number} type The key locator type.  If null, the type is unspecified.
 */
KeyLocator.prototype.setType = function(type) { this.type = type; }; 

/**
 * Set key name to a copy of the given Name.  This is the name if getType() 
 * is KeyLocatorType.KEYNAME.
 * @param {Name} name The key name which is copied.
 */
KeyLocator.prototype.setKeyName = function(name) 
{ 
  if (this.keyName == null)
    this.keyName = new KeyName();
  
  this.keyName.contentName = typeof name === 'object' && name instanceof Name ?
                             new Name(name) : new Name(); 
}; 

/**
 * Set the key data to the given value. This is the digest bytes if getType() is 
 * KeyLocatorType.KEY_LOCATOR_DIGEST.
 * @param {Buffer} keyData The array with the key data bytes.
 */
KeyLocator.prototype.setKeyData = function(keyData)
{
  var value = keyData;
  if (value != null) {
    if (typeof value === 'object' && value instanceof Blob)
      value = new Buffer(value.buf());
    else
      // Make a copy.                                                                                                      
      value = new Buffer(value);
  }
  
  this.keyData = value;
  // Set for backwards compatibility.
  this.publicKey = value;
  this.certificate = value;
};

/**
 * Clear the keyData and set the type to none.
 */
KeyLocator.prototype.clear = function() 
{
  this.type = null;
  this.keyName = null;
  this.keyData = null;
  this.publicKey = null;
  this.certificate = null;
};

KeyLocator.prototype.from_ndnb = function(decoder) {

  decoder.readElementStartDTag(this.getElementLabel());

  if (decoder.peekDTag(NDNProtocolDTags.Key)) 
  {
    try {
      var encodedKey = decoder.readBinaryDTagElement(NDNProtocolDTags.Key);
      // This is a DER-encoded SubjectPublicKeyInfo.
      
      //TODO FIX THIS, This should create a Key Object instead of keeping bytes

      this.publicKey =   encodedKey;//CryptoUtil.getPublicKey(encodedKey);
      this.type = KeyLocatorType.KEY;    

      if (LOG > 4) console.log('PUBLIC KEY FOUND: '+ this.publicKey);
    } 
    catch (e) {
      throw new Error("Cannot parse key: ", e);
    } 

    if (null == this.publicKey)
      throw new Error("Cannot parse key: ");
  } 
  else if (decoder.peekDTag(NDNProtocolDTags.Certificate)) {
    try {
      var encodedCert = decoder.readBinaryDTagElement(NDNProtocolDTags.Certificate);
      
      /*
       * Certificates not yet working
       */
      
      this.certificate = encodedCert;
      this.type = KeyLocatorType.CERTIFICATE;

      if (LOG > 4) console.log('CERTIFICATE FOUND: '+ this.certificate);      
    } 
    catch (e) {
      throw new Error("Cannot decode certificate: " +  e);
    }
    if (null == this.certificate)
      throw new Error("Cannot parse certificate! ");
  } else  {
    this.type = KeyLocatorType.KEYNAME;
    
    this.keyName = new KeyName();
    this.keyName.from_ndnb(decoder);
  }
  decoder.readElementClose();
};  

KeyLocator.prototype.to_ndnb = function(encoder) 
{
  if (LOG > 4) console.log('type is is ' + this.type);

  if (this.type == KeyLocatorType.KEY_LOCATOR_DIGEST)
    // encodeSignedInfo already encoded this as the publisherPublicKeyDigest,
    //   so do nothing here.
    return;

  encoder.writeElementStartDTag(this.getElementLabel());
  
  if (this.type == KeyLocatorType.KEY) {
    if (LOG > 5) console.log('About to encode a public key' +this.publicKey);
    encoder.writeDTagElement(NDNProtocolDTags.Key, this.publicKey);  
  } 
  else if (this.type == KeyLocatorType.CERTIFICATE) {  
    try {
      encoder.writeDTagElement(NDNProtocolDTags.Certificate, this.certificate);
    } 
    catch (e) {
      throw new Error("CertificateEncodingException attempting to write key locator: " + e);
    }    
  } 
  else if (this.type == KeyLocatorType.KEYNAME)
    this.keyName.to_ndnb(encoder);

  encoder.writeElementClose();
};

KeyLocator.prototype.getElementLabel = function() 
{
  return NDNProtocolDTags.KeyLocator; 
};

/**
 * KeyName is only used by KeyLocator.
 * @constructor
 */
var KeyName = function KeyName() 
{
  this.contentName = new Name();  //contentName
  this.publisherID = this.publisherID;  //publisherID
};

exports.KeyName = KeyName;

KeyName.prototype.from_ndnb = function(decoder) 
{
  decoder.readElementStartDTag(this.getElementLabel());

  this.contentName = new Name();
  this.contentName.from_ndnb(decoder);
  
  if (LOG > 4) console.log('KEY NAME FOUND: ');
  
  if (PublisherID.peek(decoder)) {
    this.publisherID = new PublisherID();
    this.publisherID.from_ndnb(decoder);
  }
  
  decoder.readElementClose();
};

KeyName.prototype.to_ndnb = function(encoder)
{
  encoder.writeElementStartDTag(this.getElementLabel());
  
  this.contentName.to_ndnb(encoder);
  if (null != this.publisherID)
    this.publisherID.to_ndnb(encoder);

  encoder.writeElementClose();       
};
  
KeyName.prototype.getElementLabel = function() { return NDNProtocolDTags.KeyName; };

