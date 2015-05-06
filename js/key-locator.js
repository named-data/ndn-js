/**
 * This class represents an NDN KeyLocator object.
 * Copyright (C) 2014-2015 Regents of the University of California.
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
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU Lesser General Public License is in the file COPYING.
 */

var Blob = require('./util/blob.js').Blob;
var ChangeCounter = require('./util/change-counter.js').ChangeCounter;
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
  // KeyLocatorType KEY and CERTIFICATE are not supported in NDN-TLV encoding and are deprecated.
  KEY: 3,
  CERTIFICATE: 4
};

exports.KeyLocatorType = KeyLocatorType;

/**
 * @constructor
 */
var KeyLocator = function KeyLocator(input, type)
{
  if (typeof input === 'object' && input instanceof KeyLocator) {
    // Copy from the input KeyLocator.
    this.type_ = input.type_;
    this.keyName_ = new ChangeCounter(new KeyName());
    this.keyName_.get().setContentName(input.keyName_.get().getContentName());
    this.keyName_.get().publisherID = input.keyName_.get().publisherID;
    this.keyData_ = input.keyData_;
    this.publicKey_ = input.publicKey_ == null ? null : new Buffer(input.publicKey_);
    this.certificate_ = input.certificate_ == null ? null : new Buffer(input.certificate_);
  }
  else {
    this.type_ = type;
    this.keyName_ = new ChangeCounter(new KeyName());
    this.keyData_ = new Blob();

    if (type == KeyLocatorType.KEYNAME)
      this.keyName_.set(input);
    else if (type == KeyLocatorType.KEY_LOCATOR_DIGEST)
      this.keyData_ = new Blob(input);
    else if (type == KeyLocatorType.KEY) {
      this.keyData_ = new Blob(input);
      // Set for backwards compatibility.
      this.publicKey_ = this.keyData_;
    }
    else if (type == KeyLocatorType.CERTIFICATE) {
      this.keyData_ = new Blob(input);
      // Set for backwards compatibility.
      this.certificate_ = this.keyData_;
    }
  }

  this.changeCount_ = 0;
};

exports.KeyLocator = KeyLocator;

/**
 * Get the key locator type. If KeyLocatorType.KEYNAME, you may also
 * getKeyName().  If KeyLocatorType.KEY_LOCATOR_DIGEST, you may also
 * getKeyData() to get the digest.
 * @returns {number} The key locator type, or null if not specified.
 */
KeyLocator.prototype.getType = function() { return this.type_; };

/**
 * Get the key name.  This is meaningful if getType() is KeyLocatorType.KEYNAME.
 * @returns {Name} The key name. If not specified, the Name is empty.
 */
KeyLocator.prototype.getKeyName = function()
{
  return this.keyName_.get().getContentName();
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
  if (this.type_ == KeyLocatorType.KEY)
    return new Blob(this.publicKey_);
  else if (this.type_ == KeyLocatorType.CERTIFICATE)
    return new Blob(this.certificate_);
  else
    return this.keyData_;
};

/**
 * @deprecated Use getKeyData. This method returns a Buffer which is the former
 * behavior of getKeyData, and should only be used while updating your code.
 */
KeyLocator.prototype.getKeyDataAsBuffer = function()
{
  return this.getKeyData().buf();
};

/**
 * Set the key locator type.  If KeyLocatorType.KEYNAME, you must also
 * setKeyName().  If KeyLocatorType.KEY_LOCATOR_DIGEST, you must also
 * setKeyData() to the digest.
 * @param {number} type The key locator type.  If null, the type is unspecified.
 */
KeyLocator.prototype.setType = function(type)
{
  this.type_ = type;
  ++this.changeCount_;
};

/**
 * Set key name to a copy of the given Name.  This is the name if getType()
 * is KeyLocatorType.KEYNAME.
 * @param {Name} name The key name which is copied.
 */
KeyLocator.prototype.setKeyName = function(name)
{
  this.keyName_.get().setContentName(name);
  ++this.changeCount_;
};

/**
 * Set the key data to the given value. This is the digest bytes if getType() is
 * KeyLocatorType.KEY_LOCATOR_DIGEST.
 * @param {Blob} keyData A Blob with the key data bytes.
 */
KeyLocator.prototype.setKeyData = function(keyData)
{
  this.keyData_ = typeof keyData === 'object' && keyData instanceof Blob ?
    keyData : new Blob(keyData);
  // Set for backwards compatibility.
  this.publicKey_ = this.keyData_.buf();
  this.certificate_ = this.keyData_.buf();
  ++this.changeCount_;
};

/**
 * Clear the keyData and set the type to not specified.
 */
KeyLocator.prototype.clear = function()
{
  this.type_ = null;
  this.keyName_.set(new KeyName());
  this.keyData_ = new Blob();
  this.publicKey_ = null;
  this.certificate_ = null;
  ++this.changeCount_;
};

/**
 * If the signature is a type that has a KeyLocator (so that
 * getFromSignature will succeed), return true.
 * Note: This is a static method of KeyLocator instead of a method of
 * Signature so that the Signature base class does not need to be overloaded
 * with all the different kinds of information that various signature
 * algorithms may use.
 * @param {Signature} signature An object of a subclass of Signature.
 * @returns {boolean} True if the signature is a type that has a KeyLocator,
 * otherwise false.
 */
KeyLocator.canGetFromSignature = function(signature)
{
  return signature instanceof Sha256WithRsaSignature;
}

/**
 * If the signature is a type that has a KeyLocator, then return it. Otherwise
 * throw an error.
 * @param {Signature} signature An object of a subclass of Signature.
 * @returns {KeyLocator} The signature's KeyLocator. It is an error if signature
 * doesn't have a KeyLocator.
 */
KeyLocator.getFromSignature = function(signature)
{
  if (signature instanceof Sha256WithRsaSignature)
    return signature.getKeyLocator();
  else
    throw new Error
      ("KeyLocator.getFromSignature: Signature type does not have a KeyLocator");
}

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

    this.keyName_.set(new KeyName());
    this.keyName_.get().from_ndnb(decoder);
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
    this.keyName_.get().to_ndnb(encoder);

  encoder.writeElementClose();
};

KeyLocator.prototype.getElementLabel = function()
{
  return NDNProtocolDTags.KeyLocator;
};

/**
 * Get the change count, which is incremented each time this object (or a child
 * object) is changed.
 * @returns {number} The change count.
 */
KeyLocator.prototype.getChangeCount = function()
{
  // Make sure each of the checkChanged is called.
  var changed = this.keyName_.checkChanged();
  if (changed)
    // A child object has changed, so update the change count.
    ++this.changeCount_;

  return this.changeCount_;
};

// Define properties so we can change member variable types and implement changeCount_.
Object.defineProperty(KeyLocator.prototype, "type",
  { get: function() { return this.getType(); },
    set: function(val) { this.setType(val); } });
/**
 * @deprecated Use getKeyName and setKeyName.
 */
Object.defineProperty(KeyLocator.prototype, "keyName",
  { get: function() { return this.keyName_.get(); },
    set: function(val) {
      this.keyName_.set(val == null ? new KeyName() : val);
      ++this.changeCount_;
    } });
/**
 * @@deprecated Use getKeyData and setKeyData.
 */
Object.defineProperty(KeyLocator.prototype, "keyData",
  { get: function() { return this.getKeyDataAsBuffer(); },
    set: function(val) { this.setKeyData(val); } });
/**
 * @deprecated
 */
Object.defineProperty(KeyLocator.prototype, "publicKey",
  { get: function() { return this.publicKey_; },
    set: function(val) { this.publicKey_ = val; ++this.changeCount_; } });
/**
 * @deprecated
 */
Object.defineProperty(KeyLocator.prototype, "certificate",
  { get: function() { return this.certificate_; },
    set: function(val) { this.certificate_ = val; ++this.changeCount_; } });

/**
 * @deprecated Use KeyLocator getKeyName and setKeyName. This is only needed to
 * support NDNx and will be removed.
 */
var KeyName = function KeyName()
{
  this.contentName_ = new ChangeCounter(new Name());
  this.publisherID = this.publisherID;  //publisherID
  this.changeCount_ = 0;
};

exports.KeyName = KeyName;

KeyName.prototype.getContentName = function()
{
  return this.contentName_.get();
};

KeyName.prototype.setContentName = function(name)
{
  this.contentName_.set(typeof name === 'object' && name instanceof Name ?
    new Name(name) : new Name());
  ++this.changeCount_;
};

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

/**
 * Get the change count, which is incremented each time this object (or a child
 * object) is changed.
 * @returns {number} The change count.
 */
KeyName.prototype.getChangeCount = function()
{
  // Make sure each of the checkChanged is called.
  var changed = this.contentName_.checkChanged();
  if (changed)
    // A child object has changed, so update the change count.
    ++this.changeCount_;

  return this.changeCount_;
};

// Define properties so we can change member variable types and implement changeCount_.
Object.defineProperty(KeyName.prototype, "contentName",
  { get: function() { return this.getContentName(); },
    set: function(val) { this.setContentName(val); } });

// Put this last to avoid a require loop.
var Sha256WithRsaSignature = require('./sha256-with-rsa-signature.js').Sha256WithRsaSignature;
