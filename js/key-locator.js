/**
 * This class represents an NDN KeyLocator object.
 * Copyright (C) 2014-2018 Regents of the University of California.
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

/** @ignore */
var Blob = require('./util/blob.js').Blob; /** @ignore */
var ChangeCounter = require('./util/change-counter.js').ChangeCounter; /** @ignore */
var Name = require('./name.js').Name;

/**
 * KeyLocator
 */
var KeyLocatorType = {
  KEYNAME: 1,
  KEY_LOCATOR_DIGEST: 2
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
    this.keyName_ = new ChangeCounter(new Name(input.getKeyName()));
    this.keyData_ = input.keyData_;
  }
  else {
    this.type_ = type;
    this.keyName_ = new ChangeCounter(new Name());
    this.keyData_ = new Blob();

    if (type == KeyLocatorType.KEYNAME)
      this.keyName_.set(typeof input === 'object' && input instanceof Name ?
        new Name(input) : new Name());
    else if (type == KeyLocatorType.KEY_LOCATOR_DIGEST)
      this.keyData_ = new Blob(input);
  }

  this.changeCount_ = 0;
};

exports.KeyLocator = KeyLocator;

/**
 * Get the key locator type. If KeyLocatorType.KEYNAME, you may also
 * getKeyName().  If KeyLocatorType.KEY_LOCATOR_DIGEST, you may also
 * getKeyData() to get the digest.
 * @return {number} The key locator type as a KeyLocatorType enum value,
 * or null if not specified.
 */
KeyLocator.prototype.getType = function() { return this.type_; };

/**
 * Get the key name.  This is meaningful if getType() is KeyLocatorType.KEYNAME.
 * @return {Name} The key name. If not specified, the Name is empty.
 */
KeyLocator.prototype.getKeyName = function()
{
  return this.keyName_.get();
};

/**
 * Get the key data. If getType() is KeyLocatorType.KEY_LOCATOR_DIGEST, this is
 * the digest bytes.
 * @return {Blob} The key data, or an isNull Blob if not specified.
 */
KeyLocator.prototype.getKeyData = function()
{
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
 * @param {number} type The key locator type as a KeyLocatorType enum value.  If
 * null, the type is unspecified.
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
  this.keyName_.set(typeof name === 'object' && name instanceof Name ?
    new Name(name) : new Name());
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
  ++this.changeCount_;
};

/**
 * Clear the keyData and set the type to not specified.
 */
KeyLocator.prototype.clear = function()
{
  this.type_ = null;
  this.keyName_.set(new Name());
  this.keyData_ = new Blob();
  ++this.changeCount_;
};

/**
 * Check if this key locator has the same values as the given key locator.
 * @param {KeyLocator} other The other key locator to check.
 * @return {boolean} true if the key locators are equal, otherwise false.
 */
KeyLocator.prototype.equals = function(other)
{
    if (this.type_ != other.type_)
      return false;

    if (this.type_ == KeyLocatorType.KEYNAME) {
      if (!this.getKeyName().equals(other.getKeyName()))
        return false;
    }
    else if (this.type_ == KeyLocatorType.KEY_LOCATOR_DIGEST) {
      if (!this.getKeyData().equals(other.getKeyData()))
        return false;
    }

    return true;
};

/**
 * If the signature is a type that has a KeyLocator (so that,
 * getFromSignature will succeed), return true.
 * Note: This is a static method of KeyLocator instead of a method of
 * Signature so that the Signature base class does not need to be overloaded
 * with all the different kinds of information that various signature
 * algorithms may use.
 * @param {Signature} signature An object of a subclass of Signature.
 * @return {boolean} True if the signature is a type that has a KeyLocator,
 * otherwise false.
 */
KeyLocator.canGetFromSignature = function(signature)
{
  return signature instanceof Sha256WithRsaSignature ||
         signature instanceof Sha256WithEcdsaSignature ||
         signature instanceof HmacWithSha256Signature;
}

/**
 * If the signature is a type that has a KeyLocator, then return it. Otherwise
 * throw an error.
 * @param {Signature} signature An object of a subclass of Signature.
 * @return {KeyLocator} The signature's KeyLocator. It is an error if signature
 * doesn't have a KeyLocator.
 */
KeyLocator.getFromSignature = function(signature)
{
  if (signature instanceof Sha256WithRsaSignature ||
      signature instanceof Sha256WithEcdsaSignature ||
      signature instanceof HmacWithSha256Signature)
    return signature.getKeyLocator();
  else
    throw new Error
      ("KeyLocator.getFromSignature: Signature type does not have a KeyLocator");
}

/**
 * Get the change count, which is incremented each time this object (or a child
 * object) is changed.
 * @return {number} The change count.
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
 * @@deprecated Use getKeyData and setKeyData.
 */
Object.defineProperty(KeyLocator.prototype, "keyData",
  { get: function() { return this.getKeyDataAsBuffer(); },
    set: function(val) { this.setKeyData(val); } });

// Put these last to avoid a require loop.
/** @ignore */
var Sha256WithRsaSignature = require('./sha256-with-rsa-signature.js').Sha256WithRsaSignature; /** @ignore */
var Sha256WithEcdsaSignature = require('./sha256-with-ecdsa-signature.js').Sha256WithEcdsaSignature; /** @ignore */
var HmacWithSha256Signature = require('./hmac-with-sha256-signature.js').HmacWithSha256Signature;
