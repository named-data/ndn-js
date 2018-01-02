/**
 * This class represents an NDN Data Signature object.
 * Copyright (C) 2016-2018 Regents of the University of California.
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
var KeyLocator = require('./key-locator.js').KeyLocator;

/**
 * An HmacWithSha256Signature holds the signature bits and other info
 * representing an HmacWithSha256 signature in a packet.
 * Create a new HmacWithSha256Signature object, possibly copying values from
 * another object.
 *
 * @param {HmacWithSha256Signature} value (optional) If value is a
 * HmacWithSha256Signature, copy its values.  If value is omitted, the keyLocator
 * is the default with unspecified values and the signature is unspecified.
 * @constructor
 */
var HmacWithSha256Signature = function HmacWithSha256Signature(value)
{
  if (typeof value === 'object' && value instanceof HmacWithSha256Signature) {
    // Copy the values.
    this.keyLocator_ = new ChangeCounter(new KeyLocator(value.getKeyLocator()));
    this.signature_ = value.signature_;
  }
  else {
    this.keyLocator_ = new ChangeCounter(new KeyLocator());
    this.signature_ = new Blob();
  }

  this.changeCount_ = 0;
};

exports.HmacWithSha256Signature = HmacWithSha256Signature;

/**
 * Create a new HmacWithSha256Signature which is a copy of this object.
 * @return {HmacWithSha256Signature} A new object which is a copy of this object.
 */
HmacWithSha256Signature.prototype.clone = function()
{
  return new HmacWithSha256Signature(this);
};

/**
 * Get the key locator.
 * @return {KeyLocator} The key locator.
 */
HmacWithSha256Signature.prototype.getKeyLocator = function()
{
  return this.keyLocator_.get();
};

/**
 * Get the data packet's signature bytes.
 * @return {Blob} The signature bytes. If not specified, the value isNull().
 */
HmacWithSha256Signature.prototype.getSignature = function()
{
  return this.signature_;
};

/**
 * @deprecated Use getSignature. This method returns a Buffer which is the former
 * behavior of getSignature, and should only be used while updating your code.
 */
HmacWithSha256Signature.prototype.getSignatureAsBuffer = function()
{
  return this.signature_.buf();
};

/**
 * Set the key locator to a copy of the given keyLocator.
 * @param {KeyLocator} keyLocator The KeyLocator to copy.
 */
HmacWithSha256Signature.prototype.setKeyLocator = function(keyLocator)
{
  this.keyLocator_.set(typeof keyLocator === 'object' &&
                       keyLocator instanceof KeyLocator ?
    new KeyLocator(keyLocator) : new KeyLocator());
  ++this.changeCount_;
};

/**
 * Set the data packet's signature bytes.
 * @param {Blob} signature
 */
HmacWithSha256Signature.prototype.setSignature = function(signature)
{
  this.signature_ = typeof signature === 'object' && signature instanceof Blob ?
    signature : new Blob(signature);
  ++this.changeCount_;
};

/**
 * Get the change count, which is incremented each time this object (or a child
 * object) is changed.
 * @return {number} The change count.
 */
HmacWithSha256Signature.prototype.getChangeCount = function()
{
  // Make sure each of the checkChanged is called.
  var changed = this.keyLocator_.checkChanged();
  if (changed)
    // A child object has changed, so update the change count.
    ++this.changeCount_;

  return this.changeCount_;
};

// Define properties so we can change member variable types and implement changeCount_.
Object.defineProperty(HmacWithSha256Signature.prototype, "keyLocator",
  { get: function() { return this.getKeyLocator(); },
    set: function(val) { this.setKeyLocator(val); } });
/**
 * @@deprecated Use getSignature and setSignature.
 */
Object.defineProperty(HmacWithSha256Signature.prototype, "signature",
  { get: function() { return this.getSignatureAsBuffer(); },
    set: function(val) { this.setSignature(val); } });
