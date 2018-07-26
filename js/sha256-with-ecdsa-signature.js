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
var KeyLocator = require('./key-locator.js').KeyLocator; /** @ignore */
var ValidityPeriod = require('./security/validity-period.js').ValidityPeriod;

/**
 * Create a new Sha256WithEcdsaSignature object, possibly copying values from
 * another object.
 *
 * @param {Sha256WithEcdsaSignature} value (optional) If value is a
 * Sha256WithEcdsaSignature, copy its values.  If value is omitted, the
 * keyLocator is the default with unspecified values and the signature is
 * unspecified.
 * @constructor
 */
var Sha256WithEcdsaSignature = function Sha256WithEcdsaSignature(value)
{
  if (typeof value === 'object' && value instanceof Sha256WithEcdsaSignature) {
    // Copy the values.
    this.keyLocator_ = new ChangeCounter(new KeyLocator(value.getKeyLocator()));
    this.validityPeriod_ = new ChangeCounter(new ValidityPeriod
      (value.getValidityPeriod()));
    this.signature_ = value.signature_;
  }
  else {
    this.keyLocator_ = new ChangeCounter(new KeyLocator());
    this.validityPeriod_ = new ChangeCounter(new ValidityPeriod());
    this.signature_ = new Blob();
  }

  this.changeCount_ = 0;
};

exports.Sha256WithEcdsaSignature = Sha256WithEcdsaSignature;

/**
 * Create a new Sha256WithEcdsaSignature which is a copy of this object.
 * @return {Sha256WithEcdsaSignature} A new object which is a copy of this
 * object.
 */
Sha256WithEcdsaSignature.prototype.clone = function()
{
  return new Sha256WithEcdsaSignature(this);
};

/**
 * Get the key locator.
 * @return {KeyLocator} The key locator.
 */
Sha256WithEcdsaSignature.prototype.getKeyLocator = function()
{
  return this.keyLocator_.get();
};

/**
 * Get the validity period.
 * @return {ValidityPeriod} The validity period.
 */
Sha256WithEcdsaSignature.prototype.getValidityPeriod = function()
{
  return this.validityPeriod_.get();
};

/**
 * Get the data packet's signature bytes.
 * @return {Blob} The signature bytes. If not specified, the value isNull().
 */
Sha256WithEcdsaSignature.prototype.getSignature = function()
{
  return this.signature_;
};

/**
 * Set the key locator to a copy of the given keyLocator.
 * @param {KeyLocator} keyLocator The KeyLocator to copy.
 */
Sha256WithEcdsaSignature.prototype.setKeyLocator = function(keyLocator)
{
  this.keyLocator_.set(typeof keyLocator === 'object' &&
                       keyLocator instanceof KeyLocator ?
    new KeyLocator(keyLocator) : new KeyLocator());
  ++this.changeCount_;
};

/**
 * Set the validity period to a copy of the given ValidityPeriod.
 * @param {ValidityPeriod} validityPeriod The ValidityPeriod which is copied.
 */
Sha256WithEcdsaSignature.prototype.setValidityPeriod = function(validityPeriod)
{
  this.validityPeriod_.set(typeof validityPeriod === 'object' &&
                           validityPeriod instanceof ValidityPeriod ?
    new ValidityPeriod(validityPeriod) : new ValidityPeriod());
  ++this.changeCount_;
};

/**
 * Set the data packet's signature bytes.
 * @param {Blob} signature
 */
Sha256WithEcdsaSignature.prototype.setSignature = function(signature)
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
Sha256WithEcdsaSignature.prototype.getChangeCount = function()
{
  // Make sure each of the checkChanged is called.
  var changed = this.keyLocator_.checkChanged();
  changed = this.validityPeriod_.checkChanged() || changed;
  if (changed)
    // A child object has changed, so update the change count.
    ++this.changeCount_;

  return this.changeCount_;
};
