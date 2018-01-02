/**
 * This class represents an NDN Data Signature object.
 * Copyright (C) 2014-2018 Regents of the University of California.
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
var Blob = require('./util/blob.js').Blob;

/**
 * A DigestSha256Signature extends Signature and holds the signature bits (which
 * are only the SHA256 digest) and an empty SignatureInfo for a data packet or
 * signed interest.
 *
 * Create a new DigestSha256Signature object, possibly copying values from
 * another object.
 *
 * @param {DigestSha256Signature} value (optional) If value is a
 * DigestSha256Signature, copy its values.  If value is omitted, the signature
 * is unspecified.
 * @constructor
 */
var DigestSha256Signature = function DigestSha256Signature(value)
{
  if (typeof value === 'object' && value instanceof DigestSha256Signature)
    // Copy the values.
    this.signature_ = value.signature_;
  else
    this.signature_ = new Blob();

  this.changeCount_ = 0;
};

exports.DigestSha256Signature = DigestSha256Signature;

/**
 * Create a new DigestSha256Signature which is a copy of this object.
 * @return {DigestSha256Signature} A new object which is a copy of this object.
 */
DigestSha256Signature.prototype.clone = function()
{
  return new DigestSha256Signature(this);
};

/**
 * Get the signature bytes (which are only the digest).
 * @return {Blob} The signature bytes. If not specified, the value isNull().
 */
DigestSha256Signature.prototype.getSignature = function()
{
  return this.signature_;
};

/**
 * Set the signature bytes to the given value.
 * @param {Blob} signature
 */
DigestSha256Signature.prototype.setSignature = function(signature)
{
  this.signature_ = typeof signature === 'object' && signature instanceof Blob ?
    signature : new Blob(signature);
  ++this.changeCount_;
};

/**
 * Get the change count, which is incremented each time this object is changed.
 * @return {number} The change count.
 */
DigestSha256Signature.prototype.getChangeCount = function()
{
  return this.changeCount_;
};

// Define properties so we can change member variable types and implement changeCount_.
/**
 * @@deprecated Use getSignature and setSignature.
 */
Object.defineProperty(DigestSha256Signature.prototype, "signature",
  { get: function() { return this.getSignature(); },
    set: function(val) { this.setSignature(val); } });
