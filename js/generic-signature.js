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
var Blob = require('./util/blob.js').Blob;

/**
 * A GenericSignature extends Signature and holds the encoding bytes of the
 * SignatureInfo so that the application can process experimental signature
 * types. When decoding a packet, if the type of SignatureInfo is not
 * recognized, the library creates a GenericSignature.
 * Create a new GenericSignature object, possibly copying values from another
 * object.
 *
 * @param {GenericSignature} value (optional) If value is a GenericSignature,
 * copy its values.
 * @constructor
 */
var GenericSignature = function GenericSignature(value)
{
  if (typeof value === 'object' && value instanceof GenericSignature) {
    // Copy the values.
    this.signature_ = value.signature_;
    this.signatureInfoEncoding_ = value.signatureInfoEncoding_;
    this.typeCode_ = value.typeCode_;
  }
  else {
    this.signature_ = new Blob();
    this.signatureInfoEncoding_ = new Blob();
    this.typeCode_ = null;
  }

  this.changeCount_ = 0;
};

exports.GenericSignature = GenericSignature;

/**
 * Create a new GenericSignature which is a copy of this object.
 * @return {GenericSignature} A new object which is a copy of this object.
 */
GenericSignature.prototype.clone = function()
{
  return new GenericSignature(this);
};

/**
 * Get the data packet's signature bytes.
 * @return {Blob} The signature bytes. If not specified, the value isNull().
 */
GenericSignature.prototype.getSignature = function()
{
  return this.signature_;
};

/**
 * @deprecated Use getSignature. This method returns a Buffer which is the former
 * behavior of getSignature, and should only be used while updating your code.
 */
GenericSignature.prototype.getSignatureAsBuffer = function()
{
  return this.signature_.buf();
};

/**
 * Get the bytes of the entire signature info encoding (including the type
 * code).
 * @return {Blob} The encoding bytes. If not specified, the value isNull().
 */
GenericSignature.prototype.getSignatureInfoEncoding = function()
{
  return this.signatureInfoEncoding_;
};

/**
 * Get the type code of the signature type. When wire decode calls
 * setSignatureInfoEncoding, it sets the type code. Note that the type code
 * is ignored during wire encode, which simply uses getSignatureInfoEncoding()
 * where the encoding already has the type code.
 * @return {number} The type code, or null if not known.
 */
GenericSignature.prototype.getTypeCode = function() { return this.typeCode_; };

/**
 * Set the data packet's signature bytes.
 * @param {Blob} signature
 */
GenericSignature.prototype.setSignature = function(signature)
{
  this.signature_ = typeof signature === 'object' && signature instanceof Blob ?
    signature : new Blob(signature);
  ++this.changeCount_;
};

/**
 * Set the bytes of the entire signature info encoding (including the type
 * code).
 * @param {Blob} signatureInfoEncoding A Blob with the encoding bytes.
 * @param {number} (optional) The type code of the signature type, or null if
 * not known. (When a GenericSignature is created by wire decoding, it sets
 * the typeCode.)
 */
GenericSignature.prototype.setSignatureInfoEncoding = function
  (signatureInfoEncoding, typeCode)
{
  this.signatureInfoEncoding_ =
    typeof signatureInfoEncoding === 'object' && signatureInfoEncoding instanceof Blob ?
      signatureInfoEncoding : new Blob(signatureInfoEncoding);
  this.typeCode_ = typeCode;
  ++this.changeCount_;
};

/**
 * Get the change count, which is incremented each time this object (or a child
 * object) is changed.
 * @return {number} The change count.
 */
GenericSignature.prototype.getChangeCount = function()
{
  return this.changeCount_;
};

/**
 * @@deprecated Use getSignature and setSignature.
 */
Object.defineProperty(GenericSignature.prototype, "signature",
  { get: function() { return this.getSignatureAsBuffer(); },
    set: function(val) { this.setSignature(val); } });
