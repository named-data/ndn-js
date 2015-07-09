/**
 * Copyright (C) 2015 Regents of the University of California.
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

var KeyLocator = require('../key-locator.js').KeyLocator;
var WireFormat = require('../encoding/wire-format.js').WireFormat;
var Blob = require('../util/blob').Blob;

/**
 * An EncryptedContent holds an encryption type, a payload and other fields
 * representing encrypted content.
 * @note This class is an experimental feature. The API may change.
 * @constructor
 */
var EncryptedContent = function EncryptedContent(value)
{
  if (typeof value === 'object' && value instanceof EncryptedContent) {
    // Make a deep copy.
    this.algorithmType_ = value.algorithmType_;
    this.keyLocator_ = new KeyLocator(value.keyLocator_);
    this.payload_ = value.payload_;
  }
  else {
    this.algorithmType_ = null;
    this.keyLocator_ = new KeyLocator();
    this.payload_ = new Blob();
  }
};

exports.EncryptedContent = EncryptedContent;

/**
 * Get the algorithm type.
 * @returns {number} The algorithm type, or null if not specified.
 */
EncryptedContent.prototype.getAlgorithmType = function()
{
  return this.algorithmType_;
};

/**
 * Get the key locator.
 * @returns {KeyLocator} The key locator. If not specified, getType() is null.
 */
EncryptedContent.prototype.getKeyLocator = function()
{
  return this.keyLocator_;
};

/**
 * Get the payload.
 * @returns {Blob} The payload. If not specified, isNull() is true.
 */
EncryptedContent.prototype.getPayload = function()
{
  return this.payload_;
};

/**
 * Set the algorithm type.
 * @param {number} algorithmType The algorithm type. If not specified, set to null.
 */
EncryptedContent.prototype.setAlgorithmType = function(algorithmType)
{
  return this.algorithmType_ = algorithmType;
};

/**
 * Set the key locator.
 * @param {KeyLocator} keyLocator The key locator. If not specified, set to the
 * default KeyLocator().
 */
EncryptedContent.prototype.setKeyLocator = function(keyLocator)
{
  this.keyLocator_ = typeof keyLocator === 'object' &&
                       keyLocator instanceof KeyLocator ?
    new KeyLocator(keyLocator) : new KeyLocator();
};

/**
 * Set the encrypted payload.
 * @param {Blob} payload The payload. If not specified, set to the default Blob()
 * where isNull() is true.
 */
EncryptedContent.prototype.setPayload = function(payload)
{
  this.payload_ = typeof payload === 'object' && payload instanceof Blob ?
    payload : new Blob(payload);
};

/**
 * Encode this EncryptedContent for a particular wire format.
 * @param {WireFormat} wireFormat (optional) A WireFormat object  used to encode
 * this object. If omitted, use WireFormat.getDefaultWireFormat().
 * @returns {Blob} The encoded buffer in a Blob object.
 */
EncryptedContent.prototype.wireEncode = function(wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
  return wireFormat.encodeEncryptedContent(this);
};

/**
 * Decode the input using a particular wire format and update this
 * EncryptedContent.
 * @param {Blob|Buffer} input The buffer with the bytes to decode.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to decode
 * this object. If omitted, use WireFormat.getDefaultWireFormat().
 */
EncryptedContent.prototype.wireDecode = function(input, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
  // If input is a blob, get its buf().
  var decodeBuffer = typeof input === 'object' && input instanceof Blob ?
                     input.buf() : input;
  wireFormat.decodeEncryptedContent(this, decodeBuffer);
};
