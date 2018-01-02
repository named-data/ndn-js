/**
 * Copyright (C) 2015-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt src/encrypted-content https://github.com/named-data/ndn-group-encrypt
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
var KeyLocator = require('../key-locator.js').KeyLocator; /** @ignore */
var WireFormat = require('../encoding/wire-format.js').WireFormat; /** @ignore */
var Blob = require('../util/blob.js').Blob;

/**
 * An EncryptedContent holds an encryption type, a payload and other fields
 * representing encrypted content.
 * @param {EncryptedContent} (optional) If value is another EncryptedContent
 * then copy it. If value is omitted then create an EncryptedContent with
 * unspecified values.
 * @note This class is an experimental feature. The API may change.
 * @constructor
 */
var EncryptedContent = function EncryptedContent(value)
{
  if (typeof value === 'object' && value instanceof EncryptedContent) {
    // Make a deep copy.
    this.algorithmType_ = value.algorithmType_;
    this.keyLocator_ = new KeyLocator(value.keyLocator_);
    this.initialVector_ = value.initialVector_;
    this.payload_ = value.payload_;
  }
  else {
    this.algorithmType_ = null;
    this.keyLocator_ = new KeyLocator();
    this.initialVector_ = new Blob();
    this.payload_ = new Blob();
  }
};

exports.EncryptedContent = EncryptedContent;

/**
 * Get the algorithm type from EncryptAlgorithmType.
 * @return {number} The algorithm type from EncryptAlgorithmType, or null if
 * not specified.
 */
EncryptedContent.prototype.getAlgorithmType = function()
{
  return this.algorithmType_;
};

/**
 * Get the key locator.
 * @return {KeyLocator} The key locator. If not specified, getType() is null.
 */
EncryptedContent.prototype.getKeyLocator = function()
{
  return this.keyLocator_;
};

/**
 * Get the initial vector.
 * @return {Blob} The initial vector. If not specified, isNull() is true.
 */
EncryptedContent.prototype.getInitialVector = function()
{
  return this.initialVector_;
};

/**
 * Get the payload.
 * @return {Blob} The payload. If not specified, isNull() is true.
 */
EncryptedContent.prototype.getPayload = function()
{
  return this.payload_;
};

/**
 * Set the algorithm type.
 * @param {number} algorithmType The algorithm type from EncryptAlgorithmType.
 * If not specified, set to null.
 * @return {EncryptedContent} This EncryptedContent so that you can chain calls
 * to update values.
 */
EncryptedContent.prototype.setAlgorithmType = function(algorithmType)
{
  this.algorithmType_ = algorithmType;
  return this;
};

/**
 * Set the key locator.
 * @param {KeyLocator} keyLocator The key locator. This makes a copy of the
 * object. If not specified, set to the default KeyLocator().
 * @return {EncryptedContent} This EncryptedContent so that you can chain calls
 * to update values.
 */
EncryptedContent.prototype.setKeyLocator = function(keyLocator)
{
  this.keyLocator_ = typeof keyLocator === 'object' &&
                       keyLocator instanceof KeyLocator ?
    new KeyLocator(keyLocator) : new KeyLocator();
  return this;
};

/**
 * Set the initial vector.
 * @param {Blob} initialVector The initial vector. If not specified, set to the
 * default Blob() where isNull() is true.
 * @return {EncryptedContent} This EncryptedContent so that you can chain calls
 * to update values.
 */
EncryptedContent.prototype.setInitialVector = function(initialVector)
{
  this.initialVector_ =
      typeof initialVector === 'object' && initialVector instanceof Blob ?
    initialVector : new Blob(initialVector);
  return this;
};

/**
 * Set the encrypted payload.
 * @param {Blob} payload The payload. If not specified, set to the default Blob()
 * where isNull() is true.
 * @return {EncryptedContent} This EncryptedContent so that you can chain calls
 * to update values.
 */
EncryptedContent.prototype.setPayload = function(payload)
{
  this.payload_ = typeof payload === 'object' && payload instanceof Blob ?
    payload : new Blob(payload);
  return this;
};

/**
 * Encode this EncryptedContent for a particular wire format.
 * @param {WireFormat} wireFormat (optional) A WireFormat object  used to encode
 * this object. If omitted, use WireFormat.getDefaultWireFormat().
 * @return {Blob} The encoded buffer in a Blob object.
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
  if (typeof input === 'object' && input instanceof Blob)
    // Input is a blob, so get its buf() and set copy false.
    wireFormat.decodeEncryptedContent(this, input.buf(), false);
  else
    wireFormat.decodeEncryptedContent(this, input, true);
};
