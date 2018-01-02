/**
 * Copyright (C) 2014-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt src/encrypt-params https://github.com/named-data/ndn-group-encrypt
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
var Crypto = require('../../crypto.js'); /** @ignore */
var Blob = require('../../util/blob.js').Blob;

var EncryptAlgorithmType = function EncryptAlgorithmType()
{
}

exports.EncryptAlgorithmType = EncryptAlgorithmType;

// These correspond to the TLV codes.
EncryptAlgorithmType.AesEcb = 0;
EncryptAlgorithmType.AesCbc = 1;
EncryptAlgorithmType.RsaPkcs = 2;
EncryptAlgorithmType.RsaOaep = 3;

/**
 * An EncryptParams holds an algorithm type and other parameters used to
 * encrypt and decrypt. Create an EncryptParams with the given parameters.
 * @param {number} algorithmType The algorithm type from EncryptAlgorithmType,
 * or null if not specified.
 * @param {number} initialVectorLength (optional) The initial vector length, or
 * 0 if the initial vector is not specified. If ommitted, the initial vector is
 * not specified.
 * @note This class is an experimental feature. The API may change.
 * @constructor
 */
var EncryptParams = function EncryptParams(algorithmType, initialVectorLength)
{
  this.algorithmType_ = algorithmType;

  if (initialVectorLength != null && initialVectorLength > 0) {
    var initialVector = Crypto.randomBytes(initialVectorLength);
    this.initialVector_ = new Blob(initialVector, false);
  }
  else
    this.initialVector_ = new Blob();
};

exports.EncryptParams = EncryptParams;

/**
 * Get the algorithmType.
 * @return {number} The algorithm type from EncryptAlgorithmType, or null if not
 * specified.
 */
EncryptParams.prototype.getAlgorithmType = function()
{
  return this.algorithmType_;
};

/**
 * Get the initial vector.
 * @return {Blob} The initial vector. If not specified, isNull() is true.
 */
EncryptParams.prototype.getInitialVector = function()
{
  return this.initialVector_;
};

/**
 * Set the algorithm type.
 * @param {number} algorithmType The algorithm type from EncryptAlgorithmType.
 * If not specified, set to null.
 * @return {EncryptParams} This EncryptParams so that you can chain calls to
 * update values.
 */
EncryptParams.prototype.setAlgorithmType = function(algorithmType)
{
  this.algorithmType_ = algorithmType;
  return this;
};

/**
 * Set the initial vector.
 * @param {Blob} initialVector The initial vector. If not specified, set to the
 * default Blob() where isNull() is true.
 * @return {EncryptParams} This EncryptParams so that you can chain calls to
 * update values.
 */
EncryptParams.prototype.setInitialVector = function(initialVector)
{
  this.initialVector_ =
      typeof initialVector === 'object' && initialVector instanceof Blob ?
    initialVector : new Blob(initialVector);
  return this;
};
