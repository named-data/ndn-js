/**
 * Copyright (C) 2014-2015 Regents of the University of California.
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

var Crypto = require('../../crypto.js');
var Blob = require('../../util/blob.js').Blob;

var EncryptionMode = function EncryptionMode()
{
}

exports.EncryptionMode = EncryptionMode;

EncryptionMode.ECB_AES = 0;
EncryptionMode.CBC_AES = 1;
EncryptionMode.RSA = 2;

var PaddingScheme = function PaddingScheme()
{
}

exports.PaddingScheme = PaddingScheme;

PaddingScheme.PKCS7 = 0;
PaddingScheme.PKCS1v15 = 1;
PaddingScheme.OAEP_SHA = 2;

/**
 * An EncryptParams holds an encryption mode and other parameters used to
 * encrypt and decrypt. Create an EncryptParams with the given parameters.
 * @param {number} encryptionMode The encryption mode from EncryptionMode.
 * @param {number} paddingScheme The padding scheme from PaddingScheme.
 * @param {number} The initial vector length, or 0 if the initial vector is not
 * specified.
 * @note This class is an experimental feature. The API may change.
 * @constructor
 */
var EncryptParams = function EncryptParams
  (encryptionMode, paddingScheme, initialVectorLength)
{
  this.encryptionMode_ = encryptionMode;
  this.paddingScheme_ = paddingScheme;

  if (initialVectorLength != null && initialVectorLength > 0) {
    var initialVector = Crypto.randomBytes(initialVectorLength);
    this.initialVector_ = new Blob(initialVector, false);
  }
  else
    this.initialVector_ = new Blob();
};

exports.EncryptParams = EncryptParams;

/**
 * Get the encryption mode.
 * @return {number} The encryption mode from EncryptionMode.
 */
EncryptParams.prototype.getEncryptionMode = function()
{
  return this.encryptionMode_;
};

/**
 * Get the padding scheme.
 * @return {number} The padding scheme from PaddingScheme.
 */
EncryptParams.prototype.getPaddingScheme = function()
{
  return this.paddingScheme_;
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
 * Set the encryption mode.
 * @param {number} encryptionMode The encryption mode from EncryptionMode.
 * @return {EncryptParams} This EncryptParams so that you can chain calls to
 * update values.
 */
EncryptParams.prototype.setEncryptionMode = function(encryptionMode)
{
  this.encryptionMode_ = encryptionMode;
  return this;
};

/**
 * Set the padding scheme.
 * @param {number} paddingScheme The padding scheme from PaddingScheme.
 * @return {EncryptParams} This EncryptParams so that you can chain calls to
 * update values.
 */
EncryptParams.prototype.setPaddingScheme = function(paddingScheme)
{
  this.paddingScheme_ = paddingScheme;
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
