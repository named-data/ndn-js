/**
 * Copyright (C) 2017 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/tpm/key-handle.cpp
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
var Name = require('../../name.js').Name; /** @ignore */
var SyncPromise = require('../../util/sync-promise.js').SyncPromise;

/**
 * TpmKeyHandle is an abstract base class for a TPM key handle, which provides
 * an interface to perform cryptographic operations with a key in the TPM.
 * @constructor
 */
var TpmKeyHandle = function TpmKeyHandle()
{
  this.keyName_ = new Name();
};

exports.TpmKeyHandle = TpmKeyHandle;

/**
 * Compute a digital signature from the byte buffer using this key with
 * digestAlgorithm.
 * @param {Buffer} data The input byte buffer.
 * @param {number} digestAlgorithm The digest algorithm as an int from the
 * DigestAlgorithm enum.
 * @return {Promise|SyncPromise} A promise which returns the signature Blob (or
 * an isNull Blob for an unrecognized digestAlgorithm), or a promise rejected
 * with TpmBackEnd.Error for an error in signing.
 */
TpmKeyHandle.prototype.signPromise = function(digestAlgorithm, data)
{
  return this.doSignPromise_(digestAlgorithm, data);
};

/**
 * Return the plain text which is decrypted from cipherText using this key.
 * @param {Buffer} cipherText The cipher text byte buffer.
 * @return {Promise|SyncPromise} A promise which returns the decrypted data Blob,
 * or a promise rejected with TpmPrivateKey.Error for error decrypting.
 */
TpmKeyHandle.prototype.decryptPromise = function(cipherText)
{
  return this.doDecryptPromise_(cipherText);
};

/**
 * Get the encoded public key derived from this key.
 * @return {Blob} The public key encoding Blob.
 */
TpmKeyHandle.prototype.derivePublicKey = function()
{
  return this.doDerivePublicKey_();
};

TpmKeyHandle.prototype.setKeyName = function(keyName)
{
  this.keyName_ = new Name(keyName);
};

TpmKeyHandle.prototype.getKeyName = function() { return this.keyName_; };

/**
 * A protected method to do the work of sign().
 * @param {Buffer} data The input byte buffer.
 * @param {number} digestAlgorithm The digest algorithm as an int from the
 * DigestAlgorithm enum.
 * @return {Promise|SyncPromise} A promise which returns the signature Blob (or
 * an isNull Blob for an unrecognized digestAlgorithm), or a promise rejected
 * with TpmBackEnd.Error for an error in signing.
 */
TpmKeyHandle.prototype.doSignPromise_ = function(digestAlgorithm, data)
{
  return SyncPromise.reject(new Error
    ("TpmKeyHandle.doSignPromise_ is not implemented"));
};

/**
 * A protected method to do the work of decrypt().
 * @param {Buffer} cipherText The cipher text byte buffer.
 * @return {Promise|SyncPromise} A promise which returns the decrypted data Blob,
 * or a promise rejected with TpmPrivateKey.Error for error decrypting.
 */
TpmKeyHandle.prototype.doDecryptPromise_ = function(cipherText)
{
  return SyncPromise.reject(new Error
    ("TpmKeyHandle.doDecryptPromise_ is not implemented"));
};

/**
 * A protected method to do the work of derivePublicKey().
 * @returns {Blob} The public key encoding Blob.
 */
TpmKeyHandle.prototype.doDerivePublicKey_ = function()
{
  return SyncPromise.reject(new Error
    ("TpmKeyHandle.doDerivePublicKey_ is not implemented"));
};
