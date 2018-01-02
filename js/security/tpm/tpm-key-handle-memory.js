/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/tpm/key-handle-mem.cpp
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
var Blob = require('../../util/blob.js').Blob; /** @ignore */
var SyncPromise = require('../../util/sync-promise.js').SyncPromise; /** @ignore */
var DigestAlgorithm = require('../security-types.js').DigestAlgorithm; /** @ignore */
var TpmPrivateKey = require('./tpm-private-key.js').TpmPrivateKey; /** @ignore */
var TpmBackEnd = require('./tpm-back-end.js').TpmBackEnd; /** @ignore */
var TpmKeyHandle = require('./tpm-key-handle.js').TpmKeyHandle;

/**
 * TpmKeyHandleMemory extends TpmKeyHandle to implement a TPM key handle that
 * keeps the private key in memory.
 *
 * Create a TpmKeyHandleMemory to use the given in-memory key.
 * @param {TpmPrivateKey} key The in-memory key.
 * @constructor
 */
var TpmKeyHandleMemory = function TpmKeyHandleMemory(key)
{
  // Call the base constructor.
  TpmKeyHandle.call(this);

  if (key == null)
    throw new Error("The key is null");

  this.key_ = key;
};

TpmKeyHandleMemory.prototype = new TpmKeyHandle();
TpmKeyHandleMemory.prototype.name = "TpmKeyHandleMemory";

exports.TpmKeyHandleMemory = TpmKeyHandleMemory;

/**
 * A protected method to do the work of sign().
 * @param {number} digestAlgorithm The digest algorithm as an int from the
 * DigestAlgorithm enum.
 * @param {Buffer} data The input byte buffer.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the signature Blob (or
 * an isNull Blob for an unrecognized digestAlgorithm), or a promise rejected
 * with TpmBackEnd.Error for an error in signing.
 */
TpmKeyHandleMemory.prototype.doSignPromise_ = function
  (digestAlgorithm, data, useSync)
{
  if (digestAlgorithm == DigestAlgorithm.SHA256) {
    return this.key_.signPromise(data, digestAlgorithm, useSync)
    .catch(function(err) {
      return SyncPromise.reject(new TpmBackEnd.Error(new Error
        ("Error in TpmPrivateKey.sign: " + err)));
    });
  }
  else
    return SyncPromise.resolve(new Blob());
};

/**
 * A protected method to do the work of decrypt().
 * @param {Buffer} cipherText The cipher text byte buffer.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the decrypted data Blob,
 * or a promise rejected with TpmPrivateKey.Error for error decrypting.
 */
TpmKeyHandleMemory.prototype.doDecryptPromise_ = function(cipherText, useSync)
{
  return this.key_.decryptPromise(cipherText, useSync)
  .catch(function(err) {
    return SyncPromise.reject(new TpmBackEnd.Error(new Error
      ("Error in TpmPrivateKey.decrypt: " + err)));
  });
};

/**
 * A protected method to do the work of derivePublicKey().
 * @return {Blob} The public key encoding Blob.
 */
TpmKeyHandle.prototype.doDerivePublicKey_ = function()
{
  try {
    return this.key_.derivePublicKey();
  } catch (ex) {
    throw new TpmBackEnd.Error(new Error
      ("Error in TpmPrivateKey.derivePublicKey: " + ex));
  }
};
