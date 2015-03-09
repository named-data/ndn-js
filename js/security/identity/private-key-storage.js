/**
 * Copyright (C) 2014-2015 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx security by Yingdi Yu <yingdi@cs.ucla.edu>.
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

/**
 * PrivateKeyStorage is an abstract class which declares methods for working
 * with a private key storage. You should use a subclass.
 * @constructor
 */
var PrivateKeyStorage = function PrivateKeyStorage()
{
};

exports.PrivateKeyStorage = PrivateKeyStorage;

/**
 * Generate a pair of asymmetric keys.
 * @param {Name} keyName The name of the key pair.
 * @param {KeyParams} params (optional) The parameters of the key.
 */
PrivateKeyStorage.prototype.generateKeyPair = function(keyName, params)
{
  throw new Error("PrivateKeyStorage.generateKeyPair is not implemented");
};

/**
 * Delete a pair of asymmetric keys. If the key doesn't exist, do nothing.
 * @param {Name} keyName The name of the key pair.
 */
PrivateKeyStorage.prototype.deleteKeyPair = function(keyName)
{
  throw new Error("PrivateKeyStorage.deleteKeyPair is not implemented");
};

/**
 * Get the public key
 * @param {Name} keyName The name of public key.
 * @returns {PublicKey} The public key.
 */
PrivateKeyStorage.prototype.getPublicKey = function(keyName)
{
  throw new Error("PrivateKeyStorage.getPublicKey is not implemented");
};

/**
 * Fetch the private key for keyName and sign the data to produce a signature Blob.
 * @param {Buffer} data Pointer to the input byte array.
 * @param {Name} keyName The name of the signing key.
 * @param {number} digestAlgorithm (optional) The digest algorithm from
 * DigestAlgorithm, such as DigestAlgorithm.SHA256. If omitted, use
 * DigestAlgorithm.SHA256.
 * @param {function} onComplete (optional) This calls onComplete(signature) with
 * the signature Blob. If omitted, the return value is the signature Blob. (Some
 * crypto libraries only use a callback, so onComplete is required to use these.)
 * @returns {Blob} If onComplete is omitted, return the signature Blob. Otherwise,
 * return null and use onComplete as described above.
 */
PrivateKeyStorage.prototype.sign = function
  (data, keyName, digestAlgorithm, onComplete)
{
  throw new Error("PrivateKeyStorage.sign is not implemented");
};

/**
 * Decrypt data.
 * @param {Name} keyName The name of the decrypting key.
 * @param {Buffer} data The byte to be decrypted.
 * @param {boolean} isSymmetric (optional) If true symmetric encryption is used,
 * otherwise asymmetric encryption is used. If omitted, use asymmetric
 * encryption.
 * @returns {Blob} The decrypted data.
 */
PrivateKeyStorage.prototype.decrypt = function(keyName, data, isSymmetric)
{
  throw new Error("PrivateKeyStorage.decrypt is not implemented");
};

/**
 * Encrypt data.
 * @param {Name} keyName The name of the encrypting key.
 * @param {Buffer} data The byte to be encrypted.
 * @param {boolean} isSymmetric (optional) If true symmetric encryption is used,
 * otherwise asymmetric encryption is used. If omitted, use asymmetric
 * encryption.
 * @returns {Blob} The encrypted data.
 */
PrivateKeyStorage.prototype.encrypt = function(keyName, data, isSymmetric)
{
  throw new Error("PrivateKeyStorage.encrypt is not implemented");
};

/**
 * @brief Generate a symmetric key.
 * @param {Name} keyName The name of the key.
 * @param {KeyParams} params The parameters of the key.
 */
PrivateKeyStorage.prototype.generateKey = function(keyName, params)
{
  throw new Error("PrivateKeyStorage.generateKey is not implemented");
};

/**
 * Check if a particular key exists.
 * @param {Name} keyName The name of the key.
 * @param {number} keyClass The class of the key, e.g. KeyClass.PUBLIC,
 * KeyClass.PRIVATE, or KeyClass.SYMMETRIC.
 * @returns {boolean} True if the key exists, otherwise false.
 */
PrivateKeyStorage.prototype.doesKeyExist = function(keyName, keyClass)
{
  throw new Error("PrivateKeyStorage.doesKeyExist is not implemented");
};
