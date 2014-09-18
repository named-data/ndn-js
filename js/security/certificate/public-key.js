/**
 * Copyright (C) 2014 Regents of the University of California.
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

var SecurityException = require('../security-exception.js').SecurityException;
var KeyType = require('../security-types.js').KeyType;

/**
 * A PublicKey holds an encoded public key for use by the security library.
 * Create a new PublicKey with the given values.
 * @param {number} keyType The integer from KeyType, such as KeyType.RSA.
 * @param {Blob} keyDer The blob of the PublicKeyInfo in terms of DER.
 */
var PublicKey = function PublicKey(keyType, keyDer)
{
  this.keyType = keyType;
  this.keyDer = keyDer;
};

exports.PublicKey = PublicKey;

/**
 * Encode the public key into DER.
 * @returns {DerNode} The encoded DER syntax tree.
 */
PublicKey.prototype.toDer = function()
{
  throw new Error("PublicKey.toDer is not implemented");
};

/**
 * Decode the public key from the DER blob.
 * @param {number} keyType The integer from KeyType, such as KeyType.RSA.
 * @param {Blob} keyDer The DER blob.
 * @returns {PublicKey} The decoded public key.
 */
PublicKey.fromDer = function(keyType, keyDer)
{
  if (keyType == KeyType.RSA) {
    // TODO: Make sure we can decode the public key DER.
  }
  else
    throw new SecurityException(new Error
      ("PublicKey::fromDer: Unrecognized keyType"));

  return new PublicKey(keyType, keyDer);
};

/**
 * 
 * @param {number} digestAlgorithm (optional) The integer from DigestAlgorithm, 
 * such as DigestAlgorithm.SHA256. If omitted, use DigestAlgorithm.SHA256 .
 * @returns {Blob} The digest value.
 */
PublicKey.prototype.getDigest = function(digestAlgorithm)
{
  throw new Error("PublicKey.getDigest is not implemented");
};

/**
 * Get the key type.
 * @returns {number} The key type as an int from KeyType.
 */
PublicKey.prototype.getKeyType = function()
{
  return this.keyType;
};

/**
 * Get the raw bytes of the public key in DER format.
 * @returns {Blob} The public key DER.
 */
PublicKey.prototype.getKeyDer = function()
{
  return this.keyDer;
};
