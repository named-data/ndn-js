/**
 * Copyright (C) 2014-2018 Regents of the University of California.
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

// Use capitalized Crypto to not clash with the browser's crypto.subtle.
/** @ignore */
var cryptoConstants = require('crypto').constants; /** @ignore */
var Crypto = require('../../crypto.js'); /** @ignore */
var Blob = require('../../util/blob.js').Blob; /** @ignore */
var DerNode = require('../../encoding/der/der-node.js').DerNode; /** @ignore */
var SecurityException = require('../security-exception.js').SecurityException; /** @ignore */
var UnrecognizedKeyFormatException = require('../security-exception.js').UnrecognizedKeyFormatException; /** @ignore */
var KeyType = require('../security-types.js').KeyType; /** @ignore */
var EncryptAlgorithmType = require('../../encrypt/algo/encrypt-params.js').EncryptAlgorithmType; /** @ignore */
var SyncPromise = require('../../util/sync-promise.js').SyncPromise; /** @ignore */
var UseSubtleCrypto = require('../../use-subtle-crypto-node.js').UseSubtleCrypto; /** @ignore */
var DigestAlgorithm = require('../security-types.js').DigestAlgorithm;

/**
 * Create a new PublicKey by decoding the keyDer. Set the key type from the
 * decoding.
 * @param {Blob} keyDer The blob of the SubjectPublicKeyInfo DER.
 * @throws UnrecognizedKeyFormatException if can't decode the key DER.
 * @constructor
 */
var PublicKey = function PublicKey(keyDer)
{
  if (!keyDer) {
    this.keyDer = new Blob();
    this.keyType = null;
    return;
  }

  this.keyDer = keyDer;

  // Get the public key OID.
  var oidString = null;
  try {
    var parsedNode = DerNode.parse(keyDer.buf(), 0);
    var rootChildren = parsedNode.getChildren();
    var algorithmIdChildren = DerNode.getSequence(rootChildren, 0).getChildren();
    oidString = algorithmIdChildren[0].toVal();
  }
  catch (ex) {
    throw new UnrecognizedKeyFormatException(new Error
      ("PublicKey.decodeKeyType: Error decoding the public key: " + ex.message));
  }

  // Verify that the we can decode.
  if (oidString == PublicKey.RSA_ENCRYPTION_OID) {
    this.keyType = KeyType.RSA;
    // TODO: Check RSA decoding.
  }
  else if (oidString == PublicKey.EC_ENCRYPTION_OID) {
    this.keyType = KeyType.EC;
    // TODO: Check EC decoding.
  }
};

exports.PublicKey = PublicKey;

/**
 * Encode the public key into DER.
 * @return {DerNode} The encoded DER syntax tree.
 */
PublicKey.prototype.toDer = function()
{
  return DerNode.parse(this.keyDer.buf());
};

/**
 * Get the key type.
 * @return {number} The key type as an int from KeyType.
 */
PublicKey.prototype.getKeyType = function()
{
  return this.keyType;
};

/**
 * Get the digest of the public key.
 * @param {number} digestAlgorithm (optional) The integer from DigestAlgorithm,
 * such as DigestAlgorithm.SHA256. If omitted, use DigestAlgorithm.SHA256 .
 * @return {Blob} The digest value.
 */
PublicKey.prototype.getDigest = function(digestAlgorithm)
{
  if (digestAlgorithm == undefined)
    digestAlgorithm = DigestAlgorithm.SHA256;

  if (digestAlgorithm == DigestAlgorithm.SHA256) {
    var hash = Crypto.createHash('sha256');
    hash.update(this.keyDer.buf());
    return new Blob(hash.digest(), false);
  }
  else
    throw new SecurityException(new Error("Wrong format!"));
};

/**
 * Get the raw bytes of the public key in DER format.
 * @return {Blob} The public key DER.
 */
PublicKey.prototype.getKeyDer = function()
{
  return this.keyDer;
};

/**
 * Encrypt the plainData using the keyBits according the encrypt algorithm type.
 * @param {Blob|Buffer} plainData The data to encrypt.
 * @param {number} algorithmType The algorithm type from the
 * EncryptAlgorithmType enum, e.g., RsaOaep.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the encrypted Blob.
 */
PublicKey.prototype.encryptPromise = function(plainData, algorithmType, useSync)
{
  if (typeof plainData === 'object' && plainData instanceof Blob)
    plainData = plainData.buf();

  if (UseSubtleCrypto() && !useSync &&
      // Crypto.subtle doesn't implement PKCS1 padding.
      algorithmType != EncryptAlgorithmType.RsaPkcs) {
    if (algorithmType == EncryptAlgorithmType.RsaOaep) {
      if (this.keyType != KeyType.RSA)
        return Promise.reject(new Error("The key type must be RSA"));

      return crypto.subtle.importKey
        ("spki", this.keyDer.buf(), { name: "RSA-OAEP", hash: {name: "SHA-1"} },
         false, ["encrypt"])
      .then(function(publicKey) {
        return crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, plainData);
      })
      .then(function(result) {
        return Promise.resolve(new Blob(new Uint8Array(result), false));
      });
    }
    else
      return Promise.reject(new Error("unsupported padding scheme"));
  }
  else {
    // Encode the key DER as a PEM public key as needed by Crypto.
    var keyBase64 = this.keyDer.buf().toString('base64');
    var keyPem = "-----BEGIN PUBLIC KEY-----\n";
    for (var i = 0; i < keyBase64.length; i += 64)
      keyPem += (keyBase64.substr(i, 64) + "\n");
    keyPem += "-----END PUBLIC KEY-----";

    var padding;
    if (algorithmType == EncryptAlgorithmType.RsaPkcs) {
      if (this.keyType != KeyType.RSA)
        return SyncPromise.reject(new Error("The key type must be RSA"));

      padding = cryptoConstants.RSA_PKCS1_PADDING;
    }
    else if (algorithmType == EncryptAlgorithmType.RsaOaep) {
      if (this.keyType != KeyType.RSA)
        return SyncPromise.reject(new Error("The key type must be RSA"));

      padding = cryptoConstants.RSA_PKCS1_OAEP_PADDING;
    }
    else
      return SyncPromise.reject(new Error("unsupported padding scheme"));

    try {
      // In Node.js, publicEncrypt requires version v0.12.
      return SyncPromise.resolve(new Blob
        (Crypto.publicEncrypt({ key: keyPem, padding: padding }, plainData),
         false));
    } catch (err) {
      return SyncPromise.reject(err);
    }
  }
};

/**
 * Encrypt the plainData using the keyBits according the encrypt algorithm type.
 * @param {Blob|Buffer} plainData The data to encrypt.
 * @param {number} algorithmType The algorithm type from the
 * EncryptAlgorithmType enum, e.g., RsaOaep.
 * @return {Blob} The encrypted data.
 * @throws Error If encryptPromise doesn't return a SyncPromise which is
 * already fulfilled.
 */
PublicKey.prototype.encrypt = function(plainData, algorithmType)
{
  return SyncPromise.getValue(this.encryptPromise
    (plainData, algorithmType, true));
};

PublicKey.RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.1";
PublicKey.EC_ENCRYPTION_OID = "1.2.840.10045.2.1";
