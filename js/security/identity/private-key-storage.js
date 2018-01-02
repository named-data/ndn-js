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

/** @ignore */
var SyncPromise = require('../../util/sync-promise.js').SyncPromise; /** @ignore */
var DerNode = require('../../encoding/der/der-node.js').DerNode;

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
 * @param {KeyParams} params The parameters of the key.
 * @param {boolean} (optional) useSync If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that fulfills when the pair is
 * generated.
 */
PrivateKeyStorage.prototype.generateKeyPairPromise = function
  (keyName, params, useSync)
{
  return SyncPromise.reject(new Error
    ("PrivateKeyStorage.generateKeyPairPromise is not implemented"));
};

/**
 * Generate a pair of asymmetric keys.
 * @param {Name} keyName The name of the key pair.
 * @param {KeyParams} params The parameters of the key.
 * @throws Error If generateKeyPairPromise doesn't return a SyncPromise which
 * is already fulfilled.
 */
PrivateKeyStorage.prototype.generateKeyPair = function(keyName, params)
{
  SyncPromise.getValue(this.generateKeyPairPromise(keyName, params, true));
};

/**
 * Delete a pair of asymmetric keys. If the key doesn't exist, do nothing.
 * @param {Name} keyName The name of the key pair.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that fulfills when the key pair is
 * deleted.
 */
PrivateKeyStorage.prototype.deleteKeyPairPromise = function(keyName, useSync)
{
  return SyncPromise.reject(new Error
    ("PrivateKeyStorage.deleteKeyPairPromise is not implemented"));
};

/**
 * Delete a pair of asymmetric keys. If the key doesn't exist, do nothing.
 * @param {Name} keyName The name of the key pair.
 * @throws Error If deleteKeyPairPromise doesn't return a SyncPromise which
 * is already fulfilled.
 */
PrivateKeyStorage.prototype.deleteKeyPair = function(keyName)
{
  SyncPromise.getValue(this.deleteKeyPairPromise(keyName, true));
};

/**
 * Get the public key
 * @param {Name} keyName The name of public key.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that returns the PublicKey.
 */
PrivateKeyStorage.prototype.getPublicKeyPromise = function(keyName, useSync)
{
  return SyncPromise.reject(new Error
    ("PrivateKeyStorage.getPublicKeyPromise is not implemented"));
};

/**
 * Get the public key
 * @param {Name} keyName The name of public key.
 * @return {PublicKey} The public key.
 * @throws Error If getPublicKeyPromise doesn't return a SyncPromise which
 * is already fulfilled.
 */
PrivateKeyStorage.prototype.getPublicKey = function(keyName)
{
  return SyncPromise.getValue(this.getPublicKeyPromise(keyName, true));
};

/**
 * Fetch the private key for keyName and sign the data to produce a signature Blob.
 * @param {Buffer} data Pointer to the input byte array.
 * @param {Name} keyName The name of the signing key.
 * @param {number} digestAlgorithm (optional) The digest algorithm from
 * DigestAlgorithm, such as DigestAlgorithm.SHA256. If omitted, use
 * DigestAlgorithm.SHA256.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that returns the signature Blob.
 */
PrivateKeyStorage.prototype.signPromise = function
  (data, keyName, digestAlgorithm, useSync)
{
  return SyncPromise.reject(new Error("PrivateKeyStorage.sign is not implemented"));
};

/**
 * Fetch the private key for keyName and sign the data to produce a signature Blob.
 * @param {Buffer} data Pointer to the input byte array.
 * @param {Name} keyName The name of the signing key.
 * @param {number} digestAlgorithm (optional) The digest algorithm from
 * DigestAlgorithm, such as DigestAlgorithm.SHA256. If omitted, use
 * DigestAlgorithm.SHA256.
 * @return {Blob} The signature Blob.
 * @throws Error If signPromise doesn't return a SyncPromise which is already
 * fulfilled.
 */
PrivateKeyStorage.prototype.sign = function(data, keyName, digestAlgorithm)
{
  return SyncPromise.getValue
    (this.signPromise(data, keyName, digestAlgorithm, true));
};

/**
 * Decrypt data.
 * @param {Name} keyName The name of the decrypting key.
 * @param {Buffer} data The byte to be decrypted.
 * @param {boolean} isSymmetric (optional) If true symmetric encryption is used,
 * otherwise asymmetric encryption is used. If omitted, use asymmetric
 * encryption.
 * @return {Blob} The decrypted data.
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
 * @return {Blob} The encrypted data.
 */
PrivateKeyStorage.prototype.encrypt = function(keyName, data, isSymmetric)
{
  throw new Error("PrivateKeyStorage.encrypt is not implemented");
};

/**
 * Generate a symmetric key.
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
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns true if the key exists.
 */
PrivateKeyStorage.prototype.doesKeyExistPromise = function
  (keyName, keyClass, useSync)
{
  return SyncPromise.reject(new Error
    ("PrivateKeyStorage.doesKeyExist is not implemented"));
};

/**
 * Check if a particular key exists.
 * @param {Name} keyName The name of the key.
 * @param {number} keyClass The class of the key, e.g. KeyClass.PUBLIC,
 * KeyClass.PRIVATE, or KeyClass.SYMMETRIC.
 * @return {boolean} True if the key exists.
 * @throws Error If doesKeyExistPromise doesn't return a SyncPromise which
 * is already fulfilled.
 */
PrivateKeyStorage.prototype.doesKeyExist = function(keyName, keyClass)
{
  return SyncPromise.getValue(this.doesKeyExistPromise(keyName, keyClass, true));
};

/**
 * Encode the private key to a PKCS #8 private key. We do this explicitly here
 * to avoid linking to extra OpenSSL libraries.
 * @param {Buffer} privateKeyDer The input private key DER.
 * @param {OID} oid The OID of the privateKey.
 * @param {DerNode} parameters The DerNode of the parameters for the OID.
 * @return {Blob} The PKCS #8 private key DER.
 */
PrivateKeyStorage.encodePkcs8PrivateKey = function
  (privateKeyDer, oid, parameters)
{
  var algorithmIdentifier = new DerNode.DerSequence();
  algorithmIdentifier.addChild(new DerNode.DerOid(oid));
  algorithmIdentifier.addChild(parameters);

  var result = new DerNode.DerSequence();
  result.addChild(new DerNode.DerInteger(0));
  result.addChild(algorithmIdentifier);
  result.addChild(new DerNode.DerOctetString(privateKeyDer));

  return result.encode();
};

/**
 * Encode the RSAKey private key as a PKCS #1 private key.
 * @param {RSAKey} rsaKey The RSAKey private key.
 * @return {Blob} The PKCS #1 private key DER.
 */
PrivateKeyStorage.encodePkcs1PrivateKeyFromRSAKey = function(rsaKey)
{
  // Imitate KJUR getEncryptedPKCS5PEMFromRSAKey.
  var result = new DerNode.DerSequence();

  result.addChild(new DerNode.DerInteger(0));
  result.addChild(new DerNode.DerInteger(PrivateKeyStorage.bigIntegerToBuffer(rsaKey.n)));
  result.addChild(new DerNode.DerInteger(rsaKey.e));
  result.addChild(new DerNode.DerInteger(PrivateKeyStorage.bigIntegerToBuffer(rsaKey.d)));
  result.addChild(new DerNode.DerInteger(PrivateKeyStorage.bigIntegerToBuffer(rsaKey.p)));
  result.addChild(new DerNode.DerInteger(PrivateKeyStorage.bigIntegerToBuffer(rsaKey.q)));
  result.addChild(new DerNode.DerInteger(PrivateKeyStorage.bigIntegerToBuffer(rsaKey.dmp1)));
  result.addChild(new DerNode.DerInteger(PrivateKeyStorage.bigIntegerToBuffer(rsaKey.dmq1)));
  result.addChild(new DerNode.DerInteger(PrivateKeyStorage.bigIntegerToBuffer(rsaKey.coeff)));

  return result.encode();
};

/**
 * Encode the public key values in the RSAKey private key as a
 * SubjectPublicKeyInfo.
 * @param {RSAKey} rsaKey The RSAKey private key with the public key values.
 * @return {Blob} The SubjectPublicKeyInfo DER.
 */
PrivateKeyStorage.encodePublicKeyFromRSAKey = function(rsaKey)
{
  var rsaPublicKey = new DerNode.DerSequence();

  rsaPublicKey.addChild(new DerNode.DerInteger(PrivateKeyStorage.bigIntegerToBuffer(rsaKey.n)));
  rsaPublicKey.addChild(new DerNode.DerInteger(rsaKey.e));

  var algorithmIdentifier = new DerNode.DerSequence();
  algorithmIdentifier.addChild
    (new DerNode.DerOid(new OID(PrivateKeyStorage.RSA_ENCRYPTION_OID)));
  algorithmIdentifier.addChild(new DerNode.DerNull());

  var result = new DerNode.DerSequence();

  result.addChild(algorithmIdentifier);
  result.addChild(new DerNode.DerBitString(rsaPublicKey.encode().buf(), 0));

  return result.encode();
};

/**
 * Convert a BigInteger to a Buffer.
 * @param {BigInteger} bigInteger The BigInteger.
 * @return {Buffer} The Buffer.
 */
PrivateKeyStorage.bigIntegerToBuffer = function(bigInteger)
{
  // Imitate KJUR.asn1.ASN1Util.bigIntToMinTwosComplementsHex.
  var hex = bigInteger.toString(16);
  if (hex.substr(0, 1) == "-")
    throw new Error
      ("PrivateKeyStorage.bigIntegerToBuffer: Negative integers are not currently supported");

  if (hex.length % 2 == 1)
    // Odd number of characters.
    hex = "0" + hex;
  else {
    if (! hex.match(/^[0-7]/))
      // The first byte is >= 0x80, so prepend a zero to keep it positive.
      hex = "00" + hex;
  }

  return new Buffer(hex, 'hex');
};

PrivateKeyStorage.RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.1";
PrivateKeyStorage.EC_ENCRYPTION_OID = "1.2.840.10045.2.1";
