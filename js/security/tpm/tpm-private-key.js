/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From https://github.com/named-data/ndn-cxx/blob/master/src/security/transform/private-key.cpp
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
var KeyType = require('../security-types').KeyType; /** @ignore */
var EncryptAlgorithmType = require('../../encrypt/algo/encrypt-params.js').EncryptAlgorithmType; /** @ignore */
var DigestAlgorithm = require('../security-types.js').DigestAlgorithm; /** @ignore */
var DataUtils = require('../../encoding/data-utils.js').DataUtils; /** @ignore */
var SyncPromise = require('../../util/sync-promise.js').SyncPromise; /** @ignore */
var DerNode = require('../../encoding/der/der-node.js').DerNode; /** @ignore */
var DerInteger = require('../../encoding/der/der-node.js').DerNode.DerInteger; /** @ignore */
var OID = require('../../encoding/oid.js').OID; /** @ignore */
var Blob = require('../../util/blob.js').Blob; /** @ignore */
var UseSubtleCrypto = require('../../use-subtle-crypto-node.js').UseSubtleCrypto; /** @ignore */
var rsaKeygen = null;
try {
  // This should be installed with: sudo npm install rsa-keygen
  rsaKeygen = require('rsa-keygen');
}
catch (e) {}

/**
 * A TpmPrivateKey holds an in-memory private key and provides cryptographic
 * operations such as for signing by the in-memory TPM.
 *
 * Create an uninitialized TpmPrivateKey. You must call a load method to
 * initialize it, such as loadPkcs1.
 * @constructor
 */
var TpmPrivateKey = function TpmPrivateKey()
{
  this.keyType_ = null;    // number from KeyType
  this.privateKey_ = null; // The PEM-encoded private key.
  this.subtleKey_ = null;  // The internal Crypto.subtle form of the key.
  this.decryptSubtleKey_ = null; // The internal Crypto.subtle form of the key for decryption.
};

exports.TpmPrivateKey = TpmPrivateKey;

/**
 * Create a new TpmPrivateKey.Error to report an error in private key processing.
 * Call with: throw new TpmPrivateKey.Error(new Error("message")).
 * @constructor
 * @param {Error} error The exception created with new Error.
 */
TpmPrivateKey.Error = function TpmPrivateKeyError(error)
{
  if (error) {
    error.__proto__ = TpmPrivateKey.Error.prototype;
    return error;
  }
};

TpmPrivateKey.Error.prototype = new Error();
TpmPrivateKey.Error.prototype.name = "TpmPrivateKeyError";

/**
 * Load the unencrypted private key from a buffer with the PKCS #1 encoding.
 * This replaces any existing private key in this object.
 * @param {Buffer} encoding The byte buffer with the private key encoding.
 * @param {number} keyType (optional) The KeyType, such as KeyType.RSA. If
 * omitted or null, then partially decode the private key to determine the key
 * type.
 * @throws TpmPrivateKey.Error for errors decoding the key.
 */
TpmPrivateKey.prototype.loadPkcs1 = function(encoding, keyType)
{
  if (encoding instanceof Blob)
    encoding = encoding.buf();

  if (keyType == undefined) {
    // Try to determine the key type.
    try {
      var parsedNode = DerNode.parse(encoding);
      var children = parsedNode.getChildren();

      // An RsaPrivateKey has integer version 0 and 8 integers.
      if (children.length == 9 &&
          (children[0] instanceof DerInteger) &&
          children[0].toVal() == 0 &&
          (children[1] instanceof DerInteger) &&
          (children[2] instanceof DerInteger) &&
          (children[3] instanceof DerInteger) &&
          (children[4] instanceof DerInteger) &&
          (children[5] instanceof DerInteger) &&
          (children[6] instanceof DerInteger) &&
          (children[7] instanceof DerInteger) &&
          (children[8] instanceof DerInteger))
        keyType = KeyType.RSA;
      else
        // Assume it is an EC key. Try decoding it below.
        keyType = KeyType.EC;
    } catch (ex) {
      // Assume it is an EC key. Try decoding it below.
      keyType = KeyType.EC;
    }
  }

  if (keyType == KeyType.EC) {
    // Encode the DER as PEM.
    var keyBase64 = encoding.toString('base64');
    var keyPem = "-----BEGIN EC PRIVATE KEY-----\n";
    for (var i = 0; i < keyBase64.length; i += 64)
      keyPem += (keyBase64.substr(i, 64) + "\n");
    keyPem += "-----END EC PRIVATE KEY-----";

    this.privateKey_ = keyPem;
  }
  else if (keyType == KeyType.RSA) {
    // Encode the DER as PEM.
    var keyBase64 = encoding.toString('base64');
    var keyPem = "-----BEGIN RSA PRIVATE KEY-----\n";
    for (var i = 0; i < keyBase64.length; i += 64)
      keyPem += (keyBase64.substr(i, 64) + "\n");
    keyPem += "-----END RSA PRIVATE KEY-----";

    this.privateKey_ = keyPem;
  }
  else
    throw new TpmPrivateKey.Error(new Error
      ("loadPkcs1: Unrecognized keyType: " + keyType));

  this.keyType_ = keyType;
  this.subtleKey_ = null;
  this.decryptSubtleKey_ = null;
};

/**
 * Load the unencrypted private key from a buffer with the PKCS #8 encoding.
 * This replaces any existing private key in this object.
 * @param {Buffer} encoding The byte buffer with the private key encoding.
 * @param {number} keyType (optional) The KeyType, such as KeyType.RSA. If
 * omitted or null, then partially decode the private key to determine the key
 * type.
 * @throws TpmPrivateKey.Error for errors decoding the key.
 */
TpmPrivateKey.prototype.loadPkcs8 = function(encoding, keyType)
{
  if (encoding instanceof Blob)
    encoding = encoding.buf();

  var privateKeyDer;
  if (keyType == undefined) {
    // Decode the PKCS #8 private key to find the algorithm OID and the inner
    // private key DER.
    var oidString, algorithmParameters, privateKeyDer;
    try {
      var parsedNode = DerNode.parse(encoding);
      var pkcs8Children = parsedNode.getChildren();
      // Get the algorithm OID and parameters.
      var algorithmIdChildren = DerNode.getSequence(pkcs8Children, 1).getChildren();
      oidString = algorithmIdChildren[0].toVal();
      algorithmParameters = algorithmIdChildren[1];
      // Get the value of the 3rd child which is the octet string.
      privateKeyDer = pkcs8Children[2].toVal();
    } catch (ex) {
      // Error decoding as PKCS #8. Try PKCS #1 for backwards compatibility.
      try {
        this.loadPkcs1(encoding);
        return;
      } catch (ex) {
        throw new TpmPrivateKey.Error(new Error
          ("loadPkcs8: Error decoding private key: " + ex));
      }
    }

    if (oidString == TpmPrivateKey.EC_ENCRYPTION_OID)
      keyType = KeyType.EC;
    else if (oidString == TpmPrivateKey.RSA_ENCRYPTION_OID)
      keyType = KeyType.RSA;
    else
      throw new TpmPrivateKey.Error(new Error
        ("loadPkcs8: Unrecognized private key OID: " + oidString));
  }
  else {
    // Decode the PKCS #8 key to get the inner private key DER.
    var parsedNode = DerNode.parse(encoding);
    // Get the value of the 3rd child which is the octet string.
    privateKeyDer = parsedNode.getChildren()[2].toVal();
  }

  this.loadPkcs1(privateKeyDer, keyType);
};

/**
 * Get the encoded public key for this private key.
 * @return {Blob} The public key encoding Blob.
 * @throws TpmPrivateKey.Error if no private key is loaded, or error converting
 * to a public key.
 */
TpmPrivateKey.prototype.derivePublicKey = function()
{
  if (this.keyType_ != KeyType.RSA)
    throw new TpmPrivateKey.Error(new Error
      ("derivePublicKey: The private key is not loaded"));

  try {
    var rsaPrivateKeyDer = DataUtils.privateKeyPemToDer(this.privateKey_);

    // Decode the PKCS #1 RSAPrivateKey.
    var parsedNode = DerNode.parse(rsaPrivateKeyDer, 0);
    var rsaPrivateKeyChildren = parsedNode.getChildren();
    var modulus = rsaPrivateKeyChildren[1];
    var publicExponent = rsaPrivateKeyChildren[2];

    // Encode the PKCS #1 RSAPublicKey.
    var rsaPublicKey = new DerNode.DerSequence();
    rsaPublicKey.addChild(modulus);
    rsaPublicKey.addChild(publicExponent);
    var rsaPublicKeyDer = rsaPublicKey.encode();

    // Encode the SubjectPublicKeyInfo.
    var algorithmIdentifier = new DerNode.DerSequence();
    algorithmIdentifier.addChild(new DerNode.DerOid(new OID
      (TpmPrivateKey.RSA_ENCRYPTION_OID)));
    algorithmIdentifier.addChild(new DerNode.DerNull());
    var publicKey = new DerNode.DerSequence();
    publicKey.addChild(algorithmIdentifier);
    publicKey.addChild(new DerNode.DerBitString(rsaPublicKeyDer.buf(), 0));

    return publicKey.encode();
  } catch (ex) {
    // We don't expect this to happen since the key was encoded here.
    throw new TpmPrivateKey.Error(new Error
      ("derivePublicKey: Error decoding private key " + ex));
  }
};

/**
 * Decrypt the cipherText using this private key according the encryption
 * algorithmType. Only RSA encryption is supported for now.
 * @param {Buffer} cipherText The cipher text byte buffer.
 * @param {number} algorithmType (optional) This decrypts according to
 * algorithmType which is an int from the EncryptAlgorithmType enum. If omitted,
 * use RsaOaep.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the decrypted data Blob,
 * or a promise rejected with TpmPrivateKey.Error if the private key is not
 * loaded, if decryption is not supported for this key type, or for error
 * decrypting.
 */
TpmPrivateKey.prototype.decryptPromise = function
  (cipherText, algorithmType, useSync)
{
  if (typeof algorithmType === 'boolean') {
    // algorithmType is omitted, so shift.
    useSync = algorithmType;
    algorithmType = undefined;
  }

  if (algorithmType == undefined)
    algorithmType = EncryptAlgorithmType.RsaOaep;

  if (this.keyType_ == null)
    return SyncPromise.reject(new TpmPrivateKey.Error(new Error
      ("decrypt: The private key is not loaded")));

  if (UseSubtleCrypto() && !useSync &&
      // Crypto.subtle doesn't implement PKCS1 padding.
      algorithmType != EncryptAlgorithmType.RsaPkcs) {
    if (algorithmType == EncryptAlgorithmType.RsaOaep) {
      return this.getDecryptSubtleKeyPromise_()
      .then(function(subtleKey) {
        return crypto.subtle.decrypt
          ({ name: "RSA-OAEP" }, subtleKey, cipherText);
      })
      .then(function(result) {
        return Promise.resolve(new Blob(new Uint8Array(result), false));
      });
    }
    else
      return Promise.reject(new Error("Unsupported padding scheme"));
  }
  else {
    var padding;
    if (algorithmType == EncryptAlgorithmType.RsaPkcs)
      padding = cryptoConstants.RSA_PKCS1_PADDING;
    else if (algorithmType == EncryptAlgorithmType.RsaOaep)
      padding = cryptoConstants.RSA_PKCS1_OAEP_PADDING;
    else
      return SyncPromise.reject(new TpmPrivateKey.Error(new Error
        ("Unsupported padding scheme")));

    try {
      // In Node.js, privateDecrypt requires version v0.12.
      return SyncPromise.resolve(new Blob
        (Crypto.privateDecrypt
          ({ key: this.privateKey_, padding: padding }, cipherText),
         false));
    } catch (err) {
      return SyncPromise.reject(new TpmPrivateKey.Error(err));
    }
  }
};

/**
 * Sign the data with this private key, returning a signature Blob.
 * @param {Buffer} data The input byte buffer.
 * @param {number} digestAlgorithm The digest algorithm as an int from the
 * DigestAlgorithm enum.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the signature Blob (or
 * an isNull Blob if this private key is not initialized), or a promise rejected
 * with TpmPrivateKey.Error for unrecognized digestAlgorithm or an error in
 * signing.
 */
TpmPrivateKey.prototype.signPromise = function(data, digestAlgorithm, useSync)
{
  if (this.keyType_ == null)
    return SyncPromise.resolve(new Blob());

  if (digestAlgorithm != DigestAlgorithm.SHA256)
    return SyncPromise.reject(new TpmPrivateKey.Error(new Error
      ("TpmPrivateKey.sign: Unsupported digest algorithm")));

  if (UseSubtleCrypto() && !useSync) {
    var algorithm;
    if (this.keyType_ === KeyType.RSA)
      algorithm = { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-256" }};
    else
      return SyncPromise.reject(new TpmPrivateKey.Error(new Error
        ("signPromise: Unrecognized key type " + this.keyType_)));

    return this.getSubtleKeyPromise_()
    .then(function(subtleKey) {
      return crypto.subtle.sign(algorithm, subtleKey, data);
    })
    .then(function(signature) {
      var result = new Blob(new Uint8Array(signature), true);
      return Promise.resolve(result);
    });
  }
  else {
    var signer;
    if (this.keyType_ === KeyType.RSA)
      signer = Crypto.createSign("RSA-SHA256");
    else if (this.keyType === KeyType.EC)
      // Just create a "sha256". The Crypto library will infer ECDSA from the key.
      signer = Crypto.createSign("sha256");
    else
      return SyncPromise.reject(new TpmPrivateKey.Error(new Error
        ("signPromise: Unrecognized key type " + this.keyType_)));

    signer.update(data);
    var signature = new Buffer
      (DataUtils.toNumbersIfString(signer.sign(this.privateKey_)));
    var result = new Blob(signature, false);

    return SyncPromise.resolve(result);
  }
};

/**
 * Get the encoded unencrypted private key in PKCS #1.
 * @return {Blob} The private key encoding Blob.
 * @throws {TpmPrivateKey.Error} If no private key is loaded, or error encoding.
 */
TpmPrivateKey.prototype.toPkcs1 = function()
{
  if (this.keyType_ == null)
    throw new TpmPrivateKey.Error(new Error
      ("toPkcs1: The private key is not loaded"));

  // this.privateKey_ is already the base64-encoded PKCS #1 key.
  return new Blob(DataUtils.privateKeyPemToDer(this.privateKey_), false);
};

/**
 * Get the encoded unencrypted private key in PKCS #8.
 * @return {Blob} The private key encoding Blob.
 * @throws {TpmPrivateKey.Error} If no private key is loaded, or error encoding.
 */
TpmPrivateKey.prototype.toPkcs8 = function()
{
  if (this.keyType_ == null)
    throw new TpmPrivateKey.Error(new Error
      ("toPkcs8: The private key is not loaded"));

  var oid;
  if (this.keyType_ === KeyType.RSA)
    oid = new OID(TpmPrivateKey.RSA_ENCRYPTION_OID);
  else if (this.keyType === KeyType.EC)
    oid = new OID(TpmPrivateKey.EC_ENCRYPTION_OID);
  else
    // We don't expect this to happen.
    throw new TpmPrivateKey.Error(new Error
      ("toPkcs8: Unrecognized key type " + this.keyType_));

  return TpmPrivateKey.encodePkcs8PrivateKey
    (this.toPkcs1().buf(), oid, new DerNode.DerNull());
};

/**
 * Generate a key pair according to keyParams and return a new TpmPrivateKey
 * with the private key. You can get the public key with derivePublicKey.
 * @param {KeyParams} keyParams The parameters of the key.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the new TpmPrivateKey,
 * or a promise rejected with Error if the key type is not supported, or a
 * promise rejected with TpmPrivateKey.Error for an invalid key size, or an
 * error generating.
 */
TpmPrivateKey.generatePrivateKeyPromise = function(keyParams, useSync)
{
  // TODO: Check for RSAKey in the browser.

  if (UseSubtleCrypto() && !useSync) {
    if (keyParams.getKeyType() === KeyType.RSA) {
      var privateKey = null;

      return crypto.subtle.generateKey
        ({ name: "RSASSA-PKCS1-v1_5", modulusLength: keyParams.getKeySize(),
           publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
           hash: {name: "SHA-256"} },
         true, ["sign"])
      .then(function(key) {
        privateKey = key.privateKey;
        // Export the private key to DER.
        return crypto.subtle.exportKey("pkcs8", key.privateKey);
      })
      .then(function(pkcs8Der) {
        var result = new TpmPrivateKey();
        result.loadPkcs8(new Blob(new Uint8Array(pkcs8Der), false), KeyType.RSA);
        // Cache the crypto.subtle private key.
        result.subtleKey_ = privateKey;

        return SyncPromise.resolve(result);
      });
    }
    else
      return Promise.reject(new Error
        ("Cannot generate a key pair of type " + keyParams.getKeyType()));
  }
  else {
    // Assume we are in Node.js.
    var privateKeyPem;

    if (keyParams.getKeyType() === KeyType.RSA) {
      if (!rsaKeygen)
        return SyncPromise.reject(new TpmPrivateKey.Error(new Error
          ("Need to install rsa-keygen: sudo npm install rsa-keygen")));

      var keyPair = rsaKeygen.generate(keyParams.getKeySize());
      privateKeyPem = keyPair.private_key.toString();
    }
    else
      return SyncPromise.reject(new Error
        ("Cannot generate a key pair of type " + keyParams.getKeyType()));

    var result = new TpmPrivateKey();
    result.privateKey_ = privateKeyPem;
    result.keyType_ = keyParams.getKeyType();

    return SyncPromise.resolve(result);
  }
};

/**
 * Encode the private key to a PKCS #8 private key. We do this explicitly here
 * to avoid linking to extra OpenSSL libraries.
 * @param {Buffer} privateKeyDer The input private key DER.
 * @param {OID} oid The OID of the privateKey.
 * @param {DerNode} parameters The DerNode of the parameters for the OID.
 * @return {Blob} The PKCS #8 private key DER.
 */
TpmPrivateKey.encodePkcs8PrivateKey = function(privateKeyDer, oid, parameters)
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
TpmPrivateKey.encodePkcs1PrivateKeyFromRSAKey = function(rsaKey)
{
  // Imitate KJUR getEncryptedPKCS5PEMFromRSAKey.
  var result = new DerNode.DerSequence();

  result.addChild(new DerNode.DerInteger(0));
  result.addChild(new DerNode.DerInteger(TpmPrivateKey.bigIntegerToBuffer(rsaKey.n)));
  result.addChild(new DerNode.DerInteger(rsaKey.e));
  result.addChild(new DerNode.DerInteger(TpmPrivateKey.bigIntegerToBuffer(rsaKey.d)));
  result.addChild(new DerNode.DerInteger(TpmPrivateKey.bigIntegerToBuffer(rsaKey.p)));
  result.addChild(new DerNode.DerInteger(TpmPrivateKey.bigIntegerToBuffer(rsaKey.q)));
  result.addChild(new DerNode.DerInteger(TpmPrivateKey.bigIntegerToBuffer(rsaKey.dmp1)));
  result.addChild(new DerNode.DerInteger(TpmPrivateKey.bigIntegerToBuffer(rsaKey.dmq1)));
  result.addChild(new DerNode.DerInteger(TpmPrivateKey.bigIntegerToBuffer(rsaKey.coeff)));

  return result.encode();
};

/**
 * Encode the public key values in the RSAKey private key as a
 * SubjectPublicKeyInfo.
 * @param {RSAKey} rsaKey The RSAKey private key with the public key values.
 * @return {Blob} The SubjectPublicKeyInfo DER.
 */
TpmPrivateKey.encodePublicKeyFromRSAKey = function(rsaKey)
{
  var rsaPublicKey = new DerNode.DerSequence();

  rsaPublicKey.addChild(new DerNode.DerInteger
    (TpmPrivateKey.bigIntegerToBuffer(rsaKey.n)));
  rsaPublicKey.addChild(new DerNode.DerInteger(rsaKey.e));

  var algorithmIdentifier = new DerNode.DerSequence();
  algorithmIdentifier.addChild
    (new DerNode.DerOid(new OID(TpmPrivateKey.RSA_ENCRYPTION_OID)));
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
TpmPrivateKey.bigIntegerToBuffer = function(bigInteger)
{
  // Imitate KJUR.asn1.ASN1Util.bigIntToMinTwosComplementsHex.
  var hex = bigInteger.toString(16);
  if (hex.substr(0, 1) == "-")
    throw new Error
      ("TpmPrivateKey.bigIntegerToBuffer: Negative integers are not currently supported");

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

/**
 * A private method to get the cached crypto.subtle key (for signing), importing
 * it from this.privateKey_ if needed. This means we only have to do this once per
 * session, giving us a small but not insignificant performance boost.
 * @return {Promise} A promise which returns the cached crypto.subtle key.
 */
TpmPrivateKey.prototype.getSubtleKeyPromise_ = function()
{
  if (!this.subtleKey_) {
    // This is the first time in the session that we're using crypto subtle
    // with this key so we have to convert to pkcs8 and import it.
    if (this.keyType_ === KeyType.RSA) {
      var algorithm = { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-256" }};
      var privateDER = DataUtils.privateKeyPemToDer(this.privateKey_);
      var pkcs8 = TpmPrivateKey.encodePkcs8PrivateKey
        (privateDER, new OID(TpmPrivateKey.RSA_ENCRYPTION_OID),
         new DerNode.DerNull()).buf();
      var thisKey = this;

      return crypto.subtle.importKey
        ("pkcs8", pkcs8, algorithm, true, ["sign"])
      .then(function(subtleKey) {
        // Cache the crypto.subtle key object.
        thisKey.subtleKey_ = subtleKey;
        return Promise.resolve(thisKey.subtleKey_);
      });
    }
    else
      return SyncPromise.reject(new TpmPrivateKey.Error(new Error
        ("Unrecognized key type " + this.keyType_)));
  }
  else
    // The crypto.subtle key has been cached on a previous call or from keygen.
    return Promise.resolve(this.subtleKey_);
};

/**
 * A private method to get the cached crypto.subtle key for decrypting,
 * importing it from this.privateKey_ if needed. This means we only have to do
 * this once per session, giving us a small but not insignificant performance
 * boost. This is separate from getSubtleKeyPromise_ because the import
 * parameters for decrypt are different.
 * @return {Promise} A promise which returns the cached crypto.subtle key for
 * decrypt.
 */
TpmPrivateKey.prototype.getDecryptSubtleKeyPromise_ = function()
{
  if (!this.decryptSubtleKey_) {
    // This is the first time in the session that we're using crypto subtle
    // with this key so we have to convert to pkcs8 and import it.
    if (this.keyType_ === KeyType.RSA) {
      var algorithm = { name: "RSA-OAEP", hash: {name: "SHA-1"} };
      var privateDER = DataUtils.privateKeyPemToDer(this.privateKey_);
      var pkcs8 = TpmPrivateKey.encodePkcs8PrivateKey
        (privateDER, new OID(TpmPrivateKey.RSA_ENCRYPTION_OID),
         new DerNode.DerNull()).buf();
      var thisKey = this;

      return crypto.subtle.importKey
        ("pkcs8", pkcs8, algorithm, false, ["decrypt"])
      .then(function(subtleKey) {
        // Cache the crypto.subtle key object.
        thisKey.decryptSubtleKey_ = subtleKey;
        return Promise.resolve(thisKey.decryptSubtleKey_);
      });
    }
    else
      return SyncPromise.reject(new TpmPrivateKey.Error(new Error
        ("Unrecognized key type " + this.keyType_)));
  }
  else
    // The crypto.subtle key has been cached on a previous call.
    return Promise.resolve(this.decryptSubtleKey_);
};

TpmPrivateKey.RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.1";
TpmPrivateKey.EC_ENCRYPTION_OID = "1.2.840.10045.2.1";
