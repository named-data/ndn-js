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
var Crypto = require('../../crypto.js'); /** @ignore */
var Blob = require('../../util/blob.js').Blob; /** @ignore */
var SecurityException = require('../security-exception.js').SecurityException; /** @ignore */
var PublicKey = require('../certificate/public-key.js').PublicKey; /** @ignore */
var KeyClass = require('../security-types.js').KeyClass; /** @ignore */
var KeyType = require('../security-types').KeyType; /** @ignore */
var DigestAlgorithm = require('../security-types.js').DigestAlgorithm; /** @ignore */
var DataUtils = require('../../encoding/data-utils.js').DataUtils; /** @ignore */
var PrivateKeyStorage = require('./private-key-storage.js').PrivateKeyStorage; /** @ignore */
var DerNode = require('../../encoding/der/der-node.js').DerNode; /** @ignore */
var OID = require('../../encoding/oid.js').OID; /** @ignore */
var SyncPromise = require('../../util/sync-promise.js').SyncPromise; /** @ignore */
var UseSubtleCrypto = require('../../use-subtle-crypto-node.js').UseSubtleCrypto; /** @ignore */
var rsaKeygen = null;
try {
  // This should be installed with: sudo npm install rsa-keygen
  rsaKeygen = require('rsa-keygen');
}
catch (e) {}

/**
 * MemoryPrivateKeyStorage class extends PrivateKeyStorage to implement private
 * key storage in memory.
 * @constructor
 */
var MemoryPrivateKeyStorage = function MemoryPrivateKeyStorage()
{
  // Call the base constructor.
  PrivateKeyStorage.call(this);

  // The key is the keyName.toUri(). The value is security.certificate.PublicKey.
  this.publicKeyStore = {};
  // The key is the keyName.toUri(). The value is the object
  //  {keyType,     // number from KeyType
  //   privateKey   // The PEM-encoded private key.
  //  }.
  this.privateKeyStore = {};
};

MemoryPrivateKeyStorage.prototype = new PrivateKeyStorage();
MemoryPrivateKeyStorage.prototype.name = "MemoryPrivateKeyStorage";

exports.MemoryPrivateKeyStorage = MemoryPrivateKeyStorage;

/**
 * Set the public key for the keyName.
 * @param {Name} keyName The key name.
 * @param {number} keyType The KeyType, such as KeyType.RSA.
 * @param {Buffer} publicKeyDer The public key DER byte array.
 */
MemoryPrivateKeyStorage.prototype.setPublicKeyForKeyName = function
  (keyName, keyType, publicKeyDer)
{
  this.publicKeyStore[keyName.toUri()] = new PublicKey
    (new Blob(publicKeyDer, true));
};

/**
 * Set the private key for the keyName.
 * @param {Name} keyName The key name.
 * @param {number} keyType The KeyType, such as KeyType.RSA.
 * @param {Buffer} privateKeyDer The private key DER byte array.
 */
MemoryPrivateKeyStorage.prototype.setPrivateKeyForKeyName = function
  (keyName, keyType, privateKeyDer)
{
  // Encode the DER as PEM.
  var keyBase64 = privateKeyDer.toString('base64');
  var keyPem;
  if (keyType === KeyType.RSA) {
    keyPem = "-----BEGIN RSA PRIVATE KEY-----\n";
    for (var i = 0; i < keyBase64.length; i += 64)
      keyPem += (keyBase64.substr(i, 64) + "\n");
    keyPem += "-----END RSA PRIVATE KEY-----";
  }
  else if (keyType === KeyType.EC) {
    keyPem = "-----BEGIN EC PRIVATE KEY-----\n";
    for (var i = 0; i < keyBase64.length; i += 64)
      keyPem += (keyBase64.substr(i, 64) + "\n");
    keyPem += "-----END EC PRIVATE KEY-----";
  }
  else
    throw new SecurityException(new Error
      ("MemoryPrivateKeyStorage: KeyType is not supported"));

  this.privateKeyStore[keyName.toUri()] =
    { keyType: keyType, privateKey: keyPem };
};

/**
 * Set the public and private key for the keyName.
 * @param {Name} keyName The key name.
 * @param {number} keyType The KeyType, such as KeyType.RSA.
 * @param {Buffer} publicKeyDer The public key DER byte array.
 * @param {Buffer} privateKeyDer The private key DER byte array.
 */
MemoryPrivateKeyStorage.prototype.setKeyPairForKeyName = function
  (keyName, keyType, publicKeyDer, privateKeyDer)
{
  this.setPublicKeyForKeyName(keyName, keyType, publicKeyDer);
  this.setPrivateKeyForKeyName(keyName, keyType, privateKeyDer);
};

/**
 * Generate a pair of asymmetric keys.
 * @param {Name} keyName The name of the key pair.
 * @param {KeyParams} params The parameters of the key.
 * @param {boolean} useSync (optional) If true then use blocking crypto and
 * return a SyncPromise which is already fulfilled. If omitted or false, if
 * possible use crypto.subtle and return an async Promise, otherwise use
 * blocking crypto and return a SyncPromise.
 * @return {Promise|SyncPromise} A promise that fulfills when the pair is
 * generated.
 */
MemoryPrivateKeyStorage.prototype.generateKeyPairPromise = function
  (keyName, params, useSync)
{
  if (this.doesKeyExist(keyName, KeyClass.PUBLIC))
    return SyncPromise.reject(new SecurityException(new Error
      ("Public key already exists")));
  if (this.doesKeyExist(keyName, KeyClass.PRIVATE))
    return SyncPromise.reject(new SecurityException(new Error
      ("Private key already exists")));

  var thisStore = this;

  if (UseSubtleCrypto() && !useSync) {
    if (params.getKeyType() === KeyType.RSA) {
      var privateKey = null;
      var publicKeyDer = null;

      return crypto.subtle.generateKey
        ({ name: "RSASSA-PKCS1-v1_5", modulusLength: params.getKeySize(),
           publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
           hash: {name: "SHA-256"} },
         true, ["sign", "verify"])
      .then(function(key) {
        privateKey = key.privateKey;

        // Export the public key to DER.
        return crypto.subtle.exportKey("spki", key.publicKey);
      })
      .then(function(exportedPublicKey) {
        publicKeyDer = new Blob(new Uint8Array(exportedPublicKey), false).buf();

        // Export the private key to DER.
        return crypto.subtle.exportKey("pkcs8", privateKey);
      })
      .then(function(pkcs8Der) {
        // Crypto.subtle exports the private key as PKCS #8. Decode it to find
        // the inner private key DER.
        var parsedNode = DerNode.parse
          (new Blob(new Uint8Array(pkcs8Der), false).buf());
        // Get the value of the 3rd child which is the octet string.
        var privateKeyDer = parsedNode.getChildren()[2].toVal();

        // Save the key pair.
        thisStore.setKeyPairForKeyName
          (keyName, params.getKeyType(), publicKeyDer, privateKeyDer.buf());

        // sign will use subtleKey directly.
        thisStore.privateKeyStore[keyName.toUri()].subtleKey = privateKey;

        return Promise.resolve();
      });
    }
    else
      return SyncPromise.reject(new SecurityException(new Error
        ("Only RSA key generation currently supported")));
  }
  else {
    return SyncPromise.resolve()
    .then(function() {
      if (typeof RSAKey !== 'undefined') {
        // Assume we are in the browser.
        if (params.getKeyType() === KeyType.RSA) {
          var rsaKey = new RSAKey();
          rsaKey.generate(params.getKeySize(), '010001');
          thisStore.setKeyPairForKeyName
            (keyName, params.getKeyType(),
             PrivateKeyStorage.encodePublicKeyFromRSAKey(rsaKey).buf(),
             PrivateKeyStorage.encodePkcs1PrivateKeyFromRSAKey(rsaKey).buf());
        }
        else
          return SyncPromise.reject(new SecurityException(new Error
            ("Only RSA key generation currently supported")));
      }
      else {
        // Assume we are in Node.js.
        var publicKeyDer;
        var privateKeyPem;

        if (params.getKeyType() === KeyType.RSA) {
          if (!rsaKeygen)
            return SyncPromise.reject(new SecurityException(new Error
              ("Need to install rsa-keygen: sudo npm install rsa-keygen")));

          var keyPair = rsaKeygen.generate(params.getKeySize());

          // Get the public key DER from the PEM string.
          var publicKeyBase64 = keyPair.public_key.toString().replace
            ("-----BEGIN PUBLIC KEY-----", "").replace
            ("-----END PUBLIC KEY-----", "");
          publicKeyDer = new Buffer(publicKeyBase64, 'base64');

          privateKeyPem = keyPair.private_key.toString();
        }
        else
          return SyncPromise.reject(new SecurityException(new Error
            ("Only RSA key generation currently supported")));

        thisStore.setPublicKeyForKeyName(keyName, params.getKeyType(), publicKeyDer);
        thisStore.privateKeyStore[keyName.toUri()] =
          { keyType: params.getKeyType(), privateKey: privateKeyPem };
      }

      return SyncPromise.resolve();
    });
  }
};

/**
 * Delete a pair of asymmetric keys. If the key doesn't exist, do nothing.
 * @param {Name} keyName The name of the key pair.
 * @return {SyncPromise} A promise that fulfills when the key pair is deleted.
 */
MemoryPrivateKeyStorage.prototype.deleteKeyPairPromise = function(keyName)
{
  var keyUri = keyName.toUri();

  delete this.publicKeyStore[keyUri];
  delete this.privateKeyStore[keyUri];

  return SyncPromise.resolve();
};

/**
 * Get the public key
 * @param {Name} keyName The name of public key.
 * @return {SyncPromise} A promise that returns the PublicKey.
 */
MemoryPrivateKeyStorage.prototype.getPublicKeyPromise = function(keyName)
{
  var keyUri = keyName.toUri();
  var publicKey = this.publicKeyStore[keyUri];
  if (publicKey === undefined)
    return SyncPromise.reject(new SecurityException(new Error
      ("MemoryPrivateKeyStorage: Cannot find public key " + keyName.toUri())));

  return SyncPromise.resolve(publicKey);
};

/**
 * Fetch the private key for keyName and sign the data to produce a signature Blob.
 * @param {Buffer} data Pointer to the input byte array.
 * @param {Name} keyName The name of the signing key.
 * @param {number} digestAlgorithm (optional) The digest algorithm from
 * DigestAlgorithm, such as DigestAlgorithm.SHA256. If omitted, use
 * DigestAlgorithm.SHA256.
 * @param {boolean} useSync (optional) If true then use blocking crypto and
 * return a SyncPromise which is already fulfilled. If omitted or false, if
 * possible use crypto.subtle and return an async Promise, otherwise use
 * blocking crypto and return a SyncPromise.
 * @return {Promise|SyncPromise} A promise that returns the signature Blob.
 */
MemoryPrivateKeyStorage.prototype.signPromise = function
  (data, keyName, digestAlgorithm, useSync)
{
  useSync = (typeof digestAlgorithm === "boolean") ? digestAlgorithm : useSync;
  digestAlgorithm = (typeof digestAlgorithm === "boolean" || !digestAlgorithm) ? DigestAlgorithm.SHA256 : digestAlgorithm;

  if (digestAlgorithm != DigestAlgorithm.SHA256)
    return SyncPromise.reject(new SecurityException(new Error
      ("MemoryPrivateKeyStorage.sign: Unsupported digest algorithm")));

  // Find the private key.
  var keyUri = keyName.toUri();
  var privateKey = this.privateKeyStore[keyUri];
  if (privateKey === undefined)
    return SyncPromise.reject(new SecurityException(new Error
      ("MemoryPrivateKeyStorage: Cannot find private key " + keyUri)));

  if (UseSubtleCrypto() && !useSync){
    var algo = {name:"RSASSA-PKCS1-v1_5",hash:{name:"SHA-256"}};

    if (!privateKey.subtleKey){
      //this is the first time in the session that we're using crypto subtle with this key
      //so we have to convert to pkcs8 and import it.
      //assigning it to privateKey.subtleKey means we only have to do this once per session,
      //giving us a small, but not insignificant, performance boost.
      var privateDER = DataUtils.privateKeyPemToDer(privateKey.privateKey);
      var pkcs8 = PrivateKeyStorage.encodePkcs8PrivateKey
        (privateDER, new OID(PrivateKeyStorage.RSA_ENCRYPTION_OID),
         new DerNode.DerNull()).buf();

      var promise = crypto.subtle.importKey("pkcs8", pkcs8.buffer, algo, true, ["sign"]).then(function(subtleKey){
        //cache the crypto.subtle key object
        privateKey.subtleKey = subtleKey;
        return crypto.subtle.sign(algo, subtleKey, data);
      });
    } else {
      // The crypto.subtle key has been cached on a previous sign or from keygen.
      var promise = crypto.subtle.sign(algo, privateKey.subtleKey, data);
    }

    return promise.then(function(signature){
      var result = new Blob(new Uint8Array(signature), true);
      return Promise.resolve(result);
    });
  } else {
    var signer;
    if (privateKey.keyType === KeyType.RSA)
      signer = Crypto.createSign("RSA-SHA256");
    else if (privateKey.keyType === KeyType.EC)
      // Just create a "sha256". The Crypto library will infer ECDSA from the key.
      signer = Crypto.createSign("sha256");
    else
      // We don't expect this to happen since setPrivateKeyForKeyName already checked.
      return SyncPromise.reject(new SecurityException(new Error
        ("MemoryPrivateKeyStorage.sign: Unrecognized private key type")));

    signer.update(data);
    var signature = new Buffer
      (DataUtils.toNumbersIfString(signer.sign(privateKey.privateKey)));
    var result = new Blob(signature, false);

    return SyncPromise.resolve(result);
  }
};

/**
 * Check if a particular key exists.
 * @param {Name} keyName The name of the key.
 * @param {number} keyClass The class of the key, e.g. KeyClass.PUBLIC,
 * KeyClass.PRIVATE, or KeyClass.SYMMETRIC.
 * @return {SyncPromise} A promise which returns true if the key exists.
 */
MemoryPrivateKeyStorage.prototype.doesKeyExistPromise = function
  (keyName, keyClass)
{
  var keyUri = keyName.toUri();
  var result = false;
  if (keyClass == KeyClass.PUBLIC)
    result = this.publicKeyStore[keyUri] !== undefined;
  else if (keyClass == KeyClass.PRIVATE)
    result = this.privateKeyStore[keyUri] !== undefined;

  return SyncPromise.resolve(result);
};
