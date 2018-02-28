/**
 * Copyright (C) 2015-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt src/encryptor https://github.com/named-data/ndn-group-encrypt
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
var Name = require('../../name.js').Name; /** @ignore */
var KeyLocator = require('../../key-locator.js').KeyLocator; /** @ignore */
var KeyLocatorType = require('../../key-locator.js').KeyLocatorType; /** @ignore */
var TlvWireFormat = require('../../encoding/tlv-wire-format.js').TlvWireFormat; /** @ignore */
var Blob = require('../../util/blob.js').Blob; /** @ignore */
var AesAlgorithm = require('./aes-algorithm.js').AesAlgorithm; /** @ignore */
var RsaAlgorithm = require('./rsa-algorithm.js').RsaAlgorithm; /** @ignore */
var EncryptParams = require('./encrypt-params.js').EncryptParams; /** @ignore */
var EncryptAlgorithmType = require('./encrypt-params.js').EncryptAlgorithmType; /** @ignore */
var EncryptedContent = require('../encrypted-content.js').EncryptedContent; /** @ignore */
var SyncPromise = require('../../util/sync-promise.js').SyncPromise;

/**
 * Encryptor has static constants and utility methods for encryption, such as
 * encryptData.
 * @constructor
 */
var Encryptor = function Encryptor(value)
{
};

exports.Encryptor = Encryptor;

Encryptor.NAME_COMPONENT_FOR = new Name.Component("FOR");
Encryptor.NAME_COMPONENT_READ = new Name.Component("READ");
Encryptor.NAME_COMPONENT_SAMPLE = new Name.Component("SAMPLE");
Encryptor.NAME_COMPONENT_ACCESS = new Name.Component("ACCESS");
Encryptor.NAME_COMPONENT_E_KEY = new Name.Component("E-KEY");
Encryptor.NAME_COMPONENT_D_KEY = new Name.Component("D-KEY");
Encryptor.NAME_COMPONENT_C_KEY = new Name.Component("C-KEY");

/**
 * Prepare an encrypted data packet by encrypting the payload using the key
 * according to the params. In addition, this prepares the encoded
 * EncryptedContent with the encryption result using keyName and params. The
 * encoding is set as the content of the data packet. If params defines an
 * asymmetric encryption algorithm and the payload is larger than the maximum
 * plaintext size, this encrypts the payload with a symmetric key that is
 * asymmetrically encrypted and provided as a nonce in the content of the data
 * packet. The packet's /<dataName>/ is updated to be <dataName>/FOR/<keyName>.
 * @param {Data} data The data packet which is updated.
 * @param {Blob} payload The payload to encrypt.
 * @param {Name} keyName The key name for the EncryptedContent.
 * @param {Blob} key The encryption key value.
 * @param {EncryptParams} params The parameters for encryption.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when the data packet
 * is updated.
 */
Encryptor.encryptDataPromise = function
  (data, payload, keyName, key, params, useSync)
{
  data.getName().append(Encryptor.NAME_COMPONENT_FOR).append(keyName);

  var algorithmType = params.getAlgorithmType();

  if (algorithmType == EncryptAlgorithmType.AesCbc ||
      algorithmType == EncryptAlgorithmType.AesEcb) {
    return Encryptor.encryptSymmetricPromise_
      (payload, key, keyName, params, useSync)
    .then(function(content) {
      data.setContent(content.wireEncode(TlvWireFormat.get()));
      return SyncPromise.resolve();
    });
  }
  else if (algorithmType == EncryptAlgorithmType.RsaPkcs ||
           algorithmType == EncryptAlgorithmType.RsaOaep) {
    // Node.js and Subtle don't have a direct way to get the maximum plain text size, so
    // try to encrypt the payload first and catch the error if it is too big.
    return Encryptor.encryptAsymmetricPromise_
      (payload, key, keyName, params, useSync)
    .then(function(content) {
      data.setContent(content.wireEncode(TlvWireFormat.get()));
      return SyncPromise.resolve();
    }, function(err) {
      // The payload is larger than the maximum plaintext size.
      // 128-bit nonce.
      var nonceKeyBuffer = Crypto.randomBytes(16);
      var nonceKey = new Blob(nonceKeyBuffer, false);

      var nonceKeyName = new Name(keyName);
      nonceKeyName.append("nonce");

      var symmetricParams = new EncryptParams
        (EncryptAlgorithmType.AesCbc, AesAlgorithm.BLOCK_SIZE);

      // Do encryptAsymmetric first so that, if there really is an error, we
      // catch it right away.
      var payloadContent;
      return Encryptor.encryptAsymmetricPromise_
        (nonceKey, key, keyName, params, useSync)
      .then(function(localPayloadContent) {
        payloadContent = localPayloadContent;
        return Encryptor.encryptSymmetricPromise_
          (payload, nonceKey, nonceKeyName, symmetricParams, useSync);
      })
      .then(function(nonceContent) {
        var nonceContentEncoding = nonceContent.wireEncode();
        var payloadContentEncoding = payloadContent.wireEncode();
        var content = new Buffer
          (nonceContentEncoding.size() + payloadContentEncoding.size());
        payloadContentEncoding.buf().copy(content, 0);
        nonceContentEncoding.buf().copy(content, payloadContentEncoding.size());

        data.setContent(new Blob(content, false));
        return SyncPromise.resolve();
      });
    });
  }
  else
    return SyncPromise.reject(new Error("Unsupported encryption method"));
};

/**
 * Prepare an encrypted data packet by encrypting the payload using the key
 * according to the params. In addition, this prepares the encoded
 * EncryptedContent with the encryption result using keyName and params. The
 * encoding is set as the content of the data packet. If params defines an
 * asymmetric encryption algorithm and the payload is larger than the maximum
 * plaintext size, this encrypts the payload with a symmetric key that is
 * asymmetrically encrypted and provided as a nonce in the content of the data
 * packet.
 * @param {Data} data The data packet which is updated.
 * @param {Blob} payload The payload to encrypt.
 * @param {Name} keyName The key name for the EncryptedContent.
 * @param {Blob} key The encryption key value.
 * @param {EncryptParams} params The parameters for encryption.
 * @throws Error If encryptPromise doesn't return a SyncPromise which is
 * already fulfilled.
 */
Encryptor.encryptData = function(data, payload, keyName, key, params)
{
  return SyncPromise.getValue(Encryptor.encryptDataPromise
    (data, payload, keyName, key, params, true));
};

/**
 * Encrypt the payload using the symmetric key according to params, and return
 * an EncryptedContent.
 * @param {Blob} payload The data to encrypt.
 * @param {Blob} key The key value.
 * @param {Name} keyName The key name for the EncryptedContent key locator.
 * @param {EncryptParams} params The parameters for encryption.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns a new EncryptedContent.
 */
Encryptor.encryptSymmetricPromise_ = function
  (payload, key, keyName, params, useSync)
{
  var algorithmType = params.getAlgorithmType();
  var initialVector = params.getInitialVector();
  var keyLocator = new KeyLocator();
  keyLocator.setType(KeyLocatorType.KEYNAME);
  keyLocator.setKeyName(keyName);

  if (algorithmType == EncryptAlgorithmType.AesCbc ||
      algorithmType == EncryptAlgorithmType.AesEcb) {
    if (algorithmType == EncryptAlgorithmType.AesCbc) {
      if (initialVector.size() != AesAlgorithm.BLOCK_SIZE)
        return SyncPromise.reject(new Error("incorrect initial vector size"));
    }

    return AesAlgorithm.encryptPromise(key, payload, params, useSync)
    .then(function(encryptedPayload) {
      var result = new EncryptedContent();
      result.setAlgorithmType(algorithmType);
      result.setKeyLocator(keyLocator);
      result.setPayload(encryptedPayload);
      result.setInitialVector(initialVector);
      return SyncPromise.resolve(result);
    });
  }
  else
    return SyncPromise.reject(new Error("Unsupported encryption method"));
};

/**
 * Encrypt the payload using the asymmetric key according to params, and
 * return an EncryptedContent.
 * @param {Blob} payload The data to encrypt. The size should be within range of
 * the key.
 * @param {Blob} key The key value.
 * @param {Name} keyName The key name for the EncryptedContent key locator.
 * @param {EncryptParams} params The parameters for encryption.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns a new EncryptedContent.
 */
Encryptor.encryptAsymmetricPromise_ = function
  (payload, key, keyName, params, useSync)
{
  var algorithmType = params.getAlgorithmType();
  var keyLocator = new KeyLocator();
  keyLocator.setType(KeyLocatorType.KEYNAME);
  keyLocator.setKeyName(keyName);

  if (algorithmType == EncryptAlgorithmType.RsaPkcs ||
      algorithmType == EncryptAlgorithmType.RsaOaep) {
    return RsaAlgorithm.encryptPromise(key, payload, params, useSync)
    .then(function(encryptedPayload) {
      var result = new EncryptedContent();
      result.setAlgorithmType(algorithmType);
      result.setKeyLocator(keyLocator);
      result.setPayload(encryptedPayload);
      return SyncPromise.resolve(result);
    });
  }
  else
    return SyncPromise.reject(new Error("Unsupported encryption method"));
};
