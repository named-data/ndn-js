/**
 * Copyright (C) 2015 Regents of the University of California.
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

var Crypto = require('../crypto.js');
var Name = require('../name.js').Name;
var KeyLocator = require('../key-locator.js').KeyLocator;
var KeyLocatorType = require('../key-locator.js').KeyLocatorType;
var TlvWireFormat = require('../encoding/tlv-wire-format.js').TlvWireFormat;
var Blob = require('../util/blob.js').Blob;
var AesAlgorithm = require('./algo/aes-algorithm.js').AesAlgorithm;
var RsaAlgorithm = require('./algo/rsa-algorithm.js').RsaAlgorithm;
var EncryptParams = require('./algo/encrypt-params.js').EncryptParams;
var EncryptAlgorithmType = require('./algo/encrypt-params.js').EncryptAlgorithmType;
var EncryptedContent = require('./encrypted-content.js').EncryptedContent;

/**
 * Encryptor has static utility methods for encryption, such as encryptData.
 * @constructor
 */
var Encryptor = function Encryptor(value)
{
};

exports.Encryptor = Encryptor;

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
 */
Encryptor.encryptData = function(data, payload, keyName, key, params)
{
  var algorithmType = params.getAlgorithmType();

  if (algorithmType == EncryptAlgorithmType.AesCbc ||
      algorithmType == EncryptAlgorithmType.AesEcb) {
    var content = Encryptor.encryptSymmetric_(payload, key, keyName, params);
    data.setContent(content.wireEncode(TlvWireFormat.get()));
  }
  else if (algorithmType == EncryptAlgorithmType.RsaPkcs ||
           algorithmType == EncryptAlgorithmType.RsaOaep) {
    // Node.js doesn't have a direct way to get the maximum plain text size, so
    // try to encrypt the payload first and catch the error if it is too big.
    try {
      var content = Encryptor.encryptAsymmetric_(payload, key, keyName, params);
      data.setContent(content.wireEncode(TlvWireFormat.get()));
      return;
    } catch (ex) {
      if (ex.message.indexOf("data too large for key size") < 0)
        // Not the expected error.
        throw ex;
      
      // The payload is larger than the maximum plaintext size. Continue.
    }

    // 128-bit nonce.
    var nonceKeyBuffer = Crypto.randomBytes(16);
    var nonceKey = new Blob(nonceKeyBuffer, false);

    var nonceKeyName = new Name(keyName);
    nonceKeyName.append("nonce");

    var symmetricParams = new EncryptParams
      (EncryptAlgorithmType.AesCbc, AesAlgorithm.BLOCK_SIZE);

    var nonceContent = Encryptor.encryptSymmetric_
      (payload, nonceKey, nonceKeyName, symmetricParams);

    var payloadContent = Encryptor.encryptAsymmetric_
      (nonceKey, key, keyName, params);

    var nonceContentEncoding = nonceContent.wireEncode();
    var payloadContentEncoding = payloadContent.wireEncode();
    var content = new Buffer
      (nonceContentEncoding.size() + payloadContentEncoding.size());
    payloadContentEncoding.buf().copy(content, 0);
    nonceContentEncoding.buf().copy(content, payloadContentEncoding.size());

    data.setContent(new Blob(content, false));
  }
  else
    throw new Error("Unsupported encryption method");
};

/**
 * Encrypt the payload using the symmetric key according to params, and return
 * an EncryptedContent.
 * @param {Blob} payload The data to encrypt.
 * @param {Blob} key The key value.
 * @param {Name} keyName The key name for the EncryptedContent key locator.
 * @param {EncryptParams} params The parameters for encryption.
 * @return {EncryptedContent} A new EncryptedContent.
 */
Encryptor.encryptSymmetric_ = function(payload, key, keyName, params)
{
  var algorithmType = params.getAlgorithmType();
  var initialVector = params.getInitialVector();
  var keyLocator = new KeyLocator();
  keyLocator.setType(KeyLocatorType.KEYNAME);
  keyLocator.setKeyName(keyName);

  if (algorithmType == EncryptAlgorithmType.AesCbc ||
      algorithmType == EncryptAlgorithmType.AesEcb) {
    var encryptedPayload = AesAlgorithm.encrypt(key, payload, params);

    var result = new EncryptedContent();
    result.setAlgorithmType(algorithmType);
    result.setKeyLocator(keyLocator);
    result.setPayload(encryptedPayload);
    result.setInitialVector(initialVector);
    return result;
  }
  else
    throw new Error("Unsupported encryption method");
};

/**
 * Encrypt the payload using the asymmetric key according to params, and
 * return an EncryptedContent.
 * @param payload The data to encrypt. The size should be within range of the
 * key.
 * @param key The key value.
 * @param keyName The key name for the EncryptedContent key locator.
 * @param params The parameters for encryption.
 * @return A new EncryptedContent.
 */
Encryptor.encryptAsymmetric_ = function(payload, key, keyName, params)
{
  var algorithmType = params.getAlgorithmType();
  var keyLocator = new KeyLocator();
  keyLocator.setType(KeyLocatorType.KEYNAME);
  keyLocator.setKeyName(keyName);

  if (algorithmType == EncryptAlgorithmType.RsaPkcs ||
      algorithmType == EncryptAlgorithmType.RsaOaep) {
    var encryptedPayload = RsaAlgorithm.encrypt(key, payload, params);

    var result = new EncryptedContent();
    result.setAlgorithmType(algorithmType);
    result.setKeyLocator(keyLocator);
    result.setPayload(encryptedPayload);
    return result;
  }
  else
    throw new Error("Unsupported encryption method");
};
