/**
 * Copyright (C) 2015 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt src/algo/aes https://github.com/named-data/ndn-group-encrypt
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

// (This is ported from ndn::gep::algo::Aes, and named AesAlgorithm because
// "Aes" is very short and not all the Common Client Libraries have namespaces.)

var Crypto = require('../../crypto.js');
var Blob = require('../../util/blob.js').Blob;
var DecryptKey = require('../decrypt-key.js').DecryptKey;
var EncryptKey = require('../encrypt-key.js').EncryptKey;
var EncryptionMode = require('./encrypt-params.js').EncryptionMode;

/**
 * The AesAlgorithm class provides static methods to manipulate keys, encrypt
 * and decrypt using the AES symmetric key cipher.
 * @note This class is an experimental feature. The API may change.
 */
var AesAlgorithm = function AesAlgorithm()
{
};

exports.AesAlgorithm = AesAlgorithm;

/**
 * Generate a new random decrypt key for AES based on the given params.
 * @param {AesKeyParams} params The key params with the key size (in bits).
 * @return {DecryptKey} The new decrypt key.
 */
AesAlgorithm.generateKey = function(params)
{
  // Convert the key bit size to bytes.
  var key = Crypto.randomBytes(params.getKeySize() / 8);

  var decryptKey = new DecryptKey(new Blob(key, false));
  return decryptKey;
};

/**
 * Derive a new encrypt key from the given decrypt key value.
 * @param {Blob} keyBits The key value of the decrypt key.
 * @return {EncryptKey} The new encrypt key.
 */
AesAlgorithm.deriveEncryptKey = function(keyBits)
{
  return new EncryptKey(keyBits);
};

/**
 * Decrypt the encryptedData using the keyBits according the encrypt params.
 * @param keyBits {Blob} The key value.
 * @param encryptedData {Blob} The data to decrypt.
 * @param params {EncryptParams} This decrypts according to
 * params.getEncryptionMode() and other params as needed such as
 * params.getInitialVector().
 * @return {Blob} The decrypted data.
 */
AesAlgorithm.decrypt = function(keyBits, encryptedData, params)
{
  if (params.getEncryptionMode() == EncryptionMode.ECB_AES) {
    // ECB ignores the initial vector.
    var cipher = Crypto.createDecipheriv("aes-128-ecb", keyBits.buf(), "");
    var result = Buffer.concat
      ([cipher.update(encryptedData.buf()), cipher.final()]);
    return new Blob(result, false);
  }
  else if (params.getEncryptionMode() == EncryptionMode.CBC_AES) {
    var cipher = Crypto.createDecipheriv
      ("aes-128-cbc", keyBits.buf(), params.getInitialVector().buf());
    var result = Buffer.concat
      ([cipher.update(encryptedData.buf()), cipher.final()]);
    return new Blob(result, false);
  }
  else
    throw new Error("unsupported encryption mode");
};

/**
 * Encrypt the plainData using the keyBits according the encrypt params.
 * @param keyBits {Blob} The key value.
 * @param plainData {Blob} The data to encrypt.
 * @param params {EncryptParams} This encrypts according to
 * params.getEncryptionMode() and other params as needed such as
 * params.getInitialVector().
 * @return {Blob} The encrypted data.
 */
AesAlgorithm.encrypt = function(keyBits, plainData, params)
{
  if (params.getEncryptionMode() == EncryptionMode.ECB_AES) {
    // ECB ignores the initial vector.
    var cipher = Crypto.createCipheriv("aes-128-ecb", keyBits.buf(), "");
    var result = Buffer.concat
      ([cipher.update(plainData.buf()), cipher.final()]);
    return new Blob(result, false);
  }
  else if (params.getEncryptionMode() == EncryptionMode.CBC_AES) {
    if (params.getInitialVector().size() != AesAlgorithm.BLOCK_SIZE)
      throw new Error("incorrect initial vector size");

    var cipher = Crypto.createCipheriv
      ("aes-128-cbc", keyBits.buf(), params.getInitialVector().buf());
    var result = Buffer.concat
      ([cipher.update(plainData.buf()), cipher.final()]);
    return new Blob(result, false);
  }
  else
    throw new Error("unsupported encryption mode");
};

AesAlgorithm.BLOCK_SIZE = 16;
