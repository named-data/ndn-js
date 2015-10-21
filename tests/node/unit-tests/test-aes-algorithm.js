/**
 * Copyright (C) 2015 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt unit tests
 * https://github.com/named-data/ndn-group-encrypt/blob/master/tests/unit-tests/aes.t.cpp
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version, with the additional exemption that
 * compiling, linking, and/or using OpenSSL is allowed.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var assert = require("assert");
var Blob = require('../../..').Blob;
var EncryptAlgorithmType = require('../../..').EncryptAlgorithmType;
var EncryptParams = require('../../..').EncryptParams;
var DecryptKey = require('../../..').DecryptKey;
var EncryptKey = require('../../..').EncryptKey;
var EncryptionMode = require('../../..').EncryptionMode;
var AesAlgorithm = require('../../..').AesAlgorithm;

var KEY = new Buffer([
  0xdd, 0x60, 0x77, 0xec, 0xa9, 0x6b, 0x23, 0x1b,
  0x40, 0x6b, 0x5a, 0xf8, 0x7d, 0x3d, 0x55, 0x32
]);

var PLAINTEXT = new Buffer([
  0x41, 0x45, 0x53, 0x2d, 0x45, 0x6e, 0x63, 0x72,
  0x79, 0x70, 0x74, 0x2d, 0x54, 0x65, 0x73, 0x74
]);

var CIPHERTEXT_ECB = new Buffer([
  0xcb, 0xe5, 0x6a, 0x80, 0x41, 0x24, 0x58, 0x23,
  0x84, 0x14, 0x15, 0x61, 0x80, 0xb9, 0x5e, 0xbd,
  0xce, 0x32, 0xb4, 0xbe, 0xbc, 0x91, 0x31, 0xd6,
  0x19, 0x00, 0x80, 0x8b, 0xfa, 0x00, 0x05, 0x9c
]);

var INITIAL_VECTOR = new Buffer([
  0x6f, 0x53, 0x7a, 0x65, 0x58, 0x6c, 0x65, 0x75,
  0x44, 0x4c, 0x77, 0x35, 0x58, 0x63, 0x78, 0x6e
]);

var CIPHERTEXT_CBC_IV = new Buffer([
  0xb7, 0x19, 0x5a, 0xbb, 0x23, 0xbf, 0x92, 0xb0,
  0x95, 0xae, 0x74, 0xe9, 0xad, 0x72, 0x7c, 0x28,
  0x6e, 0xc6, 0x73, 0xb5, 0x0b, 0x1a, 0x9e, 0xb9,
  0x4d, 0xc5, 0xbd, 0x8b, 0x47, 0x1f, 0x43, 0x00
]);

describe('TestAesAlgorithm', function() {
  it('EncryptionDecryption', function() {
    var encryptParams = new EncryptParams(EncryptAlgorithmType.AesEcb, 16);

    var decryptKey = new DecryptKey(new Blob(KEY, false));
    var encryptKey = AesAlgorithm.deriveEncryptKey(decryptKey.getKeyBits());

    var plainBlob = new Blob(PLAINTEXT, false);

    var cipherBlob = AesAlgorithm.encrypt(encryptKey.getKeyBits(), plainBlob, encryptParams);
    assert.ok(cipherBlob.equals(new Blob(CIPHERTEXT_ECB, false)));

    var receivedBlob = AesAlgorithm.decrypt(decryptKey.getKeyBits(), cipherBlob, encryptParams);
    assert.ok(receivedBlob.equals(plainBlob));

    encryptParams.setAlgorithmType(EncryptAlgorithmType.AesCbc);

    cipherBlob = AesAlgorithm.encrypt(encryptKey.getKeyBits(), plainBlob, encryptParams);
    receivedBlob = AesAlgorithm.decrypt(decryptKey.getKeyBits(), cipherBlob, encryptParams);
    assert.ok(receivedBlob.equals(plainBlob));

    var initialVector = new Blob(INITIAL_VECTOR, false);
    encryptParams.setInitialVector(initialVector);

    cipherBlob = AesAlgorithm.encrypt(encryptKey.getKeyBits(), plainBlob, encryptParams);
    assert.ok(cipherBlob.equals(new Blob(CIPHERTEXT_CBC_IV, false)));

    receivedBlob = AesAlgorithm.decrypt(decryptKey.getKeyBits(), cipherBlob, encryptParams);
    assert.ok(receivedBlob.equals(plainBlob));
  });
});
