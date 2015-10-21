/**
 * Copyright (C) 2015 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt unit tests
 * https://github.com/named-data/ndn-group-encrypt/blob/master/tests/unit-tests/rsa.t.cpp
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
var RsaAlgorithm = require('../../..').RsaAlgorithm;

var PRIVATE_KEY =
  "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMLY2w1PmsuZNvZ4" +
  "rJs1pESLrxF1Xlk9Zg4Sc0r2HIEn/eme8f7cOxXq8OtxIjowEfjceHGvfc7YG1Nw" +
  "LDh+ka4Jh6QtYqPEL9GHfrBeufynd0g2PAPVXySBvOJr/Isk+4/Fsj5ihrIPgrQ5" +
  "wTBBuLYjDgwPppC/+vddsr5wu5bbAgMBAAECgYBYmRLB8riIa5q6aBTUXofbQ0jP" +
  "v3avTWPicjFKnK5JbE3gtQ2Evc+AH9x8smzF2KXTayy5RPsH2uxR/GefKK5EkWbB" +
  "mLwWDJ5/QPlLK1STxPs8B/89mp8sZkZ1AxnSHhV/a3dRcK1rVamVcqPMdFyM5PfX" +
  "/apL3MlL6bsq2FipAQJBAOp7EJuEs/qAjh8hgyV2acLdsokUEwXH4gCK6+KQW8XS" +
  "xFWAG4IbbLfq1HwEpHC2hJSzifCQGoPAxYBRgSK+h6sCQQDUuqF04o06+Qpe4A/W" +
  "pWCBGE33+CD4lBtaeoIagsAs/lgcFmXiJZ4+4PhyIORmwFgql9ZDFHSpl8rAYsfk" +
  "dz2RAkEAtUKpFe/BybYzJ3Galg0xuMf0ye7QvblExjKeIqiBqS1DRO0hVrSomIxZ" +
  "8f0MuWz+lI0t5t8fABa3FnjrINa0vQJBAJeZKNaTXPJZ5/oU0zS0RkG5gFbmjRiY" +
  "86VXCMC7zRhDaacajyDKjithR6yNpDdVe39fFWJYgYsakXLo8mruTwECQGqywoy9" +
  "epf1flKx4YCCrw+qRKmbkcXWcpFV32EG2K2D1GsxkuXv/b3qO67Uxx1Arxp9o8dl" +
  "k34WfzApRjNjho0=";

var PUBLIC_KEY =
  "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDC2NsNT5rLmTb2eKybNaREi68R" +
  "dV5ZPWYOEnNK9hyBJ/3pnvH+3DsV6vDrcSI6MBH43Hhxr33O2BtTcCw4fpGuCYek" +
  "LWKjxC/Rh36wXrn8p3dINjwD1V8kgbzia/yLJPuPxbI+YoayD4K0OcEwQbi2Iw4M" +
  "D6aQv/r3XbK+cLuW2wIDAQAB";

// plaintext: RSA-Encrypt-Test
var PLAINTEXT = new Buffer([
  0x52, 0x53, 0x41, 0x2d, 0x45, 0x6e, 0x63, 0x72,
  0x79, 0x70, 0x74, 0x2d, 0x54, 0x65, 0x73, 0x74
]);

var CIPHERTEXT = new Buffer([
  0x33, 0xfb, 0x32, 0xd4, 0x2d, 0x45, 0x75, 0x3f, 0x34, 0xde, 0x3b,
  0xaa, 0x80, 0x5f, 0x74, 0x6f, 0xf0, 0x3f, 0x01, 0x31, 0xdd, 0x2b,
  0x85, 0x02, 0x1b, 0xed, 0x2d, 0x16, 0x1b, 0x96, 0xe5, 0x77, 0xde,
  0xcd, 0x44, 0xe5, 0x3c, 0x32, 0xb6, 0x9a, 0xa9, 0x5d, 0xaa, 0x4b,
  0x94, 0xe2, 0xac, 0x4a, 0x4e, 0xf5, 0x35, 0x21, 0xd0, 0x03, 0x4a,
  0xa7, 0x53, 0xae, 0x13, 0x08, 0x63, 0x38, 0x2c, 0x92, 0xe3, 0x44,
  0x64, 0xbf, 0x33, 0x84, 0x8e, 0x51, 0x9d, 0xb9, 0x85, 0x83, 0xf6,
  0x8e, 0x09, 0xc1, 0x72, 0xb9, 0x90, 0x5d, 0x48, 0x63, 0xec, 0xd0,
  0xcc, 0xfa, 0xab, 0x44, 0x2b, 0xaa, 0xa6, 0xb6, 0xca, 0xec, 0x2b,
  0x5f, 0xbe, 0x77, 0xa5, 0x52, 0xeb, 0x0a, 0xaa, 0xf2, 0x2a, 0x19,
  0x62, 0x80, 0x14, 0x87, 0x42, 0x35, 0xd0, 0xb6, 0xa3, 0x47, 0x4e,
  0xb6, 0x1a, 0x88, 0xa3, 0x16, 0xb2, 0x19
]);

describe('TestRsaAlgorithm', function() {
  it('EncryptionDecryption', function() {
    var encryptParams = new EncryptParams(EncryptAlgorithmType.RsaOaep, 0);

    var privateKeyBlob = new Blob(new Buffer(PRIVATE_KEY, 'base64'), false);
    var publicKeyBlob = new Blob(new Buffer(PUBLIC_KEY, 'base64'), false);

    var decryptKey = new DecryptKey(privateKeyBlob);
    var encryptKey = RsaAlgorithm.deriveEncryptKey(decryptKey.getKeyBits());

    var encodedPublic = publicKeyBlob;
    var derivedPublicKey = encryptKey.getKeyBits();

    assert.ok(encodedPublic.equals(derivedPublicKey));

    var plainBlob = new Blob(PLAINTEXT, false);
    var encryptBlob = RsaAlgorithm.encrypt
      (encryptKey.getKeyBits(), plainBlob, encryptParams);
    var receivedBlob = RsaAlgorithm.decrypt
      (decryptKey.getKeyBits(), encryptBlob, encryptParams);

    assert.ok(plainBlob.equals(receivedBlob));

    var cipherBlob = new Blob(CIPHERTEXT, false);
    var decryptedBlob = RsaAlgorithm.decrypt
      (decryptKey.getKeyBits(), cipherBlob, encryptParams);

    assert.ok(plainBlob.equals(decryptedBlob));
  });
});
