/**
 * Copyright (C) 2015-2016 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt unit tests
 * https://github.com/named-data/ndn-group-encrypt/blob/master/tests/unit-tests/encrypted-content.t.cpp
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
var EncryptedContent = require('../../..').EncryptedContent;
var EncryptAlgorithmType = require('../../..').EncryptAlgorithmType;
var Blob = require('../../..').Blob;
var Name = require('../../..').Name;
var KeyLocator = require('../../..').KeyLocator;
var KeyLocatorType = require('../../..').KeyLocatorType;
var DecodingException = require('../../..').DecodingException;

var encrypted = new Buffer([
0x82, 0x30, // EncryptedContent
  0x1c, 0x16, // KeyLocator
    0x07, 0x14, // Name
      0x08, 0x04,
        0x74, 0x65, 0x73, 0x74, // 'test'
      0x08, 0x03,
        0x6b, 0x65, 0x79, // 'key'
      0x08, 0x07,
        0x6c, 0x6f, 0x63, 0x61, 0x74, 0x6f, 0x72, // 'locator'
  0x83, 0x01, // EncryptedAlgorithm
    0x03,
  0x85, 0x0a, // InitialVector
    0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x62, 0x69, 0x74, 0x73,
  0x84, 0x07, // EncryptedPayload
    0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74
]);

var encryptedNoIv = new Buffer([
0x82, 0x24, // EncryptedContent
  0x1c, 0x16, // KeyLocator
    0x07, 0x14, // Name
      0x08, 0x04,
        0x74, 0x65, 0x73, 0x74, // 'test'
      0x08, 0x03,
        0x6b, 0x65, 0x79, // 'key'
      0x08, 0x07,
        0x6c, 0x6f, 0x63, 0x61, 0x74, 0x6f, 0x72, // 'locator'
  0x83, 0x01, // EncryptedAlgorithm
    0x03,
  0x84, 0x07, // EncryptedPayload
    0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74
]);

var message = new Buffer([
  0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74
]);

var iv = new Buffer([
  0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x62, 0x69, 0x74, 0x73
]);

describe('TestEncryptedContent', function() {
  it('Constructor', function() {
    // Check default settings.
    var content = new EncryptedContent();
    assert.equal(content.getAlgorithmType(), null);
    assert.ok(content.getPayload().isNull());
    assert.ok(content.getInitialVector().isNull());
    assert.equal(content.getKeyLocator().getType(), null);

    // Check an encrypted content with IV.
    var keyLocator = new KeyLocator();
    keyLocator.setType(KeyLocatorType.KEYNAME);
    keyLocator.getKeyName().set("/test/key/locator");
    var rsaOaepContent = new EncryptedContent();
    rsaOaepContent.setAlgorithmType(EncryptAlgorithmType.RsaOaep)
      .setKeyLocator(keyLocator).setPayload(new Blob(message, false))
      .setInitialVector(new Blob(iv, false));

    assert.equal(rsaOaepContent.getAlgorithmType(), EncryptAlgorithmType.RsaOaep);
    assert.ok(rsaOaepContent.getPayload().equals(new Blob(message, false)));
    assert.ok(rsaOaepContent.getInitialVector().equals(new Blob(iv, false)));
    assert.ok(rsaOaepContent.getKeyLocator().getType() != null);
    assert.ok(rsaOaepContent.getKeyLocator().getKeyName().equals
              (new Name("/test/key/locator")));

    // Encoding.
    var encryptedBlob = new Blob(encrypted, false);
    var encoded = rsaOaepContent.wireEncode();

    assert.ok(encryptedBlob.equals(encoded));

    // Decoding.
    var rsaOaepContent2 = new EncryptedContent();
    rsaOaepContent2.wireDecode(encryptedBlob);
    assert.equal(rsaOaepContent2.getAlgorithmType(), EncryptAlgorithmType.RsaOaep);
    assert.ok(rsaOaepContent2.getPayload().equals(new Blob(message, false)));
    assert.ok(rsaOaepContent2.getInitialVector().equals(new Blob(iv, false)));
    assert.ok(rsaOaepContent2.getKeyLocator().getType() != null);
    assert.ok(rsaOaepContent2.getKeyLocator().getKeyName().equals
              (new Name("/test/key/locator")));

    // Check the no IV case.
    var rsaOaepContentNoIv = new EncryptedContent();
    rsaOaepContentNoIv.setAlgorithmType(EncryptAlgorithmType.RsaOaep)
      .setKeyLocator(keyLocator).setPayload(new Blob(message, false));
    assert.equal(rsaOaepContentNoIv.getAlgorithmType(), EncryptAlgorithmType.RsaOaep);
    assert.ok(rsaOaepContentNoIv.getPayload().equals(new Blob(message, false)));
    assert.ok(rsaOaepContentNoIv.getInitialVector().isNull());
    assert.ok(rsaOaepContentNoIv.getKeyLocator().getType() != null);
    assert.ok(rsaOaepContentNoIv.getKeyLocator().getKeyName().equals
              (new Name("/test/key/locator")));

    // Encoding.
    var encryptedBlob2 = new Blob(encryptedNoIv, false);
    var encodedNoIV = rsaOaepContentNoIv.wireEncode();
    assert.ok(encryptedBlob2.equals(encodedNoIV));

    // Decoding.
    var rsaOaepContentNoIv2 = new EncryptedContent();
    rsaOaepContentNoIv2.wireDecode(encryptedBlob2);
    assert.equal(rsaOaepContentNoIv2.getAlgorithmType(), EncryptAlgorithmType.RsaOaep);
    assert.ok(rsaOaepContentNoIv2.getPayload().equals(new Blob(message, false)));
    assert.ok(rsaOaepContentNoIv2.getInitialVector().isNull());
    assert.ok(rsaOaepContentNoIv2.getKeyLocator().getType() != null);
    assert.ok(rsaOaepContentNoIv2.getKeyLocator().getKeyName().equals
              (new Name("/test/key/locator")));
  });

  it('DecodingError', function() {
    var encryptedContent = new EncryptedContent();

    var errorBlob1 = new Blob(new Buffer([
      0x1f, 0x30, // Wrong EncryptedContent (0x82, 0x24)
        0x1c, 0x16, // KeyLocator
          0x07, 0x14, // Name
            0x08, 0x04,
              0x74, 0x65, 0x73, 0x74,
            0x08, 0x03,
              0x6b, 0x65, 0x79,
            0x08, 0x07,
              0x6c, 0x6f, 0x63, 0x61, 0x74, 0x6f, 0x72,
        0x83, 0x01, // EncryptedAlgorithm
          0x00,
        0x85, 0x0a, // InitialVector
          0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x62, 0x69, 0x74, 0x73,
        0x84, 0x07, // EncryptedPayload
          0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74
    ]), false);
    assert.throws
      (function() { encryptedContent.wireDecode(errorBlob1); },
       DecodingException);

    var errorBlob2 = new Blob(new Buffer([
      0x82, 0x30, // EncryptedContent
        0x1d, 0x16, // Wrong KeyLocator (0x1c, 0x16)
          0x07, 0x14, // Name
            0x08, 0x04,
              0x74, 0x65, 0x73, 0x74,
            0x08, 0x03,
              0x6b, 0x65, 0x79,
            0x08, 0x07,
              0x6c, 0x6f, 0x63, 0x61, 0x74, 0x6f, 0x72,
        0x83, 0x01, // EncryptedAlgorithm
          0x00,
        0x85, 0x0a, // InitialVector
          0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x62, 0x69, 0x74, 0x73,
        0x84, 0x07, // EncryptedPayload
          0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74
    ]), false);
    assert.throws
      (function() { encryptedContent.wireDecode(errorBlob2); },
       DecodingException);

    var errorBlob3 = new Blob(new Buffer([
      0x82, 0x30, // EncryptedContent
        0x1c, 0x16, // KeyLocator
          0x07, 0x14, // Name
            0x08, 0x04,
              0x74, 0x65, 0x73, 0x74,
            0x08, 0x03,
              0x6b, 0x65, 0x79,
            0x08, 0x07,
              0x6c, 0x6f, 0x63, 0x61, 0x74, 0x6f, 0x72,
        0x1d, 0x01, // Wrong EncryptedAlgorithm (0x83, 0x01)
          0x00,
        0x85, 0x0a, // InitialVector
          0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x62, 0x69, 0x74, 0x73,
        0x84, 0x07, // EncryptedPayload
          0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74
    ]), false);
    assert.throws
      (function() { encryptedContent.wireDecode(errorBlob3); },
       DecodingException);

    var errorBlob4 = new Blob(new Buffer([
      0x82, 0x30, // EncryptedContent
        0x1c, 0x16, // KeyLocator
          0x07, 0x14, // Name
            0x08, 0x04,
              0x74, 0x65, 0x73, 0x74, // 'test'
            0x08, 0x03,
              0x6b, 0x65, 0x79, // 'key'
            0x08, 0x07,
              0x6c, 0x6f, 0x63, 0x61, 0x74, 0x6f, 0x72, // 'locator'
        0x83, 0x01, // EncryptedAlgorithm
          0x00,
        0x1f, 0x0a, // InitialVector (0x84, 0x0a)
          0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x62, 0x69, 0x74, 0x73,
        0x84, 0x07, // EncryptedPayload
          0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74
    ]), false);
    assert.throws
      (function() { encryptedContent.wireDecode(errorBlob4); },
       DecodingException);

    var errorBlob5 = new Blob(new Buffer([
      0x82, 0x30, // EncryptedContent
        0x1c, 0x16, // KeyLocator
          0x07, 0x14, // Name
            0x08, 0x04,
              0x74, 0x65, 0x73, 0x74, // 'test'
            0x08, 0x03,
              0x6b, 0x65, 0x79, // 'key'
            0x08, 0x07,
              0x6c, 0x6f, 0x63, 0x61, 0x74, 0x6f, 0x72, // 'locator'
        0x83, 0x01, // EncryptedAlgorithm
          0x00,
        0x85, 0x0a, // InitialVector
          0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x62, 0x69, 0x74, 0x73,
        0x21, 0x07, // EncryptedPayload (0x85, 0x07)
          0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74
    ]), false);
    assert.throws
      (function() { encryptedContent.wireDecode(errorBlob5); },
       DecodingException);

    var errorBlob6 = new Blob(new Buffer([
      0x82, 0x00 // Empty EncryptedContent
    ]), false);
    assert.throws
      (function() { encryptedContent.wireDecode(errorBlob6); },
       DecodingException);
  });

  it('SetterGetter', function() {
    var content = new EncryptedContent();
    assert.equal(content.getAlgorithmType(), null);
    assert.ok(content.getPayload().isNull());
    assert.ok(content.getInitialVector().isNull());
    assert.equal(content.getKeyLocator().getType(), null);

    content.setAlgorithmType(EncryptAlgorithmType.RsaOaep);
    assert.equal(content.getAlgorithmType(), EncryptAlgorithmType.RsaOaep);
    assert.ok(content.getPayload().isNull());
    assert.ok(content.getInitialVector().isNull());
    assert.equal(content.getKeyLocator().getType(), null);

    var keyLocator = new KeyLocator();
    keyLocator.setType(KeyLocatorType.KEYNAME);
    keyLocator.getKeyName().set("/test/key/locator");
    content.setKeyLocator(keyLocator);
    assert.ok(content.getKeyLocator().getType() != null);
    assert.ok(content.getKeyLocator().getKeyName().equals
              (new Name("/test/key/locator")));
    assert.ok(content.getPayload().isNull());
    assert.ok(content.getInitialVector().isNull());

    content.setPayload(new Blob(message, false));
    assert.ok(content.getPayload().equals(new Blob(message, false)));

    content.setInitialVector(new Blob(iv, false));
    assert.ok(content.getInitialVector().equals(new Blob(iv, false)));

    var encoded = content.wireEncode();
    var contentBlob = new Blob(encrypted, false);
    assert.ok(contentBlob.equals(encoded));
  });
});
