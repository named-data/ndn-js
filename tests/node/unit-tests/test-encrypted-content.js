/**
 * Copyright (C) 2015 Regents of the University of California.
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
var Blob = require('../../..').Blob;
var Name = require('../../..').Name;
var KeyLocator = require('../../..').KeyLocator;
var KeyLocatorType = require('../../..').KeyLocatorType;
var DecodingException = require('../../..').DecodingException;

var ENCRYPTED = new Buffer([
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
  0x84, 0x07, // EncryptedPayload
    0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74
]);

var ENCRYPTED_NO_IV = new Buffer([
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
    0x00,
  0x84, 0x07, // EncryptedPayload
    0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74
]);

var MESSAGE = new Buffer([
  0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74
]);

var IV = new Buffer([
  0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x62, 0x69, 0x74, 0x73
]);

describe('TestEncryptedContent', function() {
  it('Constructor', function() {
    var content = new EncryptedContent();
    assert.ok(content.getAlgorithmType() == null);
    assert.ok(content.getPayload().isNull());
    assert.ok(content.getInitialVector().isNull());
    assert.ok(content.getKeyLocator().getType() == null);

    var payload = new Blob(MESSAGE, false);
    var initialVector = new Blob(IV, false);

    var keyLocator = new KeyLocator();
    keyLocator.setType(KeyLocatorType.KEYNAME);
    keyLocator.getKeyName().set("/test/key/locator");
    // TODO: Use AlgorithmSha256WithRsa.
    content.setAlgorithmType(0).setKeyLocator(keyLocator).setPayload(payload)
      .setInitialVector(initialVector);

    // Test the copy constructor.
    var sha256RsaContent = new EncryptedContent(content);
    var contentPayload = sha256RsaContent.getPayload();
    var contentInitialVector = sha256RsaContent.getInitialVector();

    assert.ok(sha256RsaContent.getAlgorithmType() == 0);
    assert.ok(contentPayload.equals(payload));
    assert.ok(contentInitialVector.equals(initialVector));
    assert.ok(sha256RsaContent.getKeyLocator().getType() != null);
    assert.ok(sha256RsaContent.getKeyLocator().getKeyName().equals
              (new Name("/test/key/locator")));

    var encryptedBlob = new Blob(ENCRYPTED, false);
    var encoded = sha256RsaContent.wireEncode();

    assert.ok(encryptedBlob.equals(encoded));

    sha256RsaContent = new EncryptedContent();
    sha256RsaContent.wireDecode(encryptedBlob);
    contentPayload = sha256RsaContent.getPayload();
    contentInitialVector = sha256RsaContent.getInitialVector();

    // TODO: Use AlgorithmSha256WithRsa.
    assert.ok(sha256RsaContent.getAlgorithmType() == 0);
    assert.ok(contentPayload.equals(payload));
    assert.ok(contentInitialVector.equals(initialVector));
    assert.ok(sha256RsaContent.getKeyLocator().getType() != null);
    assert.ok(sha256RsaContent.getKeyLocator().getKeyName().equals
              (new Name("/test/key/locator")));

    // Test no IV.
    sha256RsaContent = new EncryptedContent();
    sha256RsaContent.setAlgorithmType(0).setKeyLocator(keyLocator).setPayload(payload);
    contentPayload = sha256RsaContent.getPayload();

    assert.ok(sha256RsaContent.getAlgorithmType() == 0);
    assert.ok(contentPayload.equals(payload));
    assert.ok(sha256RsaContent.getInitialVector().isNull());
    assert.ok(sha256RsaContent.getKeyLocator().getType() != null);
    assert.ok(sha256RsaContent.getKeyLocator().getKeyName().equals
              (new Name("/test/key/locator")));

    encryptedBlob = new Blob(ENCRYPTED_NO_IV, false);
    var encodedNoIv = sha256RsaContent.wireEncode();

    assert.ok(encryptedBlob.equals(encodedNoIv));

    sha256RsaContent = new EncryptedContent();
    sha256RsaContent.wireDecode(encryptedBlob);
    contentPayload = sha256RsaContent.getPayload();

    assert.ok(sha256RsaContent.getAlgorithmType() == 0);
    assert.ok(sha256RsaContent.getPayload().equals(payload));
    assert.ok(sha256RsaContent.getInitialVector().isNull());
    assert.ok(sha256RsaContent.getKeyLocator().getType() != null);
    assert.ok(sha256RsaContent.getKeyLocator().getKeyName().equals
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
    assert.ok(content.getAlgorithmType() == null);
    assert.ok(content.getPayload().isNull());
    assert.ok(content.getInitialVector().isNull());
    assert.ok(content.getKeyLocator().getType() == null);

    // TODO: Use AlgorithmSha256WithRsa.
    content.setAlgorithmType(0);
    assert.ok(content.getAlgorithmType() == 0);
    assert.ok(content.getPayload().isNull());
    assert.ok(content.getInitialVector().isNull());
    assert.ok(content.getKeyLocator().getType() == null);

    var keyLocator = new KeyLocator();
    keyLocator.setType(KeyLocatorType.KEYNAME);
    keyLocator.getKeyName().set("/test/key/locator");
    content.setKeyLocator(keyLocator);
    assert.ok(content.getKeyLocator().getType() != KeyLocatorType.NONE);
    assert.ok(content.getKeyLocator().getKeyName().equals
              (new Name("/test/key/locator")));
    assert.ok(content.getPayload().isNull());
    assert.ok(content.getInitialVector().isNull());

    var payload = new Blob(MESSAGE, false);
    content.setPayload(payload);

    var contentPayload = content.getPayload();
    assert.ok(contentPayload.equals(payload));

    var initialVector = new Blob(IV, false);
    content.setInitialVector(initialVector);

    var contentInitialVector = content.getInitialVector();
    assert.ok(contentInitialVector.equals(initialVector));

    var encoded = content.wireEncode();
    var contentBlob = new Blob(ENCRYPTED, false);

    assert.ok(contentBlob.equals(encoded));
  });
});
