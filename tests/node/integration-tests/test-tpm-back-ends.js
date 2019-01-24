/**
 * Copyright (C) 2017-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/tpm/back-end.t.cpp
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
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU Lesser General Public License is in the file COPYING.
 */

var assert = require("assert");
var fs = require('fs');
var path = require('path');
var Blob = require('../../..').Blob;
var SignedBlob = require('../../..').SignedBlob;
var DigestAlgorithm = require('../../..').DigestAlgorithm;
var Name = require('../../..').Name;
var RsaKeyParams = require('../../..').RsaKeyParams;
var RsaAlgorithm = require('../../..').RsaAlgorithm;
var EncryptParams = require('../../..').EncryptParams;
var EncryptAlgorithmType = require('../../..').EncryptAlgorithmType;
var PibKey = require('../../..').PibKey;
var Tpm = require('../../..').Tpm;
var VerificationHelpers = require('../../..').VerificationHelpers;
var TpmBackEndMemory = require('../../..').TpmBackEndMemory;
var TpmBackEndFile = require('../../..').TpmBackEndFile;

describe ("TestTpmBackEnds", function() {
  beforeEach(function(done) {
    this.backEndMemory = new TpmBackEndMemory();

    var locationPath = "policy_config/ndnsec-key-file";
    if (!fs.existsSync(locationPath))
      fs.mkdirSync(locationPath);
    // Delete files from a previous test.
    var allFiles = fs.readdirSync(locationPath);
    for (var i = 0; i < allFiles.length; ++i) {
      try {
        fs.unlinkSync(path.join(locationPath, allFiles[i]));
      } catch (e) {}
    }
    this.backEndFile = new TpmBackEndFile(locationPath);

    this.backEndList = [null, null];
    this.backEndList[0] = this.backEndMemory;
    this.backEndList[1] = this.backEndFile;

    done();
  });

  it("KeyManagement", function(done) {
    var thisTest = this;

    var test = function(iteration) {
      var tpm = thisTest.backEndList[iteration];

      var identityName = new Name("/Test/KeyName");
      var keyId = new Name.Component("1");
      var keyName = PibKey.constructKeyName(identityName, keyId);

      // The key should not exist.
      return tpm.hasKeyPromise(keyName)
      .then(function(hasKey) {
        assert.equal(false, hasKey);

        // Create a key, which should exist.
        return tpm.createKeyPromise(identityName, new RsaKeyParams(keyId));
      })
      .then(function(key) {
        assert.ok(key !== null);
        return tpm.hasKeyPromise(keyName);
      })
      .then(function(hasKey) {
        assert.ok(hasKey);
        return tpm.getKeyHandlePromise(keyName);
      })
      .then(function(keyHandle) {
        assert.ok(keyHandle != null);

        // Create a key with the same name, which should throw an error.
        return tpm.createKeyPromise(identityName, new RsaKeyParams(keyId))
        .then(function() {
          assert.fail('', '', "Did not throw the expected exception");
        }, function(err) {
          if (err instanceof Tpm.Error)
            return Promise.resolve();
          else
            assert.fail('', '', "Did not throw the expected exception");
        });
      })
      .then(function() {
        // Delete the key, then it should not exist.
        return tpm.deleteKeyPromise(keyName);
      })
      .then(function() {
        return tpm.hasKeyPromise(keyName);
      })
      .then(function(hasKey) {
        assert.equal(false, hasKey);
        return tpm.getKeyHandlePromise(keyName);
      })
      .then(function(keyHandle) {
        assert.ok(keyHandle == null);

        ++iteration;
        if (iteration >= thisTest.backEndList.length)
          // Done.
          return Promise.resolve();
        else
          // Recurse to the next iteration.
          return test(iteration);
      });
    };

    test(0)
    // When done is called, Mocha displays errors from assert.ok.
    .then(done, done);
  });

  it("RsaSigning", function(done) {
    var thisTest = this;

    var test = function(iteration) {
      var tpm = thisTest.backEndList[iteration];

      // Create an RSA key.
      var identityName = new Name("/Test/KeyName");
      var key, keyName;

      var content = new Blob([0x01, 0x02, 0x03, 0x04]);

      return tpm.createKeyPromise(identityName, new RsaKeyParams())
      .then(function(localKey) {
        key = localKey;
        keyName = key.getKeyName();

        return key.signPromise(DigestAlgorithm.SHA256, content.buf())
      })
      .then(function(signature) {
        var publicKey = key.derivePublicKey();

        return VerificationHelpers.verifySignaturePromise
          (content, signature, publicKey);
      })
      .then(function(result) {
        assert.equal(true, result);

        return tpm.deleteKeyPromise(keyName);
      })
      .then(function() {
        return tpm.hasKeyPromise(keyName);
      })
      .then(function(hasKey) {
        assert.equal(false, hasKey);

        ++iteration;
        if (iteration >= thisTest.backEndList.length)
          // Done.
          return Promise.resolve();
        else
          // Recurse to the next iteration.
          return test(iteration);
      });
    };

    test(0)
    // When done is called, Mocha displays errors from assert.ok.
    .then(done, done);
  });

  it("RsaDecryption", function(done) {
    var thisTest = this;

    var test = function(iteration) {
      var tpm = thisTest.backEndList[iteration];

      // Create an RSA key.
      var identityName = new Name("/Test/KeyName");
      var key, keyName;

      var content = new Blob([0x01, 0x02, 0x03, 0x04]);

      return tpm.createKeyPromise(identityName, new RsaKeyParams())
      .then(function(localKey) {
        key = localKey;
        keyName = key.getKeyName();

        var publicKey = key.derivePublicKey();

        // TODO: Move encrypt to PublicKey?
        var cipherText = RsaAlgorithm.encrypt
          (publicKey, content, new EncryptParams(EncryptAlgorithmType.RsaOaep));

        return key.decryptPromise(cipherText.buf());
      })
      .then(function(plainText) {
        assert.ok(plainText.equals(content));

        return tpm.deleteKeyPromise(keyName);
      })
      .then(function() {
        return tpm.hasKeyPromise(keyName);
      })
      .then(function(hasKey) {
        assert.equal(false, hasKey);

        ++iteration;
        if (iteration >= thisTest.backEndList.length)
          // Done.
          return Promise.resolve();
        else
          // Recurse to the next iteration.
          return test(iteration);
      });
    };

    test(0)
    // When done is called, Mocha displays errors from assert.ok.
    .then(done, done);
  });

  // TODO: EcdsaSigning

  it("RandomKeyId", function(done) {
    var tpm = this.backEndMemory;

    var identityName = new Name("/Test/KeyName");

    // Use the object key to store the key Name URI string, as a set.
    var keyNameUris = {};

    var test = function(iteration) {
      return tpm.createKeyPromise(identityName, new RsaKeyParams())
      .then(function(key) {
        var keyName = key.getKeyName();

        var saveSize = Object.keys(keyNameUris).length;
        keyNameUris[keyName.toUri()] = true;
        assert.ok(Object.keys(keyNameUris).length > saveSize)

        ++iteration;
        if (iteration >= 50)
          // Done.
          return Promise.resolve();
        else
          // Recurse to the next iteration.
          return test(iteration);
      });
    };

    test(0)
    // When done is called, Mocha displays errors from assert.ok.
    .then(done, done);
  });
});
