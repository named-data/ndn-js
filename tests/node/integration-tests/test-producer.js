/**
 * Copyright (C) 2015-2016 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt unit tests
 * https://github.com/named-data/ndn-group-encrypt/blob/master/tests/unit-tests/producer.t.cpp
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
var fs = require("fs");
var Name = require('../../..').Name;
var Data = require('../../..').Data;
var Blob = require('../../..').Blob;
var MemoryIdentityStorage = require('../../..').MemoryIdentityStorage;
var MemoryPrivateKeyStorage = require('../../..').MemoryPrivateKeyStorage;
var KeyChain = require('../../..').KeyChain;
var IdentityManager = require('../../..').IdentityManager;
var NoVerifyPolicyManager = require('../../..').NoVerifyPolicyManager;
var Sqlite3ProducerDb = require('../../..').Sqlite3ProducerDb;
var Producer = require('../../..').Producer;
var Encryptor = require('../../..').Encryptor;
var RsaKeyParams = require('../../..').RsaKeyParams;
var RsaAlgorithm = require('../../..').RsaAlgorithm;
var AesAlgorithm = require('../../..').AesAlgorithm;
var EncryptParams = require('../../..').EncryptParams;
var EncryptAlgorithmType = require('../../..').EncryptAlgorithmType;
var EncryptedContent = require('../../..').EncryptedContent;
var Common = require('../unit-tests/unit-tests-common.js').UnitTestsCommon;

var DATA_CONTENT = new Buffer([
  0xcb, 0xe5, 0x6a, 0x80, 0x41, 0x24, 0x58, 0x23,
  0x84, 0x14, 0x15, 0x61, 0x80, 0xb9, 0x5e, 0xbd,
  0xce, 0x32, 0xb4, 0xbe, 0xbc, 0x91, 0x31, 0xd6,
  0x19, 0x00, 0x80, 0x8b, 0xfa, 0x00, 0x05, 0x9c
]);

var databaseFilePath;

var keyChain;
var certificateName;

var decryptionKeys = {}; // key: name URI string, value: Blob
var encryptionKeys = {}; // key: name URI string, value: Data

createEncryptionKey = function(eKeyName, timeMarker)
{
  var params = new RsaKeyParams();
  eKeyName = new Name(eKeyName);
  eKeyName.append(timeMarker);

  var dKeyBlob = RsaAlgorithm.generateKey(params).getKeyBits();
  var eKeyBlob = RsaAlgorithm.deriveEncryptKey(dKeyBlob).getKeyBits();
  decryptionKeys[eKeyName.toUri()] = dKeyBlob;

  var keyData = new Data(eKeyName);
  keyData.setContent(eKeyBlob);
  keyChain.sign(keyData, certificateName);
  encryptionKeys[eKeyName.toUri()] = keyData;
}

describe ("TestProducer", function() {
  beforeEach(function(done) {
    databaseFilePath = "policy_config/test.db";
    try {
      fs.unlinkSync(databaseFilePath);
    }
    catch (e) {}

    // Set up the key chain.
    var identityStorage = new MemoryIdentityStorage();
    var privateKeyStorage = new MemoryPrivateKeyStorage();
    keyChain = new KeyChain
      (new IdentityManager(identityStorage, privateKeyStorage),
       new NoVerifyPolicyManager());
    var identityName = new Name("TestProducer");
    certificateName = keyChain.createIdentityAndCertificate(identityName);
    keyChain.getIdentityManager().setDefaultIdentity(identityName);

    done();
  });

  afterEach(function(done) {
    try {
      fs.unlinkSync(databaseFilePath);
    }
    catch (e) {}

    done();
  });

  it("ContentKeyRequest", function(done) {
    var prefix = new Name("/prefix");
    var suffix = new Name("/a/b/c");
    var expectedInterest = new Name(prefix);
    expectedInterest.append(Encryptor.NAME_COMPONENT_READ);
    expectedInterest.append(suffix);
    expectedInterest.append(Encryptor.NAME_COMPONENT_E_KEY);

    var cKeyName = new Name(prefix);
    cKeyName.append(Encryptor.NAME_COMPONENT_SAMPLE);
    cKeyName.append(suffix);
    cKeyName.append(Encryptor.NAME_COMPONENT_C_KEY);

    var timeMarker = new Name("20150101T100000/20150101T120000");
    var testTime1 = Common.fromIsoString("20150101T100001");
    var testTime2 = Common.fromIsoString("20150101T110001");
    var testTimeRounded1 = new Name.Component("20150101T100000");
    var testTimeRounded2 = new Name.Component("20150101T110000");
    var testTimeComponent2 = new Name.Component("20150101T110001");

    // Create content keys required for this test case:
    for (var i = 0; i < suffix.size(); ++i) {
      createEncryptionKey(expectedInterest, timeMarker);
      expectedInterest = expectedInterest.getPrefix(-2).append
        (Encryptor.NAME_COMPONENT_E_KEY);
    }

    var expressInterestCallCount = 0;

    // Prepare a TestFace to instantly answer calls to expressInterest.
    var TestFace = function TestFace() {};
    TestFace.prototype.expressInterest = function(interest, onData, onTimeout)
    {
      try {
        ++expressInterestCallCount;

        var interestName = new Name(interest.getName());
        interestName.append(timeMarker);
        assert.ok(encryptionKeys[interestName.toUri()] != undefined);
        onData(interest, encryptionKeys[interestName.toUri()]);

        return 0;
      } catch (ex) { done(ex); }
    };

    var face = new TestFace();

    // Verify that the content key is correctly encrypted for each domain, and
    // the produce method encrypts the provided data with the same content key.
    var testDb = new Sqlite3ProducerDb(databaseFilePath);
    var producer = new Producer(prefix, suffix, face, keyChain, testDb);
    var contentKey = null; // Blob

    // We don't know which callback will be called first, so count.
    var nCallbacksNeeded = 4;
    var nCallbacksCalled = 0;

    function checkEncryptionKeys
        (result, testTime, roundedTime, expectedExpressInterestCallCount) {
      try {
        assert.equal(expressInterestCallCount, expectedExpressInterestCallCount);
      } catch (ex) { done(ex); return; }

      testDb.hasContentKeyPromise(testTime)
      .then(function(exists) {
        assert.equal(true, exists);
        return testDb.getContentKeyPromise(testTime);
      })
      .then(function(localContentKey) {
        contentKey = localContentKey;

        var params = new EncryptParams(EncryptAlgorithmType.RsaOaep);
        for (var i = 0; i < result.length; ++i) {
          var key = result[i]; // Data
          var keyName = key.getName();
          assert.ok(cKeyName.equals(keyName.getSubName(0, 6)));
          assert.ok(keyName.get(6).equals(roundedTime));
          assert.ok(keyName.get(7).equals(Encryptor.NAME_COMPONENT_FOR));
          assert.equal(decryptionKeys[keyName.getSubName(8).toUri()] != undefined, true);

          var decryptionKey = decryptionKeys[keyName.getSubName(8).toUri()];
          assert.equal(decryptionKey.size() != 0, true);
          var encryptedKeyEncoding = key.getContent();

          var content = new EncryptedContent();
          content.wireDecode(encryptedKeyEncoding);
          var encryptedKey = content.getPayload();
          var retrievedKey = RsaAlgorithm.decrypt
            (decryptionKey, encryptedKey, params);

          assert.ok(contentKey.equals(retrievedKey));
        }

        assert.equal(result.length, 3);

        if (++nCallbacksCalled == nCallbacksNeeded)
          done();
      })
      .catch(function(ex) {
        done(ex);
      });
    }

    var contentKeyName1;

    // An initial test to confirm that keys are created for this time slot.
    producer.createContentKey(testTime1, function(keys) {
      try {
        checkEncryptionKeys(keys, testTime1, testTimeRounded1, 3);
        // Verify that we do not repeat the search for e-keys. The total
        //   expressInterestCallCount should be the same.
        producer.createContentKey(testTime2, function(keys) {
          checkEncryptionKeys(keys, testTime2, testTimeRounded2, 3);
          try {
            // Confirm that produce encrypts with the correct key and has the
            //   right name.
            var testData = new Data();
            producer.produce
              (testData, testTime2, new Blob(DATA_CONTENT, false), function() {
              try {
                var producedName = testData.getName();
                assert.ok(cKeyName.getPrefix(-1).equals(producedName.getSubName(0, 5)));
                assert.ok(testTimeComponent2.equals(producedName.get(5)));
                assert.ok(Encryptor.NAME_COMPONENT_FOR.equals(producedName.get(6)));
                assert.ok(cKeyName.equals(producedName.getSubName(7, 6)));
                assert.ok(testTimeRounded2.equals(producedName.get(13)));

                var dataBlob = testData.getContent();

                var dataContent = new EncryptedContent();
                dataContent.wireDecode(dataBlob);
                var encryptedData = dataContent.getPayload();
                var initialVector = dataContent.getInitialVector();

                var params = new EncryptParams(EncryptAlgorithmType.AesCbc, 16);
                params.setInitialVector(initialVector);
                var decryptTest = AesAlgorithm.decrypt(contentKey, encryptedData, params);
                assert.ok(decryptTest.equals(new Blob(DATA_CONTENT, false)));

                if (++nCallbacksCalled == nCallbacksNeeded)
                  done();
              } catch (ex) { done(ex); }
            }, function(errorCode, message) { done(new Error(message)); });
          } catch (ex) { done(ex); }
        }, function(contentKeyName2) {
          try {
            // Confirm content key names are correct.
            assert.ok(cKeyName.equals(contentKeyName1.getPrefix(-1)));
            assert.ok(testTimeRounded1.equals(contentKeyName1.get(6)));
            assert.ok(cKeyName.equals(contentKeyName2.getPrefix(-1)));
            assert.ok(testTimeRounded2.equals(contentKeyName2.get(6)));

            if (++nCallbacksCalled == nCallbacksNeeded)
              done();
          } catch (ex) { done(ex); }
        }, function(errorCode, message) { done(new Error(message)); });
      } catch (ex) { done(ex); }
    }, function(contentKeyName) {
      contentKeyName1 = contentKeyName;
    }, function(errorCode, message) { done(new Error(message)); });
  });

  it("ContentKeySearch", function(done) {
    var timeMarkerFirstHop = new Name("20150101T070000/20150101T080000");
    var timeMarkerSecondHop = new Name("20150101T080000/20150101T090000");
    var timeMarkerThirdHop = new Name("20150101T100000/20150101T110000");

    var prefix = new Name("/prefix");
    var suffix = new Name("/suffix");
    var expectedInterest = new Name(prefix);
    expectedInterest.append(Encryptor.NAME_COMPONENT_READ);
    expectedInterest.append(suffix);
    expectedInterest.append(Encryptor.NAME_COMPONENT_E_KEY);

    var cKeyName = new Name(prefix);
    cKeyName.append(Encryptor.NAME_COMPONENT_SAMPLE);
    cKeyName.append(suffix);
    cKeyName.append(Encryptor.NAME_COMPONENT_C_KEY);

    var testTime = Common.fromIsoString("20150101T100001");

    // Create content keys required for this test case:
    createEncryptionKey(expectedInterest, timeMarkerFirstHop);
    createEncryptionKey(expectedInterest, timeMarkerSecondHop);
    createEncryptionKey(expectedInterest, timeMarkerThirdHop);

    var requestCount = 0;

    // Prepare a TestFace to instantly answer calls to expressInterest.
    var TestFace = function TestFace() {};
    TestFace.prototype.expressInterest = function(interest, onData, onTimeout)
    {
      try {
        assert.ok(expectedInterest.equals(interest.getName()));

        var gotInterestName = false;
        var interestName = null;
        for (var i = 0; i < 3; ++i) {
          interestName = new Name(interest.getName());
          if (i == 0)
            interestName.append(timeMarkerFirstHop);
          else if (i == 1)
            interestName.append(timeMarkerSecondHop);
          else if (i == 2)
            interestName.append(timeMarkerThirdHop);

          // matchesName will check the Exclude.
          if (interest.matchesName(interestName)) {
            gotInterestName = true;
            ++requestCount;
            break;
          }
        }

        if (gotInterestName)
          onData(interest, encryptionKeys[interestName.toUri()]);

        return 0;
      } catch (ex) { done(ex); }
    };

    var face = new TestFace();

    // Verify that if a key is found, but not within the right time slot, the
    // search is refined until a valid time slot is found.
    var testDb = new Sqlite3ProducerDb(databaseFilePath);
    var producer = new Producer(prefix, suffix, face, keyChain, testDb);
    producer.createContentKey
      (testTime, function(result) {
      try {
        assert.equal(requestCount, 3);
        assert.equal(result.length, 1);

        var keyData = result[0];
        var keyName = keyData.getName();
        assert.ok(cKeyName.equals(keyName.getSubName(0, 4)));
        assert.ok(timeMarkerThirdHop.get(0).equals(keyName.get(4)));
        assert.ok(Encryptor.NAME_COMPONENT_FOR.equals(keyName.get(5)));
        assert.ok(expectedInterest.append(timeMarkerThirdHop).equals
                  (keyName.getSubName(6)));

        done();
      } catch (ex) { done(ex); }
    },
      function(contentKeyName) {},
      function(errorCode, message) { done(new Error(message)); });
  });

  it("ContentKeyTimeout", function(done) {
    var prefix = new Name("/prefix");
    var suffix = new Name("/suffix");
    var expectedInterest = new Name(prefix);
    expectedInterest.append(Encryptor.NAME_COMPONENT_READ);
    expectedInterest.append(suffix);
    expectedInterest.append(Encryptor.NAME_COMPONENT_E_KEY);

    var testTime = Common.fromIsoString("20150101T100001");

    var timeoutCount = 0;

    // Prepare a TestFace to instantly answer calls to expressInterest.
    var TestFace = function TestFace() {};
    TestFace.prototype.expressInterest = function(interest, onData, onTimeout)
    {
      try {
        assert.ok(expectedInterest.equals(interest.getName()));
        ++timeoutCount;
        onTimeout(interest);

        return 0;
      } catch (ex) { done(ex); }
    };

    var face = new TestFace();

    // Verify that if no response is received, the producer appropriately times
    // out. The result vector should not contain elements that have timed out.
    var testDb = new Sqlite3ProducerDb(databaseFilePath);
    var producer = new Producer(prefix, suffix, face, keyChain, testDb);
    producer.createContentKey
      (testTime, function(result) {
      try {
        assert.equal(timeoutCount, 4);
        assert.equal(result.length, 0);
        done();
      } catch (ex) { done(ex); }
    },
      function(contentKeyName) {},
      function(errorCode, message) { done(new Error(message)); });
  });
});
