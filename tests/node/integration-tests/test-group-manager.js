/**
 * Copyright (C) 2015-2016 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt unit tests
 * https://github.com/named-data/ndn-group-encrypt/blob/master/tests/unit-tests/group-manager.t.cpp
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
var RepetitiveInterval = require('../../..').RepetitiveInterval;
var Schedule = require('../../..').Schedule;
var GroupManager = require('../../..').GroupManager;
var Sqlite3GroupManagerDb = require('../../..').Sqlite3GroupManagerDb;
var EncryptedContent = require('../../..').EncryptedContent;
var EncryptParams = require('../../..').EncryptParams;
var EncryptAlgorithmType = require('../../..').EncryptAlgorithmType;
var RsaKeyParams = require('../../..').RsaKeyParams;
var RsaAlgorithm = require('../../..').RsaAlgorithm;
var AesAlgorithm = require('../../..').AesAlgorithm;
var PublicKey = require('../../..').PublicKey;
var EncryptKey = require('../../..').EncryptKey;
var DecryptKey = require('../../..').DecryptKey;
var Name = require('../../..').Name;
var Data = require('../../..').Data;
var Blob = require('../../..').Blob;
var TlvWireFormat = require('../../..').TlvWireFormat;
var MemoryIdentityStorage = require('../../..').MemoryIdentityStorage;
var MemoryPrivateKeyStorage = require('../../..').MemoryPrivateKeyStorage;
var KeyChain = require('../../..').KeyChain;
var IdentityManager = require('../../..').IdentityManager;
var NoVerifyPolicyManager = require('../../..').NoVerifyPolicyManager;
var IdentityCertificate = require('../../..').IdentityCertificate;
var Common = require('../unit-tests/unit-tests-common.js').UnitTestsCommon;

var SIG_INFO = new Buffer([
  0x16, 0x1b, // SignatureInfo
      0x1b, 0x01, // SignatureType
          0x01,
      0x1c, 0x16, // KeyLocator
          0x07, 0x14, // Name
              0x08, 0x04,
                  0x74, 0x65, 0x73, 0x74,
              0x08, 0x03,
                  0x6b, 0x65, 0x79,
              0x08, 0x07,
                  0x6c, 0x6f, 0x63, 0x61, 0x74, 0x6f, 0x72
]);

var SIG_VALUE = new Buffer([
  0x17, 0x80, // SignatureValue
      0x2f, 0xd6, 0xf1, 0x6e, 0x80, 0x6f, 0x10, 0xbe, 0xb1, 0x6f, 0x3e, 0x31, 0xec,
      0xe3, 0xb9, 0xea, 0x83, 0x30, 0x40, 0x03, 0xfc, 0xa0, 0x13, 0xd9, 0xb3, 0xc6,
      0x25, 0x16, 0x2d, 0xa6, 0x58, 0x41, 0x69, 0x62, 0x56, 0xd8, 0xb3, 0x6a, 0x38,
      0x76, 0x56, 0xea, 0x61, 0xb2, 0x32, 0x70, 0x1c, 0xb6, 0x4d, 0x10, 0x1d, 0xdc,
      0x92, 0x8e, 0x52, 0xa5, 0x8a, 0x1d, 0xd9, 0x96, 0x5e, 0xc0, 0x62, 0x0b, 0xcf,
      0x3a, 0x9d, 0x7f, 0xca, 0xbe, 0xa1, 0x41, 0x71, 0x85, 0x7a, 0x8b, 0x5d, 0xa9,
      0x64, 0xd6, 0x66, 0xb4, 0xe9, 0x8d, 0x0c, 0x28, 0x43, 0xee, 0xa6, 0x64, 0xe8,
      0x55, 0xf6, 0x1c, 0x19, 0x0b, 0xef, 0x99, 0x25, 0x1e, 0xdc, 0x78, 0xb3, 0xa7,
      0xaa, 0x0d, 0x14, 0x58, 0x30, 0xe5, 0x37, 0x6a, 0x6d, 0xdb, 0x56, 0xac, 0xa3,
      0xfc, 0x90, 0x7a, 0xb8, 0x66, 0x9c, 0x0e, 0xf6, 0xb7, 0x64, 0xd1
]);

var dKeyDatabaseFilePath;
var eKeyDatabaseFilePath;
var intervalDatabaseFilePath;
var groupKeyDatabaseFilePath;
var decryptKeyBlob;
var encryptKeyBlob;
var certificate = new IdentityCertificate();
var keyChain;

function setManagerPromise(manager)
{
  // Set up the first schedule.
  var schedule1 = new Schedule();
  var interval11 = new RepetitiveInterval
    (Common.fromIsoString("20150825T000000"),
     Common.fromIsoString("20150827T000000"), 5, 10, 2,
     RepetitiveInterval.RepeatUnit.DAY);
  var interval12 = new RepetitiveInterval
    (Common.fromIsoString("20150825T000000"),
     Common.fromIsoString("20150827T000000"), 6, 8, 1,
     RepetitiveInterval.RepeatUnit.DAY);
  var interval13 = new RepetitiveInterval
    (Common.fromIsoString("20150827T000000"),
     Common.fromIsoString("20150827T000000"), 7, 8);
  schedule1.addWhiteInterval(interval11);
  schedule1.addWhiteInterval(interval12);
  schedule1.addBlackInterval(interval13);

  // Set up the second schedule.
  var schedule2 = new Schedule();
  var interval21 = new RepetitiveInterval
    (Common.fromIsoString("20150825T000000"),
     Common.fromIsoString("20150827T000000"), 9, 12, 1,
     RepetitiveInterval.RepeatUnit.DAY);
  var interval22 = new RepetitiveInterval
    (Common.fromIsoString("20150827T000000"),
     Common.fromIsoString("20150827T000000"), 6, 8);
  var interval23 = new RepetitiveInterval
    (Common.fromIsoString("20150827T000000"),
     Common.fromIsoString("20150827T000000"), 2, 4);
  schedule2.addWhiteInterval(interval21);
  schedule2.addWhiteInterval(interval22);
  schedule2.addBlackInterval(interval23);

  var memberA;
  var memberB;
  var memberC;

  // Add them to the group manager database.
  return manager.addSchedulePromise("schedule1", schedule1)
  .then(function() {
    return manager.addSchedulePromise("schedule2", schedule2);
  })
  .then(function() {
    // Make some adaptions to certificate.
    var dataBlob = certificate.wireEncode();

    memberA = new Data();
    memberA.wireDecode(dataBlob, TlvWireFormat.get());
    memberA.setName(new Name("/ndn/memberA/KEY/ksk-123/ID-CERT/123"));
    memberB = new Data();
    memberB.wireDecode(dataBlob, TlvWireFormat.get());
    memberB.setName(new Name("/ndn/memberB/KEY/ksk-123/ID-CERT/123"));
    memberC = new Data();
    memberC.wireDecode(dataBlob, TlvWireFormat.get());
    memberC.setName(new Name("/ndn/memberC/KEY/ksk-123/ID-CERT/123"));

    // Add the members to the database.
    return manager.addMemberPromise("schedule1", memberA);
  })
  .then(function() {
    return manager.addMemberPromise("schedule1", memberB);
  })
  .then(function() {
    return manager.addMemberPromise("schedule2", memberC);
  });
}

describe ("TestGroupManager", function() {
  beforeEach(function(done) {
    dKeyDatabaseFilePath = "policy_config/manager-d-key-test.db";
    try {
      fs.unlinkSync(dKeyDatabaseFilePath);
    } catch (e) {}

    eKeyDatabaseFilePath = "policy_config/manager-e-key-test.db";
    try {
      fs.unlinkSync(eKeyDatabaseFilePath);
    } catch (e) {}

    intervalDatabaseFilePath = "policy_config/manager-interval-test.db";
    try {
      fs.unlinkSync(intervalDatabaseFilePath);
    } catch (e) {}

    groupKeyDatabaseFilePath = "policy_config/manager-group-key-test.db";
    try {
      fs.unlinkSync(groupKeyDatabaseFilePath);
    } catch (e) {}

    var params = new RsaKeyParams();
    var memberDecryptKey = RsaAlgorithm.generateKey(params);
    decryptKeyBlob = memberDecryptKey.getKeyBits();
    var memberEncryptKey = RsaAlgorithm.deriveEncryptKey(decryptKeyBlob);
    encryptKeyBlob = memberEncryptKey.getKeyBits();

    // Generate the certificate.
    certificate.setName(new Name("/ndn/memberA/KEY/ksk-123/ID-CERT/123"));
    var contentPublicKey = new PublicKey(encryptKeyBlob);
    certificate.setPublicKeyInfo(contentPublicKey);
    certificate.encode();

    var signatureInfoBlob = new Blob(SIG_INFO, false);
    var signatureValueBlob = new Blob(SIG_VALUE, false);

    var signature = TlvWireFormat.get().decodeSignatureInfoAndValue
      (signatureInfoBlob.buf(), signatureValueBlob.buf());
    certificate.setSignature(signature);

    certificate.wireEncode();

    // Set up the keyChain.
    var identityStorage = new MemoryIdentityStorage();
    var privateKeyStorage = new MemoryPrivateKeyStorage();
    keyChain = new KeyChain
      (new IdentityManager(identityStorage, privateKeyStorage),
       new NoVerifyPolicyManager());
    var identityName = new Name("TestGroupManager");
    keyChain.createIdentityAndCertificate(identityName);
    keyChain.getIdentityManager().setDefaultIdentity(identityName);

    done();
  });

  afterEach(function(done) {
    try {
      fs.unlinkSync(dKeyDatabaseFilePath);
    } catch (e) {}
    try {
      fs.unlinkSync(eKeyDatabaseFilePath);
    } catch (e) {}
    try {
      fs.unlinkSync(intervalDatabaseFilePath);
    } catch (e) {}
    try {
      fs.unlinkSync(groupKeyDatabaseFilePath);
    } catch (e) {}

    done();
  });

  it("CreateDKeyData", function(done) {
    // Create the group manager.
    var manager = new GroupManager
      (new Name("Alice"), new Name("data_type"),
       new Sqlite3GroupManagerDb(dKeyDatabaseFilePath), 2048, 1, keyChain);

    var newCertificateBlob = certificate.wireEncode();
    var newCertificate = new IdentityCertificate();
    newCertificate.wireDecode(newCertificateBlob);

    var encryptedNonce;
    var dataContent;
    var decryptParams;

    // Encrypt the D-KEY.
    manager.createDKeyDataPromise_
      ("20150825T000000", "20150827T000000", new Name("/ndn/memberA/KEY"),
       decryptKeyBlob, newCertificate.getPublicKeyInfo().getKeyDer())
    .then(function(data) {
      // Verify the encrypted D-KEY.
      dataContent = data.getContent();

      // Get the nonce key.
      // dataContent is a sequence of the two EncryptedContent.
      encryptedNonce = new EncryptedContent();
      encryptedNonce.wireDecode(dataContent);
      assert.equal(encryptedNonce.getInitialVector().size(), 0);
      assert.equal(encryptedNonce.getAlgorithmType(), EncryptAlgorithmType.RsaOaep);

      var blobNonce = encryptedNonce.getPayload();
      decryptParams = new EncryptParams(EncryptAlgorithmType.RsaOaep);
      return RsaAlgorithm.decryptPromise(decryptKeyBlob, blobNonce, decryptParams);
    })
    .then(function(nonce) {
      // Get the D-KEY.
      // Use the size of encryptedNonce to find the start of encryptedPayload.
      var payloadContent = dataContent.buf().slice
        (encryptedNonce.wireEncode().size());
      var encryptedPayload = new EncryptedContent();
      encryptedPayload.wireDecode(payloadContent);
      assert.equal(encryptedPayload.getInitialVector().size(), 16);
      assert.equal(encryptedPayload.getAlgorithmType(), EncryptAlgorithmType.AesCbc);

      decryptParams.setAlgorithmType(EncryptAlgorithmType.AesCbc);
      decryptParams.setInitialVector(encryptedPayload.getInitialVector());
      var blobPayload = encryptedPayload.getPayload();
      return AesAlgorithm.decryptPromise(nonce, blobPayload, decryptParams);
    })
    .then(function(largePayload) {
      assert.ok(largePayload.equals(decryptKeyBlob));

      return Promise.resolve();
    })
    // When done is called, Mocha displays errors from assert.ok.
    .then(done, done);
  });

  it("CreateEKeyData", function(done) {
    // Create the group manager.
    var manager = new GroupManager
      (new Name("Alice"), new Name("data_type"),
       new Sqlite3GroupManagerDb(eKeyDatabaseFilePath), 1024, 1, keyChain);

    setManagerPromise(manager)
    .then(function() {
      return manager.createEKeyDataPromise_
        ("20150825T090000", "20150825T110000", encryptKeyBlob);
    })
    .then(function(data) {
      assert.equal(data.getName().toUri(),
                   "/Alice/READ/data_type/E-KEY/20150825T090000/20150825T110000")

      var contentBlob = data.getContent();
      assert.ok(encryptKeyBlob.equals(contentBlob));

      return Promise.resolve();
    })
    // When done is called, Mocha displays errors from assert.ok.
    .then(done, done);
  });

  it("CalculateInterval", function(done) {
    // Create the group manager.
    var manager = new GroupManager
      (new Name("Alice"), new Name("data_type"),
       new Sqlite3GroupManagerDb(intervalDatabaseFilePath), 1024, 1, keyChain);

    var memberKeys = [];

    setManagerPromise(manager)
    .then(function() {
      var timePoint1 = Common.fromIsoString("20150825T093000");
      return manager.calculateIntervalPromise_(timePoint1, memberKeys);
    })
    .then(function(result) {
      assert.equal(Common.toIsoString(result.getStartTime()), "20150825T090000");
      assert.equal(Common.toIsoString(result.getEndTime()), "20150825T100000");

      var timePoint2 = Common.fromIsoString("20150827T073000");
      return manager.calculateIntervalPromise_(timePoint2, memberKeys);
    })
    .then(function(result) {
      assert.equal(Common.toIsoString(result.getStartTime()), "20150827T070000");
      assert.equal(Common.toIsoString(result.getEndTime()), "20150827T080000");

      var timePoint3 = Common.fromIsoString("20150827T043000");
      return manager.calculateIntervalPromise_(timePoint3, memberKeys);
    })
    .then(function(result) {
      assert.equal(result.isValid(), false);

      var timePoint4 = Common.fromIsoString("20150827T053000");
      return manager.calculateIntervalPromise_(timePoint4, memberKeys);
    })
    .then(function(result) {
      assert.equal(Common.toIsoString(result.getStartTime()), "20150827T050000");
      assert.equal(Common.toIsoString(result.getEndTime()), "20150827T060000");

      return Promise.resolve();
    })
    // When done is called, Mocha displays errors from assert.ok.
    .then(done, done);
  });

  it("GetGroupKey", function(done) {
    // Create the group manager.
    var manager = new GroupManager
      (new Name("Alice"), new Name("data_type"),
       new Sqlite3GroupManagerDb(groupKeyDatabaseFilePath), 1024, 1, keyChain);

    var result;
    var data;
    var groupEKey;
    var dataContent;
    var encryptedNonce;
    var decryptParams;

    setManagerPromise(manager)
    .then(function() {
      // Get the data list from the group manager.
      var timePoint1 = Common.fromIsoString("20150825T093000");
      return manager.getGroupKeyPromise(timePoint1);
    })
    .then(function(localResult) {
      result = localResult;
      assert.equal(result.length, 4);

      // The first data packet contains the group's encryption key (public key).
      data = result[0];
      assert.equal
        (data.getName().toUri(),
         "/Alice/READ/data_type/E-KEY/20150825T090000/20150825T100000");
      groupEKey = new EncryptKey(data.getContent());

      // Get the second data packet and decrypt.
      data = result[1];
      assert.equal
        (data.getName().toUri(),
         "/Alice/READ/data_type/D-KEY/20150825T090000/20150825T100000/FOR/ndn/memberA/ksk-123");

      /////////////////////////////////////////////////////// Start decryption.
      dataContent = data.getContent();

      // Get the nonce key.
      // dataContent is a sequence of the two EncryptedContent.
      encryptedNonce = new EncryptedContent();
      encryptedNonce.wireDecode(dataContent);
      assert.equal(encryptedNonce.getInitialVector().size(), 0);
      assert.equal(encryptedNonce.getAlgorithmType(), EncryptAlgorithmType.RsaOaep);

      decryptParams = new EncryptParams(EncryptAlgorithmType.RsaOaep);
      var blobNonce = encryptedNonce.getPayload();
      return RsaAlgorithm.decryptPromise(decryptKeyBlob, blobNonce, decryptParams);
    })
    .then(function(nonce) {
      // Get the payload.
      // Use the size of encryptedNonce to find the start of encryptedPayload.
      var payloadContent = dataContent.buf().slice
        (encryptedNonce.wireEncode().size());
      var encryptedPayload = new EncryptedContent();
      encryptedPayload.wireDecode(payloadContent);
      assert.equal(encryptedPayload.getInitialVector().size(), 16);
      assert.equal(encryptedPayload.getAlgorithmType(), EncryptAlgorithmType.AesCbc);

      decryptParams.setAlgorithmType(EncryptAlgorithmType.AesCbc);
      decryptParams.setInitialVector(encryptedPayload.getInitialVector());
      var blobPayload = encryptedPayload.getPayload();
      return AesAlgorithm.decryptPromise(nonce, blobPayload, decryptParams);
    })
    .then(function(largePayload) {
      // Get the group D-KEY.
      var groupDKey = new DecryptKey(largePayload);

      /////////////////////////////////////////////////////// End decryption.

      // Check the D-KEY.
      var derivedGroupEKey = RsaAlgorithm.deriveEncryptKey
        (groupDKey.getKeyBits());
      assert.ok(groupEKey.getKeyBits().equals(derivedGroupEKey.getKeyBits()));

      // Check the third data packet.
      data = result[2];
      assert.equal
        (data.getName().toUri(),
         "/Alice/READ/data_type/D-KEY/20150825T090000/20150825T100000/FOR/ndn/memberB/ksk-123");

      // Check the fourth data packet.
      data = result[3];
      assert.equal
        (data.getName().toUri(),
         "/Alice/READ/data_type/D-KEY/20150825T090000/20150825T100000/FOR/ndn/memberC/ksk-123");

      // Check invalid time stamps for getting the group key.
      var timePoint2 = Common.fromIsoString("20150826T083000");
      return manager.getGroupKeyPromise(timePoint2);
    })
    .then(function(localResult) {
      assert.equal(localResult.length, 0);

      var timePoint3 = Common.fromIsoString("20150827T023000");
      return manager.getGroupKeyPromise(timePoint3);
    })
    .then(function(localResult) {
      assert.equal(localResult.length, 0);

      return Promise.resolve();
    })
    // When done is called, Mocha displays errors from assert.ok.
    .then(done, done);
  });
});
