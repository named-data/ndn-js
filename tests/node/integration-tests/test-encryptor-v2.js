/**
 * Copyright (C) 2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt unit tests
 * https://github.com/named-data/name-based-access-control/blob/new/tests/tests/encryptor.t.cpp
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
var Blob = require('../../..').Blob;
var Name = require('../../..').Name;
var Interest = require('../../..').Interest;
var Data = require('../../..').Data;
var SigningInfo = require('../../..').SigningInfo;
var ValidatorNull = require('../../..').ValidatorNull;
var EncryptorV2 = require('../../..').EncryptorV2;
var InMemoryStorageRetaining = require('../../..').InMemoryStorageRetaining;
var IdentityManagementFixture = require('./identity-management-fixture.js').IdentityManagementFixture;
var InMemoryStorageFace = require('./in-memory-storage-face.js').InMemoryStorageFace;
var EncryptStaticData = require('./encrypt-static-data.js').EncryptStaticData;

/**
 * @param {boolean} shouldPublishData
 * @param {function} onError
 * @constructor
 */
var EncryptorFixture = function EncryptorFixture(shouldPublishData, onError)
{
  // Call the base constructor.
  IdentityManagementFixture.call(this);

  // Include the code here from the NAC unit-tests class
  // EncryptorStaticDataEnvironment instead of making it a base class.
  this.storage_ = new InMemoryStorageRetaining();
  if (shouldPublishData)
    this.publishData();

  this.face_ = new InMemoryStorageFace(this.storage_);
  this.validator_ = new ValidatorNull();
  this.encryptor_ = new EncryptorV2
    (new Name("/access/policy/identity/NAC/dataset"),
     new Name("/some/ck/prefix"),
     new SigningInfo(SigningInfo.SignerType.SHA256),
     onError, this.validator_, this.keyChain_, this.face_);
};

EncryptorFixture.prototype = new IdentityManagementFixture();
EncryptorFixture.prototype.name = "EncryptorFixture";

EncryptorFixture.prototype.publishData = function()
{
  for (var i in EncryptStaticData.managerPackets) {
    var data = new Data();
    data.wireDecode(EncryptStaticData.managerPackets[i]);
    this.storage_.insert(data);
  }
};

describe ("TestEncryptorV2", function() {
  beforeEach(function() {
    this.fixture_ = new EncryptorFixture
      (true,
       function(code, message) { assert.fail('', '', "onError: " + message); });
  });

  it("EncryptAndPublishCk", function() {
    this.fixture_.encryptor_.kekData_ = null;
    assert.equal(false, this.fixture_.encryptor_.isKekRetrievalInProgress_);
    this.fixture_.encryptor_.regenerateCk();
    // Unlike the ndn-group-encrypt unit tests, we don't check
    // isKekRetrievalInProgress_ true because we use a synchronous face which
    // finishes immediately.

    var plainText = new Blob("Data to encrypt");
    var encryptedContent = this.fixture_.encryptor_.encrypt(plainText);

    var ckPrefix = encryptedContent.getKeyLocatorName();
    assert.ok(new Name("/some/ck/prefix/CK").equals(ckPrefix.getPrefix(-1)));

    assert.ok(encryptedContent.hasInitialVector());
    assert.ok(!encryptedContent.getPayload().equals(plainText));

    // Check that the KEK Interest has been sent.
    assert.ok(this.fixture_.face_.sentInterests_[0].getName().getPrefix(6).equals
      (new Name("/access/policy/identity/NAC/dataset/KEK")));

    var kekData = this.fixture_.face_.sentData_[0];
    assert.ok(kekData.getName().getPrefix(6).equals
      (new Name("/access/policy/identity/NAC/dataset/KEK")));
    assert.equal(7, kekData.getName().size());

    this.fixture_.face_.sentData_ = [];
    this.fixture_.face_.sentInterests_ = [];

    this.fixture_.face_.receive
      (new Interest(ckPrefix).setCanBePrefix(true).setMustBeFresh(true));

    var ckName = this.fixture_.face_.sentData_[0].getName();
    assert.ok(ckName.getPrefix(4).equals(new Name("/some/ck/prefix/CK")));
    assert.ok(ckName.get(5).equals(new Name.Component("ENCRYPTED-BY")));

    var extractedKek = ckName.getSubName(6);
    assert.ok(extractedKek.equals(kekData.getName()));

    assert.equal(false, this.fixture_.encryptor_.isKekRetrievalInProgress_);
  });

  it("KekRetrievalFailure", function() {
    // Replace the default fixture.
    var nErrors = [0];
    this.fixture_ = new EncryptorFixture
      (false, function(errorCode, message) { ++nErrors[0]; });

    var plainText = new Blob("Data to encrypt");
    var encryptedContent = this.fixture_.encryptor_.encrypt(plainText);

    // Check that KEK interests has been sent.
    assert.ok(this.fixture_.face_.sentInterests_[0].getName().getPrefix(6).equals
      (new Name("/access/policy/identity/NAC/dataset/KEK")));

    // ... and failed to retrieve.
    assert.equal(0, this.fixture_.face_.sentData_.length);

    assert.equal(1, nErrors[0]);
    assert.equal(0, this.fixture_.face_.sentData_.length);

    // Check recovery.
    this.fixture_.publishData();

    // Simulate the behavior of onTimeout in EncryptorV2.fetchKekAndPublishCkData_
    // which calls retryFetchingKek_() after a delay.
    this.fixture_.encryptor_.retryFetchingKek_();

    var kekData = this.fixture_.face_.sentData_[0];
    assert.ok(kekData.getName().getPrefix(6).equals
      (new Name("/access/policy/identity/NAC/dataset/KEK")));
    assert.equal(7, kekData.getName().size());
  });

  it("EnumerateDataFromInMemoryStorage", function() {
    this.fixture_.encryptor_.regenerateCk();
    this.fixture_.encryptor_.regenerateCk();

    assert.equal(3, this.fixture_.encryptor_.size());
    var nCk = 0;
    for (var nameUri in this.fixture_.encryptor_.storage_.cache_) {
      var data = this.fixture_.encryptor_.storage_.cache_[nameUri];
      if (data.getName().getPrefix(4).equals(new Name("/some/ck/prefix/CK")))
        ++nCk;
    }
    assert.equal(3, nCk);
  });
});
