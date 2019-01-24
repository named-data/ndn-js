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
var Data = require('../../..').Data;
var ValidatorNull = require('../../..').ValidatorNull;
var DecryptorV2 = require('../../..').DecryptorV2;
var SafeBag = require('../../..').SafeBag;
var InMemoryStorageRetaining = require('../../..').InMemoryStorageRetaining;
var EncryptedContent = require('../../..').EncryptedContent;
var IdentityManagementFixture = require('./identity-management-fixture.js').IdentityManagementFixture;
var InMemoryStorageFace = require('./in-memory-storage-face.js').InMemoryStorageFace;
var EncryptStaticData = require('./encrypt-static-data.js').EncryptStaticData;

/**
 * @param {Name} identityName
 * @constructor
 */
var DecryptorFixture = function DecryptorFixture(identityName)
{
  // Call the base constructor.
  IdentityManagementFixture.call(this);

  // Include the code here from the NAC unit-tests class
  // EncryptorStaticDataEnvironment instead of making it a base class.
  this.storage_ = new InMemoryStorageRetaining();
  for (var i in EncryptStaticData.managerPackets) {
    var data = new Data();
    data.wireDecode(EncryptStaticData.managerPackets[i]);
    this.storage_.insert(data);
  }

  for (var i in EncryptStaticData.encryptorPackets) {
    var data = new Data();
    data.wireDecode(EncryptStaticData.encryptorPackets[i]);
    this.storage_.insert(data);
  }

  // Import the "/first/user" identity.
  this.keyChain_.importSafeBag
    (new SafeBag(EncryptStaticData.userIdentity),
     new Blob("password").buf());

  this.addIdentity(new Name("/not/authorized"));

  this.face_ = new InMemoryStorageFace(this.storage_);
  this.validator_ = new ValidatorNull();
  this.decryptor_ = new DecryptorV2
    (this.keyChain_.getPib().getIdentity(identityName).getDefaultKey(),
     this.validator_, this.keyChain_, this.face_);
};

DecryptorFixture.prototype = new IdentityManagementFixture();
DecryptorFixture.prototype.name = "DecryptorFixture";

describe ("TestDecryptorV2", function() {
  it("DecryptValid", function() {
    var fixture = new DecryptorFixture(new Name("/first/user"));

    var encryptedContent = new EncryptedContent();
    encryptedContent.wireDecodeV2(EncryptStaticData.encryptedBlobs[0]);

    var nSuccesses = [0];
    var nFailures = [0];
    fixture.decryptor_.decrypt
      (encryptedContent,
       function(plainData) {
         ++nSuccesses[0];
         assert.equal(15, plainData.size());
         assert.ok(plainData.equals(new Blob("Data to encrypt")));
       },
       function(errorCode, message) {
         ++nFailures[0];
       });

    assert.equal(1, nSuccesses[0]);
    assert.equal(0, nFailures[0]);
  });

  it("DecryptInvalid", function() {
    var fixture = new DecryptorFixture(new Name("/not/authorized"));

    var encryptedContent = new EncryptedContent();
    encryptedContent.wireDecodeV2(EncryptStaticData.encryptedBlobs[0]);

    var nSuccesses = [0];
    var nFailures = [0];
    fixture.decryptor_.decrypt
      (encryptedContent,
       function(plainData) {
         ++nSuccesses[0];
       },
       function(errorCode, message) {
         ++nFailures[0];
       });

    assert.equal(0, nSuccesses[0]);
    assert.equal(1, nFailures[0]);
  });
});
