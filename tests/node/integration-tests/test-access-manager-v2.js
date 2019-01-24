/**
 * Copyright (C) 2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt unit tests
 * https://github.com/named-data/name-based-access-control/blob/new/tests/tests/access-manager.t.cpp
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
var Name = require('../../..').Name;
var Interest = require('../../..').Interest;
var RsaKeyParams = require('../../..').RsaKeyParams;
var EncryptorV2 = require('../../..').EncryptorV2;
var AccessManagerV2 = require('../../..').AccessManagerV2;
var InMemoryStorageRetaining = require('../../..').InMemoryStorageRetaining;
var IdentityManagementFixture = require('./identity-management-fixture.js').IdentityManagementFixture;
var InMemoryStorageFace = require('./in-memory-storage-face.js').InMemoryStorageFace;

/**
 * @constructor
 */
var AccessManagerFixture = function AccessManagerFixture()
{
  // Call the base constructor.
  IdentityManagementFixture.call(this);

  this.userIdentities_ = [];

  this.face_ = new InMemoryStorageFace(this.storage_);
  this.accessIdentity_ = this.addIdentity(new Name("/access/policy/identity"));
  // This is a hack to get access to the KEK key-id.
  this.nacIdentity_ = this.addIdentity
    (new Name("/access/policy/identity/NAC/dataset"), new RsaKeyParams());
  this.userIdentities_.push
    (this.addIdentity(new Name("/first/user"), new RsaKeyParams()));
  this.userIdentities_.push
    (this.addIdentity(new Name("/second/user"), new RsaKeyParams()));
  this.manager_ = new AccessManagerV2
    (this.accessIdentity_, new Name("/dataset"), this.keyChain_, this.face_);

  for (var i in this.userIdentities_)
    this.manager_.addMember
      (this.userIdentities_[i].getDefaultKey().getDefaultCertificate());
};

AccessManagerFixture.prototype = new IdentityManagementFixture();
AccessManagerFixture.prototype.name = "AccessManagerFixture";

describe ("TestAccessManagerV2", function() {
  beforeEach(function() {
    this.fixture_ = new AccessManagerFixture();
  });

  it("PublishedKek", function() {
    this.fixture_.face_.receive(new Interest
      (new Name("/access/policy/identity/NAC/dataset/KEK"))
       .setCanBePrefix(true).setMustBeFresh(true));

    assert.ok(this.fixture_.face_.sentData_[0].getName().getPrefix(-1).equals
      (new Name("/access/policy/identity/NAC/dataset/KEK")));
    assert.ok(this.fixture_.face_.sentData_[0].getName().get(-1).equals
      (this.fixture_.nacIdentity_.getDefaultKey().getName().get(-1)));
  });

  it("PublishedKdks", function() {
    for (var i in this.fixture_.userIdentities_) {
      var user = this.fixture_.userIdentities_[i];

      var kdkName = new Name("/access/policy/identity/NAC/dataset/KDK");
      kdkName
        .append(this.fixture_.nacIdentity_.getDefaultKey().getName().get(-1))
        .append("ENCRYPTED-BY")
        .append(user.getDefaultKey().getName());

      this.fixture_.face_.receive
        (new Interest(kdkName).setCanBePrefix(true).setMustBeFresh(true));

      assert.ok(this.fixture_.face_.sentData_[0].getName().equals(kdkName),
        "Sent Data does not have the KDK name " + kdkName.toUri());
      this.fixture_.face_.sentData_ = [];
    }
  });

  it("EnumerateDataFromInMemoryStorage", function() {
    assert.equal(3, this.fixture_.manager_.size());

    var nKek = 0;
    var nKdk = 0;
    for (var nameUri in this.fixture_.manager_.storage_.cache_) {
      var data = this.fixture_.manager_.storage_.cache_[nameUri];

      if (data.getName().get(5).equals(EncryptorV2.NAME_COMPONENT_KEK))
        ++nKek;
      if (data.getName().get(5).equals(EncryptorV2.NAME_COMPONENT_KDK))
        ++nKdk;
    }

    assert.equal(1, nKek);
    assert.equal(2, nKdk);
  });
});
