/**
 * Copyright (C) 2015-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/v2/key-chain.t.cpp
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
var Pib = require('../../..').Pib;
var CertificateV2 = require('../../..').CertificateV2;
var SyncPromise = require('../../../js/util/sync-promise').SyncPromise;
var IdentityManagementFixture = require('./identity-management-fixture.js').IdentityManagementFixture;

describe ("TestKeyChain", function() {
  beforeEach(function() {
    this.fixture_ = new IdentityManagementFixture();
  });

  it("Management", function() {
    var identityName = new Name("/test/id");
    var identity2Name = new Name("/test/id2");

    // We must initialize the Pib.
    SyncPromise.getValue
      (this.fixture_.keyChain_.getPib().initializePromise_());
    assert.equal(0, this.fixture_.keyChain_.getPib().identities_.size());
    try {
      this.fixture_.keyChain_.getPib().getDefaultIdentity();
      assert.fail('', '', "Did not throw the expected exception");
    } catch (ex) {
      if (!(ex instanceof Pib.Error))
        assert.fail('', '', "Did not throw the expected exception");
    }

    // Create an identity.
    var id = this.fixture_.keyChain_.createIdentityV2(identityName);
    assert.ok(id != null);
    assert.ok
      (this.fixture_.keyChain_.getPib().identities_.identities_[identityName]
       !== undefined);

    // The first added identity becomes the default identity.
    try {
      this.fixture_.keyChain_.getPib().getDefaultIdentity();
    } catch (ex) {
      assert.fail('', '', "Unexpected exception: " + ex);
    }

    // The default key of the added identity must exist.
    var key;
    try {
      key = id.getDefaultKey();
    } catch (ex) {
      assert.fail('', '', "Unexpected exception: " + ex);
    }

    // The default certificate of the default key must exist.
    try {
      key.getDefaultCertificate();
    } catch (ex) {
      assert.fail('', '', "Unexpected exception: " + ex);
    }

    // Delete the key.
    var key1Name = key.getName();
    try {
      id.getKey(key1Name);
    } catch (ex) {
      assert.fail('', '', "Unexpected exception: " + ex);
    }

    assert.equal(1, id.getKeys_().size());
    this.fixture_.keyChain_.deleteKey(id, key);
// TODO: Implement key validity.
//        // The key instance should not be valid anymore.
//        assert.ok(!key);

    try {
      id.getKey(key1Name);
      assert.fail('', '', "Did not throw the expected exception");
    } catch (ex) {
      if (!(ex instanceof Pib.Error))
        assert.fail('', '', "Did not throw the expected exception");
    }

    assert.equal(0, id.getKeys_().size());

    // Create another key.
    this.fixture_.keyChain_.createKey(id);
    // The added key becomes the default key.
    try {
      id.getDefaultKey();
    } catch (ex) {
      assert.fail('', '', "Unexpected exception: " + ex);
    }

    var key2 = id.getDefaultKey();
    assert.ok(key2 != null);
    assert.ok(!key2.getName().equals(key1Name));
    assert.equal(1, id.getKeys_().size());
    try {
      key2.getDefaultCertificate();
    } catch (ex) {
      assert.fail('', '', "Unexpected exception: " + ex);
    }

    // Create a third key.
    var key3 = this.fixture_.keyChain_.createKey(id);
    assert.ok(!key3.getName().equals(key2.getName()));
    // The added key will not be the default key, because the default key
    // already exists.
    assert.ok(id.getDefaultKey().getName().equals(key2.getName()));
    assert.equal(2, id.getKeys_().size());
    try {
      key3.getDefaultCertificate();
    } catch (ex) {
      assert.fail('', '', "Unexpected exception: " + ex);
    }

    // Delete the certificate.
    assert.equal(1, key3.getCertificates_().size());
    var key3Cert1 = key3.getCertificates_().certificates_
      [Object.keys(key3.getCertificates_().certificates_)[0]];
    var key3CertName = key3Cert1.getName();
    this.fixture_.keyChain_.deleteCertificate(key3, key3CertName);
    assert.equal(0, key3.getCertificates_().size());
    try {
      key3.getDefaultCertificate();
      assert.fail('', '', "Did not throw the expected exception");
    } catch (ex) {
      if (!(ex instanceof Pib.Error))
        assert.fail('', '', "Did not throw the expected exception");
    }

    // Add a certificate.
    this.fixture_.keyChain_.addCertificate(key3, key3Cert1);
    assert.equal(1, key3.getCertificates_().size());
    try {
      key3.getDefaultCertificate();
    } catch (ex) {
      assert.fail('', '', "Unexpected exception: " + ex);
    }

    // Overwriting the certificate should work.
    this.fixture_.keyChain_.addCertificate(key3, key3Cert1);
    assert.equal(1, key3.getCertificates_().size());
    // Add another certificate.
    var key3Cert2 = new CertificateV2(key3Cert1);
    var key3Cert2Name = new Name(key3.getName());
    key3Cert2Name.append("Self");
    key3Cert2Name.appendVersion(1);
    key3Cert2.setName(key3Cert2Name);
    this.fixture_.keyChain_.addCertificate(key3, key3Cert2);
    assert.equal(2, key3.getCertificates_().size());

    // Set the default certificate.
    assert.ok(key3.getDefaultCertificate().getName().equals(key3CertName));
    this.fixture_.keyChain_.setDefaultCertificate(key3, key3Cert2);
    assert.ok(key3.getDefaultCertificate().getName().equals(key3Cert2Name));

    // Set the default key.
    assert.ok(id.getDefaultKey().getName().equals(key2.getName()));
    this.fixture_.keyChain_.setDefaultKey(id, key3);
    assert.ok(id.getDefaultKey().getName().equals(key3.getName()));

    // Set the default identity.
    var id2 = this.fixture_.keyChain_.createIdentityV2(identity2Name);
    assert.ok(this.fixture_.keyChain_.getPib().getDefaultIdentity().getName()
      .equals(id.getName()));
    this.fixture_.keyChain_.setDefaultIdentity(id2);
    assert.ok(this.fixture_.keyChain_.getPib().getDefaultIdentity().getName()
      .equals(id2.getName()));

    // Delete an identity.
    this.fixture_.keyChain_.deleteIdentity(id);
// TODO: Implement identity validity.
//        // The identity instance should not be valid anymore.
//        BOOST_CHECK(!id)
    try {
      this.fixture_.keyChain_.getPib().getIdentity(identityName);
      assert.fail('', '', "Did not throw the expected exception");
    } catch (ex) {
      if (!(ex instanceof Pib.Error))
        assert.fail('', '', "Did not throw the expected exception");
    }

    assert.ok
      (this.fixture_.keyChain_.getPib().identities_.identities_[identityName]
       === undefined);
  });

  it("SelfSignedCertValidity", function() {
    var certificate = this.fixture_.addIdentity
      (new Name("/Security/V2/TestKeyChain/SelfSignedCertValidity"))
       .getDefaultKey().getDefaultCertificate();
    assert.ok(certificate.isValid());
    // Check 10 years from now.
    assert.ok(certificate.isValid
      (new Date().getTime() + 10 * 365 * 24 * 3600 * 1000.0));
    // Check that notAfter is later than 10 years from now.
    assert.ok(certificate.getValidityPeriod().getNotAfter() >
      new Date().getTime() + 10 * 365 * 24 * 3600 * 1000.0);
  });
});
