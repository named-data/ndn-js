/**
 * Copyright (C) 2018-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/v2/trust-anchor-container.t.cpp
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

var fs = require("fs");
var path = require("path");
var assert = require("assert");
var Name = require('../../..').Name;
var Interest = require('../../..').Interest;
var CertificateV2 = require('../../..').CertificateV2;
var TrustAnchorContainer = require('../../../js/security/v2/trust-anchor-container.js').TrustAnchorContainer;
var StaticTrustAnchorGroup = require('../../../js/security/v2/static-trust-anchor-group.js').StaticTrustAnchorGroup;
var IdentityManagementFixture = require('./identity-management-fixture.js').IdentityManagementFixture;

describe ("TestTrustAnchorContainer", function() {
  beforeEach(function() {
    this.anchorContainer = new TrustAnchorContainer();
    this.fixture = new IdentityManagementFixture();

    // Create a directory and prepares two certificates.
    this.certificateDirectoryPath = path.join("policy_config", "test-cert-dir");
    try {
      fs.mkdirSync(this.certificateDirectoryPath);
    } catch (ex) {}

    this.certificatePath1 =
      path.join(this.certificateDirectoryPath, "trust-anchor-1.cert");
    this.certificatePath2 =
      path.join(this.certificateDirectoryPath, "trust-anchor-2.cert");

    this.identity1 = this.fixture.addIdentity(new Name("/TestAnchorContainer/First"));
    this.certificate1 = this.identity1.getDefaultKey().getDefaultCertificate();
    this.fixture.saveCertificateToFile(this.certificate1, this.certificatePath1);

    this.identity2 = this.fixture.addIdentity(new Name("/TestAnchorContainer/Second"));
    this.certificate2 = this.identity2.getDefaultKey().getDefaultCertificate();
    this.fixture.saveCertificateToFile(this.certificate2, this.certificatePath2);
  });

  afterEach(function() {
    try {
      fs.unlinkSync(this.certificatePath1);
    }
    catch (e) {}

    try {
      fs.unlinkSync(this.certificatePath2);
    }
    catch (e) {}
  });

  it("Insert", function(done) {
    // Static
    this.anchorContainer.insert("group1", this.certificate1);
    assert.ok(this.anchorContainer.find(this.certificate1.getName()) != null);
    assert.ok(this.anchorContainer.find(this.identity1.getName()) != null);
    var certificate = this.anchorContainer.find(this.certificate1.getName());
    try {
      // Re-inserting the same certificate should do nothing.
      this.anchorContainer.insert("group1", this.certificate1);
    } catch (ex) {
      assert.fail('', '', "Unexpected exception: " + ex);
    }
    // It should still be the same instance of the certificate.
    assert.ok(certificate == this.anchorContainer.find(this.certificate1.getName()));
    // Cannot add a dynamic group when the static already exists.
    try {
      this.anchorContainer.insert("group1", this.certificatePath1, 400.0);
      assert.fail('', '', "Did not throw the expected exception");
    } catch (ex) {
      if (!(ex instanceof TrustAnchorContainer.Error))
        assert.fail('', '', "Did not throw the expected exception");
    }

    assert.equal(1, this.anchorContainer.getGroup("group1").size());
    assert.equal(1, this.anchorContainer.size());

    // From file
    this.anchorContainer.insert("group2", this.certificatePath2, 400.0);
    assert.ok(this.anchorContainer.find(this.certificate2.getName()) != null);
    assert.ok(this.anchorContainer.find(this.identity2.getName()) != null);
    try {
      this.anchorContainer.insert("group2", this.certificate2);
      assert.fail('', '', "Did not throw the expected exception");
    } catch (ex) {
      if (!(ex instanceof TrustAnchorContainer.Error))
        assert.fail('', '', "Did not throw the expected exception");
    }

    try {
      this.anchorContainer.insert("group2", this.certificatePath2, 400.0);
      assert.fail('', '', "Did not throw the expected exception");
    } catch (ex) {
      if (!(ex instanceof TrustAnchorContainer.Error))
        assert.fail('', '', "Did not throw the expected exception");
    }

    assert.equal(1, this.anchorContainer.getGroup("group2").size());
    assert.equal(2, this.anchorContainer.size());

    try {
      fs.unlinkSync(this.certificatePath2);
    }
    catch (e) {}

    // Wait for the refresh period to expire.
    var thisTest = this;
    setTimeout(function() {
      assert.ok(thisTest.anchorContainer.find(thisTest.identity2.getName()) == null);
      assert.ok(thisTest.anchorContainer.find(thisTest.certificate2.getName()) == null);
      assert.equal(0, thisTest.anchorContainer.getGroup("group2").size());
      assert.equal(1, thisTest.anchorContainer.size());

      var staticGroup = thisTest.anchorContainer.getGroup("group1");
      assert.ok(staticGroup instanceof StaticTrustAnchorGroup);
      assert.equal(1, staticGroup.size());
      staticGroup.remove(thisTest.certificate1.getName());
      assert.equal(0, staticGroup.size());
      assert.equal(0, thisTest.anchorContainer.size());

      try {
        thisTest.anchorContainer.getGroup("non-existing-group");
        assert.fail('', '', "Did not throw the expected exception");
      } catch (ex) {
        if (!(ex instanceof TrustAnchorContainer.Error))
          assert.fail('', '', "Did not throw the expected exception");
      }

      done();
    }, 500);
  });

  it("DynamicAnchorFromDirectory", function(done) {
    try {
      fs.unlinkSync(this.certificatePath2);
    }
    catch (e) {}

    this.anchorContainer.insert
      ("group", this.certificateDirectoryPath, 400.0, true);

    assert.ok(this.anchorContainer.find(this.identity1.getName()) != null);
    assert.ok(this.anchorContainer.find(this.identity2.getName()) == null);
    assert.equal(1, this.anchorContainer.getGroup("group").size());

    this.fixture.saveCertificateToFile(this.certificate2, this.certificatePath2);

    // Wait for the refresh period to expire. The dynamic anchors should remain.
    var thisTest = this;
    setTimeout(function() {
      assert.ok(thisTest.anchorContainer.find(thisTest.identity1.getName()) != null);
      assert.ok(thisTest.anchorContainer.find(thisTest.identity2.getName()) != null);
      assert.equal(2, thisTest.anchorContainer.getGroup("group").size());

      // Delete files from a previous test.
      var allFiles = fs.readdirSync(thisTest.certificateDirectoryPath);
      for (var i = 0; i < allFiles.length; ++i) {
        try {
          fs.unlinkSync(path.join(thisTest.certificateDirectoryPath, allFiles[i]));
        }
        catch (e) {}
      }

      // Wait for the refresh period to expire. The dynamic anchors should be gone.
      setTimeout(function() {
        assert.ok(thisTest.anchorContainer.find(thisTest.identity1.getName()) == null);
        assert.ok(thisTest.anchorContainer.find(thisTest.identity2.getName()) == null);
        assert.equal(0, thisTest.anchorContainer.getGroup("group").size());

        done();
      }, 500);
    }, 500);
  });

  it("FindByInterest", function() {
    this.anchorContainer.insert("group1", this.certificatePath1, 400.0);
    var interest = new Interest(this.identity1.getName());
    assert.ok(this.anchorContainer.find(interest) != null);
    var interest1 = new Interest(this.identity1.getName().getPrefix(-1));
    assert.ok(this.anchorContainer.find(interest1) != null);
    var interest2 = new Interest(new Name(this.identity1.getName()).appendVersion(1));
    assert.ok(this.anchorContainer.find(interest2) == null);

    var certificate3 =
      this.fixture.addCertificate(this.identity1.getDefaultKey(), "3");
    var certificate4 =
      this.fixture.addCertificate(this.identity1.getDefaultKey(), "4");
    var certificate5 =
      this.fixture.addCertificate(this.identity1.getDefaultKey(), "5");

    var certificate3Copy = new CertificateV2(certificate3);
    this.anchorContainer.insert("group2", certificate3Copy);
    this.anchorContainer.insert("group3", certificate4);
    this.anchorContainer.insert("group4", certificate5);

    var interest3 = new Interest(certificate3.getKeyName());
    var foundCertificate = this.anchorContainer.find(interest3);
    assert.ok(foundCertificate != null);
    assert.ok(interest3.getName().isPrefixOf(foundCertificate.getName()));
    assert.ok(certificate3.getName().equals(foundCertificate.getName()));

    interest3.getExclude().appendComponent
      (certificate3.getName().get(CertificateV2.ISSUER_ID_OFFSET));
    foundCertificate = this.anchorContainer.find(interest3);
    assert.ok(foundCertificate != null);
    assert.ok(interest3.getName().isPrefixOf(foundCertificate.getName()));
    assert.ok(!foundCertificate.getName().equals(certificate3.getName()));
  });
});
