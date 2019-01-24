/**
 * Copyright (C) 2017-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/pib/pib-impl.t.cpp
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
var path = require('path');
var Name = require('../../..').Name;
var Pib = require('../../..').Pib;
var PibMemory = require('../../..').PibMemory;
var PibSqlite3 = require('../../..').PibSqlite3;
var PibDataFixture = require('../unit-tests/pib-data-fixture.js').PibDataFixture;

var PibMemoryFixture = function PibMemoryFixture()
{
  // Call the base constructor.
  PibDataFixture.call(this);

  this.myPib_ = new PibMemory();
  this.pib = this.myPib_;
};

PibMemoryFixture.prototype = new PibDataFixture();
PibMemoryFixture.prototype.name = "PibMemoryFixture";

var PibSqlite3Fixture = function PibSqlite3Fixture
  (databaseDirectoryPath, databaseFilename)
{
  // Call the base constructor.
  PibDataFixture.call(this);

  this.myPib_ = new PibSqlite3(databaseDirectoryPath, databaseFilename);
  this.pib = this.myPib_;
};

PibSqlite3Fixture.prototype = new PibDataFixture();
PibSqlite3Fixture.prototype.name = "PibSqlite3Fixture";

describe ("TestPibImpl", function() {
  beforeEach(function(done) {
    this.pibMemoryFixture = new PibMemoryFixture();

    var databaseDirectoryPath = "policy_config";
    var databaseFilename = "test-pib.db";
    this.databaseFilePath =  path.join(databaseDirectoryPath, databaseFilename);
    try {
      fs.unlinkSync(this.databaseFilePath);
    } catch (e) {}
    this.pibSqlite3Fixture = new PibSqlite3Fixture
      (databaseDirectoryPath, databaseFilename);

    this.pibImpls = [null, null];
    this.pibImpls[0] = this.pibMemoryFixture;
    this.pibImpls[1] = this.pibSqlite3Fixture;

    done();
  });

  afterEach(function(done) {
    try {
      fs.unlinkSync(this.databaseFilePath);
    } catch (e) {}

    done();
  });

  it("CertificateDecoding", function(done) {
    // Use pibMemoryFixture to test.
    var fixture = this.pibMemoryFixture;

    assert.ok(fixture.id1Key1Cert1.getPublicKey().equals
      (fixture.id1Key1Cert2.getPublicKey()));
    assert.ok(fixture.id1Key2Cert1.getPublicKey().equals
      (fixture.id1Key2Cert2.getPublicKey()));
    assert.ok(fixture.id2Key1Cert1.getPublicKey().equals
      (fixture.id2Key1Cert2.getPublicKey()));
    assert.ok(fixture.id2Key2Cert1.getPublicKey().equals
      (fixture.id2Key2Cert2.getPublicKey()));

    assert.ok(fixture.id1Key1Cert1.getPublicKey().equals(fixture.id1Key1));
    assert.ok(fixture.id1Key1Cert2.getPublicKey().equals(fixture.id1Key1));
    assert.ok(fixture.id1Key2Cert1.getPublicKey().equals(fixture.id1Key2));
    assert.ok(fixture.id1Key2Cert2.getPublicKey().equals(fixture.id1Key2));

    assert.ok(fixture.id2Key1Cert1.getPublicKey().equals(fixture.id2Key1));
    assert.ok(fixture.id2Key1Cert2.getPublicKey().equals(fixture.id2Key1));
    assert.ok(fixture.id2Key2Cert1.getPublicKey().equals(fixture.id2Key2));
    assert.ok(fixture.id2Key2Cert2.getPublicKey().equals(fixture.id2Key2));

    assert.ok(fixture.id1Key1Cert2.getIdentity().equals(fixture.id1));
    assert.ok(fixture.id1Key2Cert1.getIdentity().equals(fixture.id1));
    assert.ok(fixture.id1Key2Cert2.getIdentity().equals(fixture.id1));

    assert.ok(fixture.id2Key1Cert2.getIdentity().equals(fixture.id2));
    assert.ok(fixture.id2Key2Cert1.getIdentity().equals(fixture.id2));
    assert.ok(fixture.id2Key2Cert2.getIdentity().equals(fixture.id2));

    assert.ok(fixture.id1Key1Cert2.getKeyName().equals(fixture.id1Key1Name));
    assert.ok(fixture.id1Key2Cert2.getKeyName().equals(fixture.id1Key2Name));

    assert.ok(fixture.id2Key1Cert2.getKeyName().equals(fixture.id2Key1Name));
    assert.ok(fixture.id2Key2Cert2.getKeyName().equals(fixture.id2Key2Name));

    done();
  });

  it("TpmLocator", function(done) {
    var thisTest = this;

    var test = function(iteration) {
      var fixture = thisTest.pibImpls[iteration];
      var pib = fixture.pib;

      // Basic getting and setting.
      return pib.getTpmLocatorPromise()
      .then(function() {
        return pib.setTpmLocatorPromise("tpmLocator");
      })
      .then(function() {
        return pib.getTpmLocatorPromise();
      })
      .then(function(tpmLocator) {
        assert.equal(tpmLocator, "tpmLocator");

        // Add a certificate, and do not change the TPM locator.
        return pib.addCertificatePromise(fixture.id1Key1Cert1);
      })
      .then(function() {
        return pib.hasIdentityPromise(fixture.id1);
      })
      .then(function(hasIdentity) {
        assert.ok(hasIdentity);
        return pib.hasKeyPromise(fixture.id1Key1Name);
      })
      .then(function(hasKey) {
        assert.ok(hasKey);
        return pib.hasCertificatePromise(fixture.id1Key1Cert1.getName());
      })
      .then(function(hasCertificate) {
        assert.ok(hasCertificate);

        // Set the TPM locator to the same value. Nothing should change.
        return pib.setTpmLocatorPromise("tpmLocator");
      })
      .then(function() {
        return pib.hasIdentityPromise(fixture.id1);
      })
      .then(function(hasIdentity) {
        assert.ok(hasIdentity);
        return pib.hasKeyPromise(fixture.id1Key1Name);
      })
      .then(function(hasKey) {
        assert.ok(hasKey);
        return pib.hasCertificatePromise(fixture.id1Key1Cert1.getName());
      })
      .then(function(hasCertificate) {
        assert.ok(hasCertificate);

        // Change the TPM locator. (The contents of the PIB should not change.)
        return pib.setTpmLocatorPromise("newTpmLocator");
      })
      .then(function() {
        return pib.hasIdentityPromise(fixture.id1);
      })
      .then(function(hasIdentity) {
        assert.ok(hasIdentity);
        return pib.hasKeyPromise(fixture.id1Key1Name);
      })
      .then(function(hasKey) {
        assert.ok(hasKey);
        return pib.hasCertificatePromise(fixture.id1Key1Cert1.getName());
      })
      .then(function(hasCertificate) {
        assert.ok(hasCertificate);

        ++iteration;
        if (iteration >= thisTest.pibImpls.length)
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

  it("IdentityManagement", function(done) {
    var thisTest = this;

    var test = function(iteration) {
      var fixture = thisTest.pibImpls[iteration];
      var pib = fixture.pib;

      return Promise.resolve()
      .then(function() {
        // No default identity is set. This should throw an Error.
        return pib.getDefaultIdentityPromise()
        .then(function() {
          assert.fail('', '', "Did not throw the expected exception");
        }, function(err) {
          if (err instanceof Pib.Error)
            return Promise.resolve();
          else
            assert.fail('', '', "Did not throw the expected exception");
        });
      })
      .then(function() {
        // Check for id1, which should not exist.
        return pib.hasIdentityPromise(fixture.id1);
      })
      .then(function(hasIdentity) {
        assert.equal(false, hasIdentity);

        // Add id1, which should be the default.
        return pib.addIdentityPromise(fixture.id1);
      })
      .then(function() {
        return pib.hasIdentityPromise(fixture.id1);
      })
      .then(function(hasIdentity) {
        assert.equal(true, hasIdentity);
        return pib.getDefaultIdentityPromise();
      })
      .then(function(defaultIdentity) {
        assert.ok(fixture.id1.equals(defaultIdentity));

        // Add id2, which should not be the default.
        return pib.addIdentityPromise(fixture.id2);
      })
      .then(function() {
        return pib.hasIdentityPromise(fixture.id2);
      })
      .then(function(hasIdentity) {
        assert.equal(true, hasIdentity);
        return pib.getDefaultIdentityPromise();
      })
      .then(function(defaultIdentity) {
        assert.ok(fixture.id1.equals(defaultIdentity));

        // Explicitly set id2 as the default.
        return pib.setDefaultIdentityPromise(fixture.id2);
      })
      .then(function() {
        return pib.getDefaultIdentityPromise();
      })
      .then(function(defaultIdentity) {
        assert.ok(fixture.id2.equals(defaultIdentity));

        // Remove id2. The PIB should not have a default identity.
        return pib.removeIdentityPromise(fixture.id2);
      })
      .then(function() {
        return pib.hasIdentityPromise(fixture.id2);
      })
      .then(function(hasIdentity) {
        assert.equal(false, hasIdentity);

        return pib.getDefaultIdentityPromise()
        .then(function() {
          assert.fail('', '', "Did not throw the expected exception");
        }, function(err) {
          if (err instanceof Pib.Error)
            return Promise.resolve();
          else
            assert.fail('', '', "Did not throw the expected exception");
        });
      })
      .then(function() {
        // Set id2 as the default. This should add id2 again.
        return pib.setDefaultIdentityPromise(fixture.id2);
      })
      .then(function() {
        return pib.getDefaultIdentityPromise();
      })
      .then(function(defaultIdentity) {
        assert.ok(fixture.id2.equals(defaultIdentity));

        // Get all the identities, which should have id1 and id2.
        return pib.getIdentitiesPromise();
      })
      .then(function(idNames) {
        assert.equal(2, idNames.length);
        assert.ok(fixture.id1.equals(idNames[0]) ||
                  fixture.id1.equals(idNames[1]));
        assert.ok(fixture.id2.equals(idNames[0]) ||
                  fixture.id2.equals(idNames[1]));

        ++iteration;
        if (iteration >= thisTest.pibImpls.length)
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

  it("ClearIdentities", function(done) {
    var thisTest = this;

    var test = function(iteration) {
      var fixture = thisTest.pibImpls[iteration];
      var pib = fixture.pib;

      return pib.setTpmLocatorPromise("tpmLocator")
      .then(function() {
        // Add id, key, and cert.
        return pib.addCertificatePromise(fixture.id1Key1Cert1);
      })
      .then(function() {
        return pib.hasIdentityPromise(fixture.id1);
      })
      .then(function(hasIdentity) {
        assert.ok(hasIdentity);
        return pib.hasKeyPromise(fixture.id1Key1Name);
      })
      .then(function(hasKey) {
        assert.ok(hasKey);
        return pib.hasCertificatePromise(fixture.id1Key1Cert1.getName());
      })
      .then(function(hasCertificate) {
        assert.ok(hasCertificate);

        // Clear identities.
        return pib.clearIdentitiesPromise();
      })
      .then(function() {
        return pib.getIdentitiesPromise();
      })
      .then(function(idNames) {
        assert.equal(0, idNames.length);
        return pib.getKeysOfIdentityPromise(fixture.id1);
      })
      .then(function(keys) {
        assert.equal(0, keys.length);
        return pib.getCertificatesOfKeyPromise(fixture.id1Key1Name);
      })
      .then(function(certificateNames) {
        assert.equal(0, certificateNames.length);
        return pib.getTpmLocatorPromise();
      })
      .then(function(tpmLocator) {
        assert.equal("tpmLocator", tpmLocator);

        ++iteration;
        if (iteration >= thisTest.pibImpls.length)
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

  it("KeyManagement", function(done) {
    var thisTest = this;

    var test = function(iteration) {
      var fixture = thisTest.pibImpls[iteration];
      var pib = fixture.pib;

      // There is no default setting. This should throw an Error.
      return pib.hasIdentityPromise(fixture.id2)
      .then(function(hasIdentity) {
        assert.equal(false, hasIdentity)

        return pib.getDefaultKeyOfIdentityPromise(fixture.id1)
        .then(function() {
          assert.fail('', '', "Did not throw the expected exception");
        }, function(err) {
          if (err instanceof Pib.Error)
            return Promise.resolve();
          else
            assert.fail('', '', "Did not throw the expected exception");
        });
      })
      .then(function() {
        // Check for id1Key1, which should not exist. Neither should id1.
        return pib.hasKeyPromise(fixture.id1Key1Name);
      })
      .then(function(hasKey) {
        assert.equal(false, hasKey);
        return pib.hasIdentityPromise(fixture.id1);
      })
      .then(function(hasIdentity) {
        assert.equal(false, hasIdentity);

        // Add id1Key1, which should be the default. id1 should be added implicitly.
        return pib.addKeyPromise
          (fixture.id1, fixture.id1Key1Name, fixture.id1Key1.buf());
      })
      .then(function() {
        return pib.hasKeyPromise(fixture.id1Key1Name);
      })
      .then(function(hasKey) {
        assert.equal(true, hasKey);
        return pib.hasIdentityPromise(fixture.id1);
      })
      .then(function(hasIdentity) {
        assert.equal(true, hasIdentity);
        return pib.getKeyBitsPromise(fixture.id1Key1Name);
      })
      .then(function(keyBits) {
        assert.ok(keyBits.equals(fixture.id1Key1));
        return pib.getDefaultKeyOfIdentityPromise(fixture.id1);
      })
      .then(function(defaultKey) {
        assert.ok(fixture.id1Key1Name.equals(defaultKey));

        // Add id1Key2, which should not be the default.
        return pib.addKeyPromise
          (fixture.id1, fixture.id1Key2Name, fixture.id1Key2.buf());
      })
      .then(function() {
        return pib.hasKeyPromise(fixture.id1Key2Name);
      })
      .then(function(hasKey) {
        assert.equal(true, hasKey);
        return pib.getDefaultKeyOfIdentityPromise(fixture.id1);
      })
      .then(function(defaultKey) {
        assert.ok(fixture.id1Key1Name.equals(defaultKey));

        // Explicitly Set id1Key2 as the default.
        return pib.setDefaultKeyOfIdentityPromise
          (fixture.id1, fixture.id1Key2Name);
      })
      .then(function() {
        return pib.getDefaultKeyOfIdentityPromise(fixture.id1);
      })
      .then(function(defaultKey) {
        assert.ok(fixture.id1Key2Name.equals(defaultKey));

        // Set a non-existing key as the default. This should throw an Error.
        return pib.setDefaultKeyOfIdentityPromise
          (fixture.id1, new Name("/non-existing"))
        .then(function() {
          assert.fail('', '', "Did not throw the expected exception");
        }, function(err) {
          if (err instanceof Pib.Error)
            return Promise.resolve();
          else
            assert.fail('', '', "Did not throw the expected exception");
        });
      })
      .then(function() {
        // Remove id1Key2. The PIB should not have a default key.
        return pib.removeKeyPromise(fixture.id1Key2Name);
      })
      .then(function() {
        return pib.hasKeyPromise(fixture.id1Key2Name);
      })
      .then(function(hasKey) {
        assert.equal(false, hasKey);

        return pib.getKeyBitsPromise(fixture.id1Key2Name)
        .then(function() {
          assert.fail('', '', "Did not throw the expected exception");
        }, function(err) {
          if (err instanceof Pib.Error)
            return Promise.resolve();
          else
            assert.fail('', '', "Did not throw the expected exception");
        });
      })
      .then(function() {
        return pib.getDefaultKeyOfIdentityPromise(fixture.id1)
        .then(function() {
          assert.fail('', '', "Did not throw the expected exception");
        }, function(err) {
          if (err instanceof Pib.Error)
            return Promise.resolve();
          else
            assert.fail('', '', "Did not throw the expected exception");
        });
      })
      .then(function() {
        // Add id1Key2 back, which should be the default.
        return pib.addKeyPromise
          (fixture.id1, fixture.id1Key2Name, fixture.id1Key2.buf());
      })
      .then(function() {
        return pib.getKeyBitsPromise(fixture.id1Key2Name);
      })
      .then(function() {
        return pib.getDefaultKeyOfIdentityPromise(fixture.id1);
      })
      .then(function(defaultKey) {
        assert.ok(fixture.id1Key2Name.equals(defaultKey));

        // Get all the keys, which should have id1Key1 and id1Key2.
        return pib.getKeysOfIdentityPromise(fixture.id1);
      })
      .then(function(keyNames) {
        assert.equal(2, keyNames.length);
        assert.ok(fixture.id1Key1Name.equals(keyNames[0]) ||
                  fixture.id1Key1Name.equals(keyNames[1]));
        assert.ok(fixture.id1Key2Name.equals(keyNames[0]) ||
                  fixture.id1Key2Name.equals(keyNames[1]));

        // Remove id1, which should remove all the keys.
        return pib.removeIdentityPromise(fixture.id1);
      })
      .then(function() {
        return pib.getKeysOfIdentityPromise(fixture.id1);
      })
      .then(function(keyNames) {
        assert.equal(0, keyNames.length);

        ++iteration;
        if (iteration >= thisTest.pibImpls.length)
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

  it("CertificateManagement", function(done) {
    var thisTest = this;

    var test = function(iteration) {
      var fixture = thisTest.pibImpls[iteration];
      var pib = fixture.pib;

      return Promise.resolve()
      .then(function() {
        // There is no default setting. This should throw an Error.
        return pib.getDefaultCertificateOfKeyPromise(fixture.id1Key1Name)
        .then(function() {
          assert.fail('', '', "Did not throw the expected exception");
        }, function(err) {
          if (err instanceof Pib.Error)
            return Promise.resolve();
          else
            assert.fail('', '', "Did not throw the expected exception");
        });
      })
      .then(function() {
        // Check for id1Key1Cert1, which should not exist. Neither should id1 or
        // id1Key1.
        return pib.hasCertificatePromise(fixture.id1Key1Cert1.getName());
      })
      .then(function(hasCertificate) {
        assert.equal(false, hasCertificate);
        return pib.hasIdentityPromise(fixture.id1);
      })
      .then(function(hasIdentity) {
        assert.equal(false, hasIdentity);
        return pib.hasKeyPromise(fixture.id1Key1Name);
      })
      .then(function(hasKey) {
        assert.equal(false, hasKey);

        // Add id1Key1Cert1, which should be the default.
        // id1 and id1Key1 should be added implicitly.
        return pib.addCertificatePromise(fixture.id1Key1Cert1);
      })
      .then(function() {
        return pib.hasCertificatePromise(fixture.id1Key1Cert1.getName());
      })
      .then(function(hasCertificate) {
        assert.equal(true, hasCertificate);
        return pib.hasIdentityPromise(fixture.id1);
      })
      .then(function(hasIdentity) {
        assert.equal(true, hasIdentity);
        return pib.hasKeyPromise(fixture.id1Key1Name);
      })
      .then(function(hasKey) {
        assert.equal(true, hasKey);
        return pib.getCertificatePromise(fixture.id1Key1Cert1.getName());
      })
      .then(function(certificate) {
        assert.ok(certificate.wireEncode().equals
                  (fixture.id1Key1Cert1.wireEncode()));
        return pib.getDefaultCertificateOfKeyPromise(fixture.id1Key1Name);
      })
      .then(function(certificate) {
        // Use the wire encoding to check equivalence.
        assert.ok(fixture.id1Key1Cert1.wireEncode().equals
          (certificate.wireEncode()));

        // Add id1Key1Cert2, which should not be the default.
        return pib.addCertificatePromise(fixture.id1Key1Cert2);
      })
      .then(function() {
        return pib.hasCertificatePromise(fixture.id1Key1Cert2.getName());
      })
      .then(function(hasCertificate) {
        assert.equal(true, hasCertificate);
        return pib.getDefaultCertificateOfKeyPromise(fixture.id1Key1Name);
      })
      .then(function(certificate) {
        assert.ok(fixture.id1Key1Cert1.wireEncode().equals
          (certificate.wireEncode()));

        // Explicitly set id1Key1Cert2 as the default.
        return pib.setDefaultCertificateOfKeyPromise
          (fixture.id1Key1Name, fixture.id1Key1Cert2.getName());
      })
      .then(function() {
        return pib.getDefaultCertificateOfKeyPromise(fixture.id1Key1Name);
      })
      .then(function(certificate) {
        assert.ok(fixture.id1Key1Cert2.wireEncode().equals
          (certificate.wireEncode()));

        // Set a non-existing certificate as the default. This should throw an Error.
        return pib.setDefaultCertificateOfKeyPromise
          (fixture.id1Key1Name, new Name("/non-existing"))
        .then(function() {
          assert.fail('', '', "Did not throw the expected exception");
        }, function(err) {
          if (err instanceof Pib.Error)
            return Promise.resolve();
          else
            assert.fail('', '', "Did not throw the expected exception");
        });
      })
      .then(function() {
        // Remove id1Key1Cert2, which should not have a default certificate.
        return pib.removeCertificatePromise(fixture.id1Key1Cert2.getName());
      })
      .then(function() {
        return pib.hasCertificatePromise(fixture.id1Key1Cert2.getName());
      })
      .then(function(hasCertificate) {
        assert.equal(false, hasCertificate);

        return pib.getCertificatePromise(fixture.id1Key1Cert2.getName())
        .then(function() {
          assert.fail('', '', "Did not throw the expected exception");
        }, function(err) {
          if (err instanceof Pib.Error)
            return Promise.resolve();
          else
            assert.fail('', '', "Did not throw the expected exception");
        });
      })
      .then(function() {
        return pib.getDefaultCertificateOfKeyPromise(fixture.id1Key1Name)
        .then(function() {
          assert.fail('', '', "Did not throw the expected exception");
        }, function(err) {
          if (err instanceof Pib.Error)
            return Promise.resolve();
          else
            assert.fail('', '', "Did not throw the expected exception");
        });
      })
      .then(function() {
        // Add id1Key1Cert2, which should be the default.
        return pib.addCertificatePromise(fixture.id1Key1Cert2);
      })
      .then(function() {
        // Make sure this succeeds.
        return pib.getCertificatePromise(fixture.id1Key1Cert1.getName());
      })
      .then(function() {
        return pib.getDefaultCertificateOfKeyPromise(fixture.id1Key1Name);
      })
      .then(function(certificate) {
        assert.ok(fixture.id1Key1Cert2.wireEncode().equals
          (certificate.wireEncode()));

        // Get all certificates, which should have id1Key1Cert1 and id1Key1Cert2.
        return pib.getCertificatesOfKeyPromise(fixture.id1Key1Name);
      })
      .then(function(certNames) {
        assert.equal(2, certNames.length);
        assert.ok(fixture.id1Key1Cert1.getName().equals(certNames[0]) ||
                  fixture.id1Key1Cert1.getName().equals(certNames[1]));
        assert.ok(fixture.id1Key1Cert2.getName().equals(certNames[0]) ||
                  fixture.id1Key1Cert2.getName().equals(certNames[1]));

        // Remove id1Key1, which should remove all the certificates.
        return pib.removeKeyPromise(fixture.id1Key1Name);
      })
      .then(function() {
        return pib.getCertificatesOfKeyPromise(fixture.id1Key1Name);
      })
      .then(function(certNames) {
        assert.equal(0, certNames.length);

        ++iteration;
        if (iteration >= thisTest.pibImpls.length)
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

  it("DefaultsManagement", function(done) {
    var thisTest = this;

    var test = function(iteration) {
      var fixture = thisTest.pibImpls[iteration];
      var pib = fixture.pib;

      return Promise.resolve()
      .then(function() {
        return pib.addIdentityPromise(fixture.id1);
      })
      .then(function() {
        return pib.getDefaultIdentityPromise();
      })
      .then(function(defaultIdentity) {
        assert.ok(fixture.id1.equals(defaultIdentity));

        return pib.addIdentityPromise(fixture.id2);
      })
      .then(function() {
        return pib.getDefaultIdentityPromise();
      })
      .then(function(defaultIdentity) {
        assert.ok(fixture.id1.equals(defaultIdentity));

        return pib.removeIdentityPromise(fixture.id1);
      })
      .then(function() {
        return pib.getDefaultIdentityPromise()
        .then(function() {
          assert.fail('', '', "Did not throw the expected exception");
        }, function(err) {
          if (err instanceof Pib.Error)
            return Promise.resolve();
          else
            assert.fail('', '', "Did not throw the expected exception");
        });
      })
      .then(function() {
        return pib.addKeyPromise
          (fixture.id2, fixture.id2Key1Name, fixture.id2Key1.buf());
      })
      .then(function() {
        return pib.getDefaultIdentityPromise();
      })
      .then(function(defaultIdentity) {
        assert.ok(fixture.id2.equals(defaultIdentity));
        return pib.getDefaultKeyOfIdentityPromise(fixture.id2);
      })
      .then(function(defaultKey) {
        assert.ok(fixture.id2Key1Name.equals(defaultKey));

        return pib.addKeyPromise
          (fixture.id2, fixture.id2Key2Name, fixture.id2Key2.buf());
      })
      .then(function() {
        return pib.getDefaultKeyOfIdentityPromise(fixture.id2);
      })
      .then(function(defaultKey) {
        assert.ok(fixture.id2Key1Name.equals(defaultKey));

        return pib.removeKeyPromise(fixture.id2Key1Name);
      })
      .then(function() {
        return pib.getDefaultKeyOfIdentityPromise(fixture.id2)
        .then(function() {
          assert.fail('', '', "Did not throw the expected exception");
        }, function(err) {
          if (err instanceof Pib.Error)
            return Promise.resolve();
          else
            assert.fail('', '', "Did not throw the expected exception");
        });
      })
      .then(function() {
        return pib.addCertificatePromise(fixture.id2Key2Cert1);
      })
      .then(function() {
        return pib.getDefaultKeyOfIdentityPromise(fixture.id2);
      })
      .then(function(defaultKey) {
        assert.ok(fixture.id2Key2Name.equals(defaultKey));
        return pib.getDefaultCertificateOfKeyPromise(fixture.id2Key2Name);
      })
      .then(function(certificate) {
        assert.ok(fixture.id2Key2Cert1.getName().equals(certificate.getName()));

        return pib.addCertificatePromise(fixture.id2Key2Cert2);
      })
      .then(function() {
        return pib.getDefaultCertificateOfKeyPromise(fixture.id2Key2Name);
      })
      .then(function(certificate) {
        assert.ok(fixture.id2Key2Cert1.getName().equals(certificate.getName()));

        return pib.removeCertificatePromise(fixture.id2Key2Cert2.getName());
      })
      .then(function() {
        return pib.getDefaultCertificateOfKeyPromise(fixture.id2Key2Name);
      })
      .then(function(certificate) {
        assert.ok(fixture.id2Key2Cert1.getName().equals(certificate.getName()));

        ++iteration;
        if (iteration >= thisTest.pibImpls.length)
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

  it("Overwrite", function(done) {
    var thisTest = this;
    var cert2;

    var test = function(iteration) {
      var fixture = thisTest.pibImpls[iteration];
      var pib = fixture.pib;

      // Check for id1Key1, which should not exist.
      return pib.removeIdentityPromise(fixture.id1)
      .then(function() {
        return pib.hasKeyPromise(fixture.id1Key1Name);
      })
      .then(function(hasKey) {
        assert.equal(false, hasKey);

        // Add id1Key1.
        return pib.addKeyPromise
          (fixture.id1, fixture.id1Key1Name, fixture.id1Key1.buf());
      })
      .then(function() {
        return pib.hasKeyPromise(fixture.id1Key1Name);
      })
      .then(function(hasKey) {
        assert.equal(true, hasKey);
        return pib.getKeyBitsPromise(fixture.id1Key1Name);
      })
      .then(function(keyBits) {
        assert.ok(keyBits.equals(fixture.id1Key1));

        // To check overwrite, add a key with the same name.
        return pib.addKeyPromise(fixture.id1, fixture.id1Key1Name, fixture.id1Key2.buf());
      })
      .then(function() {
        return pib.getKeyBitsPromise(fixture.id1Key1Name);
      })
      .then(function(keyBits2) {
        assert.ok(keyBits2.equals(fixture.id1Key2));

        // Check for id1Key1Cert1, which should not exist.
        return pib.removeIdentityPromise(fixture.id1);
      })
      .then(function() {
        return pib.hasCertificatePromise(fixture.id1Key1Cert1.getName());
      })
      .then(function(hasCertificate) {
        assert.equal(false, hasCertificate);

        // Add id1Key1Cert1.
        return pib.addKeyPromise
          (fixture.id1, fixture.id1Key1Name, fixture.id1Key1.buf());
      })
      .then(function() {
        return pib.addCertificatePromise(fixture.id1Key1Cert1);
      })
      .then(function() {
        return pib.hasCertificatePromise(fixture.id1Key1Cert1.getName());
      })
      .then(function(hasCertificate) {
        assert.equal(true, hasCertificate);
        return pib.getCertificatePromise(fixture.id1Key1Cert1.getName());
      })
      .then(function(cert) {
        assert.ok(cert.wireEncode().equals(fixture.id1Key1Cert1.wireEncode()));

        // Create a fake certificate with the same name.
        cert2 = fixture.id1Key2Cert1;
        cert2.setName(fixture.id1Key1Cert1.getName());
        cert2.setSignature(fixture.id1Key2Cert1.getSignature());
        return pib.addCertificatePromise(cert2);
      })
      .then(function() {
        return pib.getCertificatePromise(fixture.id1Key1Cert1.getName());
      })
      .then(function(cert3) {
        assert.ok(cert3.wireEncode().equals(cert2.wireEncode()));

        // Check that both the key and certificate are overwritten.
        return pib.getKeyBitsPromise(fixture.id1Key1Name);;
      })
      .then(function(keyBits3) {
        assert.ok(keyBits3.equals(fixture.id1Key2));

        ++iteration;
        if (iteration >= thisTest.pibImpls.length)
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
