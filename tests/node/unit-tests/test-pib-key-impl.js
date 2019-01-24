/**
 * Copyright (C) 2017-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/pib/detail/key-impl.t.cpp
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
var Blob = require('../../..').Blob;
var CertificateV2 = require('../../..').CertificateV2;
var Pib = require('../../..').Pib;
var KeyType = require('../../..').KeyType;
var PibMemory = require('../../..').PibMemory;
var PibDataFixture = require('./pib-data-fixture.js').PibDataFixture;
var PibKeyImpl = require('../../../js/security/pib/detail/pib-key-impl.js').PibKeyImpl;

describe ("TestPibKeyImpl", function() {
  beforeEach(function(done) {
    this.fixture = new PibDataFixture();

    done();
  });

  it("Basic", function(done) {
    var fixture = this.fixture;
    var pibImpl = new PibMemory();
    var key11, key11FromBackend;

    PibKeyImpl.makePromise
      (fixture.id1Key1Name, fixture.id1Key1.buf(), pibImpl)
    .then(function(pibKeyImpl) {
      key11 = pibKeyImpl;

      assert.ok(fixture.id1Key1Name.equals(key11.getName()));
      assert.ok(fixture.id1.equals(key11.getIdentityName()));
      assert.equal(KeyType.RSA, key11.getKeyType());
      assert.ok(key11.getPublicKey().equals(fixture.id1Key1));

      return PibKeyImpl.makePromise(fixture.id1Key1Name, pibImpl);
    })
    .then(function(pibKeyImpl) {
      key11FromBackend = pibKeyImpl;
      assert.ok(fixture.id1Key1Name.equals(key11FromBackend.getName()));
      assert.ok(fixture.id1.equals(key11FromBackend.getIdentityName()));
      assert.equal(KeyType.RSA, key11FromBackend.getKeyType());
      assert.ok(key11FromBackend.getPublicKey().equals(fixture.id1Key1));

      return Promise.resolve();
    })
    // When done is called, Mocha displays errors from assert.ok.
    .then(done, done);
  });

  it("CertificateOperation", function(done) {
    var fixture = this.fixture;
    var pibImpl = new PibMemory();
    var key11;

    PibKeyImpl.makePromise
      (fixture.id1Key1Name, fixture.id1Key1.buf(), pibImpl)
    .then(function(pibKeyImpl) {
      key11 = pibKeyImpl;

      // The key should not have any certificates.
      assert.equal(0, key11.certificates_.size());

      // Check that this doesn't throw an error.
      return PibKeyImpl.makePromise(fixture.id1Key1Name, pibImpl);
    })
    .then(function() {
      // Getting a non-existing certificate should throw Pib.Error.
      return key11.getCertificatePromise(fixture.id1Key1Cert1.getName())
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
      // Getting a non-existing default certificate should throw Pib.Error.
      return key11.getDefaultCertificatePromise()
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
      // Setting a non-existing certificate as the default should throw Pib.Error.
      return key11.setDefaultCertificatePromise(fixture.id1Key1Cert1.getName())
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
      // Add a certificate.
      return key11.addCertificatePromise(fixture.id1Key1Cert1);
    })
    .then(function() {
      // The new certificate becomes the default when there was no default.
      return key11.getDefaultCertificatePromise();
    })
    .then(function(defaultCert0) {
      // Use the wire encoding to check equivalence.
      assert.ok(fixture.id1Key1Cert1.wireEncode().equals
        (defaultCert0.wireEncode()));

      // Remove the certificate.
      return key11.removeCertificatePromise(fixture.id1Key1Cert1.getName());
    })
    .then(function() {
      return key11.getCertificatePromise(fixture.id1Key1Cert1.getName())
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
      return key11.getDefaultCertificatePromise()
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
      // Set the default certificate directly.
      return key11.setDefaultCertificatePromise(fixture.id1Key1Cert1);
    })
    .then(function() {
      // This should not give an error.
      return key11.getDefaultCertificatePromise();
    })
    .then(function() {
      // This should not give an error.
      return key11.getCertificatePromise(fixture.id1Key1Cert1.getName());
    })
    .then(function() {
      // Check the default certificate.
      return key11.getDefaultCertificatePromise();
    })
    .then(function(defaultCert1) {
      assert.ok(fixture.id1Key1Cert1.getName().equals(defaultCert1.getName()));
      assert.ok(defaultCert1.wireEncode().equals
        (fixture.id1Key1Cert1.wireEncode()));


      // Add another certificate.
      return key11.addCertificatePromise(fixture.id1Key1Cert2);
    })
    .then(function() {
      assert.equal(2, key11.certificates_.size());

      // Set the default certificate using a name.
      return key11.setDefaultCertificatePromise(fixture.id1Key1Cert2.getName());
    })
    .then(function() {
      return key11.getDefaultCertificatePromise();
    })
    .then(function(defaultCert2) {
      assert.ok(fixture.id1Key1Cert2.getName().equals(defaultCert2.getName()));
      assert.ok(defaultCert2.wireEncode().equals
        (fixture.id1Key1Cert2.wireEncode()));

      // Remove a certificate.
      return key11.removeCertificatePromise(fixture.id1Key1Cert1.getName());
    })
    .then(function() {
      return key11.getCertificatePromise(fixture.id1Key1Cert1.getName())
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
      assert.equal(1, key11.certificates_.size());

      // Set the default certificate directly again, which should change the default.
      return key11.setDefaultCertificatePromise(fixture.id1Key1Cert1);
    })
    .then(function() {
      return key11.getDefaultCertificatePromise();
    })
    .then(function(defaultCert3) {
      assert.ok(fixture.id1Key1Cert1.getName().equals(defaultCert3.getName()));
      assert.ok(defaultCert3.wireEncode().equals
        (fixture.id1Key1Cert1.wireEncode()));
      assert.equal(2, key11.certificates_.size());

      // Remove all certificates.
      return key11.removeCertificatePromise(fixture.id1Key1Cert1.getName());
    })
    .then(function() {
      return key11.getCertificatePromise(fixture.id1Key1Cert1.getName())
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
      assert.equal(1, key11.certificates_.size());
      return key11.removeCertificatePromise(fixture.id1Key1Cert2.getName());
    })
    .then(function() {
      return key11.getCertificatePromise(fixture.id1Key1Cert2.getName())
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
      return key11.getDefaultCertificatePromise()
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
      assert.equal(0, key11.certificates_.size());

      return Promise.resolve();
    })
    // When done is called, Mocha displays errors from assert.ok.
    .then(done, done);
  });

  it("Overwrite", function(done) {
    var fixture = this.fixture;
    var pibImpl = new PibMemory();
    var key1, key2, otherCert;

    Promise.resolve()
    .then(function() {
      return PibKeyImpl.makePromise(fixture.id1Key1Name, pibImpl)
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
      return PibKeyImpl.makePromise
        (fixture.id1Key1Name, fixture.id1Key1.buf(), pibImpl);
    })
    .then(function() {
      return PibKeyImpl.makePromise(fixture.id1Key1Name, pibImpl);
    })
    .then(function(pibKeyImpl) {
      key1 = pibKeyImpl;

      // Overwriting the key should work.
      return PibKeyImpl.makePromise
        (fixture.id1Key1Name, fixture.id1Key2.buf(), pibImpl);
    })
    .then(function(pibKeyImpl) {
      key2 = pibKeyImpl;

      // key1 should have cached the original public key.
      assert.ok(!key1.getPublicKey().equals(key2.getPublicKey()));
      assert.ok(key2.getPublicKey().equals(fixture.id1Key2));

      return key1.addCertificatePromise(fixture.id1Key1Cert1);
    })
    .then(function() {
      // Use the wire encoding to check equivalence.
      return key1.getCertificatePromise(fixture.id1Key1Cert1.getName());
    })
    .then(function(certificate) {
      assert.ok
        (certificate.wireEncode().equals(fixture.id1Key1Cert1.wireEncode()));

      otherCert = new CertificateV2(fixture.id1Key1Cert1);
      otherCert.getSignature().getValidityPeriod().setPeriod
        (new Date().getTime(), new Date().getTime() + 1000);
      // Don't bother resigning so we don't have to load a private key.

      assert.ok(fixture.id1Key1Cert1.getName().equals(otherCert.getName()));
      assert.ok(otherCert.getContent().equals
        (fixture.id1Key1Cert1.getContent()));
      assert.ok(!otherCert.wireEncode().equals
        (fixture.id1Key1Cert1.wireEncode()));

      return key1.addCertificatePromise(otherCert);
    })
    .then(function() {
      return key1.getCertificatePromise(fixture.id1Key1Cert1.getName());
    })
    .then(function(certificate) {
      assert.ok(certificate.wireEncode().equals(otherCert.wireEncode()));

      return Promise.resolve();
    })
    // When done is called, Mocha displays errors from assert.ok.
    .then(done, done);
  });

  it("Errors", function(done) {
    var fixture = this.fixture;
    var pibImpl = new PibMemory();
    var key11;

    Promise.resolve()
    .then(function() {
      return PibKeyImpl.makePromise(fixture.id1Key1Name, pibImpl)
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
      return PibKeyImpl.makePromise
        (fixture.id1Key1Name, fixture.id1Key1.buf(), pibImpl);
    })
    .then(function(pibKeyImpl) {
      key11 = pibKeyImpl;

      return PibKeyImpl.makePromise(new Name("/wrong"), pibImpl)
      .then(function() {
        assert.fail('', '', "Did not throw the expected exception");
      }, function(err) {
        if (err instanceof Error)
          return Promise.resolve();
        else
          assert.fail('', '', "Did not throw the expected exception");
      });
    })
    .then(function() {
      var wrongKey = new Blob("");
      return PibKeyImpl.makePromise(fixture.id1Key2Name, wrongKey.buf(), pibImpl)
      .then(function() {
        assert.fail('', '', "Did not throw the expected exception");
      }, function(err) {
        if (err instanceof Error)
          return Promise.resolve();
        else
          assert.fail('', '', "Did not throw the expected exception");
      });
    })
    .then(function() {
      return key11.addCertificatePromise(fixture.id1Key1Cert1);
    })
    .then(function() {
      return key11.addCertificatePromise(fixture.id1Key2Cert1)
      .then(function() {
        assert.fail('', '', "Did not throw the expected exception");
      }, function(err) {
        if (err instanceof Error)
          return Promise.resolve();
        else
          assert.fail('', '', "Did not throw the expected exception");
      });
    })
    .then(function() {
      return key11.removeCertificatePromise(fixture.id1Key2Cert1.getName())
      .then(function() {
        assert.fail('', '', "Did not throw the expected exception");
      }, function(err) {
        if (err instanceof Error)
          return Promise.resolve();
        else
          assert.fail('', '', "Did not throw the expected exception");
      });
    })
    .then(function() {
      return key11.getCertificatePromise(fixture.id1Key2Cert1.getName())
      .then(function() {
        assert.fail('', '', "Did not throw the expected exception");
      }, function(err) {
        if (err instanceof Error)
          return Promise.resolve();
        else
          assert.fail('', '', "Did not throw the expected exception");
      });
    })
    .then(function() {
      return key11.setDefaultCertificatePromise(fixture.id1Key2Cert1)
      .then(function() {
        assert.fail('', '', "Did not throw the expected exception");
      }, function(err) {
        if (err instanceof Error)
          return Promise.resolve();
        else
          assert.fail('', '', "Did not throw the expected exception");
      });
    })
    .then(function() {
      return key11.setDefaultCertificatePromise(fixture.id1Key2Cert1.getName())
      .then(function() {
        assert.fail('', '', "Did not throw the expected exception");
      }, function(err) {
        if (err instanceof Error)
          return Promise.resolve();
        else
          assert.fail('', '', "Did not throw the expected exception");
      });
    })
    // When done is called, Mocha displays errors from assert.ok.
    .then(done, done);
  });
});
