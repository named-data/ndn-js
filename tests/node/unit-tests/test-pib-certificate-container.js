/**
 * Copyright (C) 2017-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/pib/certificate-container.t.cpp
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
var PibMemory = require('../../..').PibMemory;
var PibDataFixture = require('./pib-data-fixture.js').PibDataFixture;
var PibCertificateContainer = require('../../../js/security/pib/pib-certificate-container.js').PibCertificateContainer;

describe ("TestPibCertificateContainer", function() {
  beforeEach(function(done) {
    this.fixture = new PibDataFixture();

    done();
  });

  it("Basic", function(done) {
    var fixture = this.fixture;
    var pibImpl = new PibMemory();
    var container, container2;

    // Start with an empty container.
    PibCertificateContainer.makePromise(fixture.id1Key1Name, pibImpl)
    .then(function(localContainer) {
      container = localContainer;
      assert.equal(0, container.size());
      assert.equal(0, Object.keys(container.certificates_).length);

      // Add a certificate.
      return container.addPromise(fixture.id1Key1Cert1);
    })
    .then(function() {
      assert.equal(1, container.size());
      assert.equal(1, Object.keys(container.certificates_).length);
      assert.ok
        (container.certificates_[fixture.id1Key1Cert1.getName().toUri()] !== undefined);

      // Add the same certificate again.
      return container.addPromise(fixture.id1Key1Cert1);
    })
    .then(function() {
      assert.equal(1, container.size());
      assert.equal(1, Object.keys(container.certificates_).length);
      assert.ok
        (container.certificates_[fixture.id1Key1Cert1.getName().toUri()] !== undefined);

      // Add another certificate.
      return container.addPromise(fixture.id1Key1Cert2);
    })
    .then(function() {
      assert.equal(2, container.size());
      assert.equal(2, Object.keys(container.certificates_).length);
      assert.ok
        (container.certificates_[fixture.id1Key1Cert1.getName().toUri()] !== undefined);
      assert.ok
        (container.certificates_[fixture.id1Key1Cert2.getName().toUri()] !== undefined);

      // Check that these don't throw an exception.
      return container.getPromise(fixture.id1Key1Cert1.getName());
    })
    .then(function() {
      return container.getPromise(fixture.id1Key1Cert2.getName());
    })
    .then(function() {
      var id1Key1Cert3Name = new Name(fixture.id1Key1Name);
      id1Key1Cert3Name.append("issuer").appendVersion(3);
      return container.getPromise(id1Key1Cert3Name)
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
      // Check the certificates.
      return container.getPromise(fixture.id1Key1Cert1.getName());
    })
    .then(function(cert1) {
      // Use the wire encoding to check equivalence.
      assert.ok(cert1.wireEncode().equals(fixture.id1Key1Cert1.wireEncode()));
      return container.getPromise(fixture.id1Key1Cert2.getName());
    })
    .then(function(cert2) {
      assert.ok(cert2.wireEncode().equals(fixture.id1Key1Cert2.wireEncode()));

      // Create another container with the same PibImpl. The cache should be empty.
      return PibCertificateContainer.makePromise(fixture.id1Key1Name, pibImpl);
    })
    .then(function(localContainer) {
      container2 = localContainer;
      assert.equal(2, container2.size());
      assert.equal(0, Object.keys(container2.certificates_).length);

      // Get a certificate. The cache should be filled.
      return container2.getPromise(fixture.id1Key1Cert1.getName());
    })
    .then(function() {
      assert.equal(2, container2.size());
      assert.equal(1, Object.keys(container2.certificates_).length);

      return container2.getPromise(fixture.id1Key1Cert2.getName());
    })
    .then(function() {
      assert.equal(2, container2.size());
      assert.equal(2, Object.keys(container2.certificates_).length);

      // Remove a certificate.
      return container2.removePromise(fixture.id1Key1Cert1.getName());
    })
    .then(function() {
      assert.equal(1, container2.size());
      assert.equal(1, Object.keys(container2.certificates_).length);
      assert.ok
        (container2.certificates_[fixture.id1Key1Cert1.getName().toUri()] ===
         undefined);
      assert.ok
        (container2.certificates_[fixture.id1Key1Cert2.getName().toUri()] !==
         undefined);

      // Remove another certificate.
      return container2.removePromise(fixture.id1Key1Cert2.getName());
    })
    .then(function() {
      assert.equal(0, container2.size());
      assert.equal(0, Object.keys(container2.certificates_).length);
      assert.ok
        (container2.certificates_[fixture.id1Key1Cert2.getName().toUri()] ===
         undefined);

      return Promise.resolve();
    })
    // When done is called, Mocha displays errors from assert.ok.
    .then(done, done);
  });

  it("Errors", function(done) {
    var fixture = this.fixture;
    var pibImpl = new PibMemory();
    var container;

    PibCertificateContainer.makePromise(fixture.id1Key1Name, pibImpl)
    .then(function(localContainer) {
      container = localContainer;

      return container.addPromise(fixture.id1Key2Cert1)
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
      return container.removePromise(fixture.id1Key2Cert1.getName())
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
      return container.getPromise(fixture.id1Key2Cert1.getName())
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
