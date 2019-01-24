/**
 * Copyright (C) 2017-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/pib/identity-container.t.cpp
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
var PibKey = require('../../../js/security/pib/pib-key.js').PibKey;
var PibDataFixture = require('./pib-data-fixture.js').PibDataFixture;
var PibIdentityContainer = require('../../../js/security/pib/pib-identity-container.js').PibIdentityContainer;

describe ("TestPibIdentityContainer", function() {
  beforeEach(function(done) {
    this.fixture = new PibDataFixture();

    done();
  });

  it("Basic", function(done) {
    var fixture = this.fixture;
    var pibImpl = new PibMemory();
    var container, container2;

    // Start with an empty container.
    PibIdentityContainer.makePromise(pibImpl)
    .then(function(localContainer) {
      container = localContainer;
      assert.equal(0, container.size());
      assert.equal(0, Object.keys(container.identities_).length);

      // Add the first identity.
      return container.addPromise(fixture.id1);
    })
    .then(function(identity11) {
      assert.ok(fixture.id1.equals(identity11.getName()));
      assert.equal(1, container.size());
      assert.equal(1, Object.keys(container.identities_).length);
      assert.ok(container.identities_[fixture.id1.toUri()] !== undefined);

      // Add the same identity again.
      return container.addPromise(fixture.id1);
    })
    .then(function(identity12) {
      assert.ok(fixture.id1.equals(identity12.getName()));
      assert.equal(1, container.size());
      assert.equal(1, Object.keys(container.identities_).length);
      assert.ok(container.identities_[fixture.id1.toUri()] !== undefined);

      // Add the second identity.
      return container.addPromise(fixture.id2);
    })
    .then(function(identity21) {
      assert.ok(fixture.id2.equals(identity21.getName()));
      assert.equal(2, container.size());
      assert.equal(2, Object.keys(container.identities_).length);
      assert.ok(container.identities_[fixture.id1.toUri()] !== undefined);
      assert.ok(container.identities_[fixture.id2.toUri()] !== undefined);

      // Get identities.
      // Check that this doesn't throw an error.
      return container.getPromise(fixture.id1);
    })
    .then(function() {
      // Check that this doesn't throw an error.
      return container.getPromise(fixture.id2);
    })
    .then(function() {
      return container.getPromise(new Name("/non-existing"))
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
      // Check the identity.
      return container.getPromise(fixture.id1);
    })
    .then(function(identity1) {
      assert.ok(fixture.id1.equals(identity1.getName()));
      return container.getPromise(fixture.id2);
    })
    .then(function(identity2) {
      assert.ok(fixture.id2.equals(identity2.getName()));

      // Create another container from the same PibImpl. The cache should be empty.
      return PibIdentityContainer.makePromise(pibImpl);
    })
    .then(function(localContainer) {
      container2 = localContainer;
      assert.equal(2, container2.size());
      assert.equal(0, Object.keys(container2.identities_).length);

      // Get keys. The cache should be filled.
      return container2.getPromise(fixture.id1);
    })
    .then(function() {
      assert.equal(2, container2.size());
      assert.equal(1, Object.keys(container2.identities_).length);

      return container2.getPromise(fixture.id2);
    })
    .then(function() {
      assert.equal(2, container2.size());
      assert.equal(2, Object.keys(container2.identities_).length);

      // Remove a key.
      return container2.removePromise(fixture.id1);
    })
    .then(function() {
      assert.equal(1, container2.size());
      assert.equal(1, Object.keys(container2.identities_).length);
      assert.ok(container2.identities_[fixture.id1.toUri()] === undefined);
      assert.ok(container2.identities_[fixture.id2.toUri()] !== undefined);

      // Remove another key.
      return container2.removePromise(fixture.id2);
    })
    .then(function() {
      assert.equal(0, container2.size());
      assert.equal(0, Object.keys(container2.identities_).length);
      assert.ok(container2.identities_[fixture.id2.toUri()] === undefined);

      return Promise.resolve();
    })
    // When done is called, Mocha displays errors from assert.ok.
    .then(done, done);
  });
});
