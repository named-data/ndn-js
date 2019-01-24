/**
 * Copyright (C) 2017-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/pib/key-container.t.cpp
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
var PibKeyContainer = require('../../../js/security/pib/pib-key-container.js').PibKeyContainer;

describe ("TestPibKeyContainer", function() {
  beforeEach(function(done) {
    this.fixture = new PibDataFixture();

    done();
  });

  it("Basic", function(done) {
    var fixture = this.fixture;
    var pibImpl = new PibMemory();
    var container, container2;

    // Start with an empty container.
    PibKeyContainer.makePromise(fixture.id1, pibImpl)
    .then(function(localContainer) {
      container = localContainer;
      assert.equal(0, container.size());
      assert.equal(0, Object.keys(container.keys_).length);

      // Add the first key.
      return container.addPromise(fixture.id1Key1.buf(), fixture.id1Key1Name);
    })
    .then(function(key11) {
      assert.ok(fixture.id1Key1Name.equals(key11.getName()));
      assert.ok(key11.getPublicKey().equals(fixture.id1Key1));
      assert.equal(1, container.size());
      assert.equal(1, Object.keys(container.keys_).length);
      assert.ok(container.keys_[fixture.id1Key1Name.toUri()] !== undefined);

      // Add the same key again.
      return container.addPromise(fixture.id1Key1.buf(), fixture.id1Key1Name);
    })
    .then(function(key12) {
      assert.ok(fixture.id1Key1Name.equals(key12.getName()));
      assert.ok(key12.getPublicKey().equals(fixture.id1Key1));
      assert.equal(1, container.size());
      assert.equal(1, Object.keys(container.keys_).length);
      assert.ok(container.keys_[fixture.id1Key1Name.toUri()] !== undefined);

      // Add the second key.
      return container.addPromise(fixture.id1Key2.buf(), fixture.id1Key2Name);
    })
    .then(function(key21) {
      assert.ok(fixture.id1Key2Name.equals(key21.getName()));
      assert.ok(key21.getPublicKey().equals(fixture.id1Key2));
      assert.equal(2, container.size());
      assert.equal(2, Object.keys(container.keys_).length);
      assert.ok(container.keys_[fixture.id1Key1Name.toUri()] !== undefined);
      assert.ok(container.keys_[fixture.id1Key2Name.toUri()] !== undefined);

      // Get keys.
      // Check that this doesn't throw an error.
      return container.getPromise(fixture.id1Key1Name);
    })
    .then(function() {
      // Check that this doesn't throw an error.
      return container.getPromise(fixture.id1Key2Name);
    })
    .then(function() {
      var id1Key3Name = PibKey.constructKeyName
        (fixture.id1, Name.Component("non-existing-id"));
      return container.getPromise(id1Key3Name)
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
      // Get and check keys.
      return container.getPromise(fixture.id1Key1Name);
    })
    .then(function(key1) {
      assert.ok(fixture.id1Key1Name.equals(key1.getName()));
      assert.ok(key1.getPublicKey().equals(fixture.id1Key1));
      return container.getPromise(fixture.id1Key2Name);
    })
    .then(function(key2) {
      assert.ok(fixture.id1Key2Name.equals(key2.getName()));
      assert.ok(key2.getPublicKey().equals(fixture.id1Key2));

      // Create another container using the same PibImpl. The cache should be empty.
      return PibKeyContainer.makePromise(fixture.id1, pibImpl);
    })
    .then(function(localContainer) {
      container2 = localContainer;
      assert.equal(2, container2.size());
      assert.equal(0, Object.keys(container2.keys_).length)

      // Get a key. The cache should be filled.
      return container2.getPromise(fixture.id1Key1Name);
    })
    .then(function() {
      assert.equal(2, container2.size());
      assert.equal(1, Object.keys(container2.keys_).length);

      return container2.getPromise(fixture.id1Key2Name);
    })
    .then(function() {
      assert.equal(2, container2.size());
      assert.equal(2, Object.keys(container2.keys_).length);

      // Remove a key.
      return container2.removePromise(fixture.id1Key1Name);
    })
    .then(function() {
      assert.equal(1, container2.size());
      assert.equal(1, Object.keys(container2.keys_).length);
      assert.ok(container2.keys_[fixture.id1Key1Name.toUri()] === undefined);
      assert.ok(container2.keys_[fixture.id1Key2Name.toUri()] !== undefined);

      // Remove another key.
      return container2.removePromise(fixture.id1Key2Name);
    })
    .then(function() {
      assert.equal(0, container2.size());
      assert.equal(0, Object.keys(container2.keys_).length);
      assert.ok(container2.keys_[fixture.id1Key2Name.toUri()] === undefined);

      return Promise.resolve();
    })
    // When done is called, Mocha displays errors from assert.ok.
    .then(done, done);
  });

  it("Errors", function(done) {
    var fixture = this.fixture;
    var pibImpl = new PibMemory();
    var container;

    PibKeyContainer.makePromise(fixture.id1, pibImpl)
    .then(function(localContainer) {
      container = localContainer;

      return container.addPromise(fixture.id2Key1.buf(), fixture.id2Key1Name)
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
      return container.removePromise(fixture.id2Key1Name)
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
      return container.getPromise(fixture.id2Key1Name)
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
