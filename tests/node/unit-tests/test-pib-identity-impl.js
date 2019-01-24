/**
 * Copyright (C) 2017-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/pib/detail/identity-impl.t.cpp
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
var PibIdentityImpl = require('../../../js/security/pib/detail/pib-identity-impl.js').PibIdentityImpl;

describe ("TestPibIdentityImpl", function() {
  beforeEach(function(done) {
    this.fixture = new PibDataFixture();

    done();
  });

  it("Basic", function(done) {
    var fixture = this.fixture;
    var pibImpl = new PibMemory();
    var identity1;

    PibIdentityImpl.makePromise(fixture.id1, pibImpl, true)
    .then(function(pibIdentityImpl) {
      identity1 = pibIdentityImpl;

      assert.ok(fixture.id1.equals(identity1.getName()));
      return Promise.resolve();
    })
    // When done is called, Mocha displays errors from assert.ok.
    .then(done, done);
  });

  it("KeyOperation", function(done) {
    var fixture = this.fixture;
    var pibImpl = new PibMemory();
    var identity1;

    PibIdentityImpl.makePromise(fixture.id1, pibImpl, true)
    .then(function(pibIdentityImpl) {
      identity1 = pibIdentityImpl;

      // Check that this doesn't throw an error.
      return PibIdentityImpl.makePromise(fixture.id1, pibImpl, false);
    })
    .then(function() {
      // The identity should not have any key.
      assert.equal(0, identity1.keys_.size());

      // Getting non-existing key should throw Pib.Error.
      return identity1.getKeyPromise(fixture.id1Key1Name)
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
      // Getting the default key should throw Pib.Error.
      return identity1.getDefaultKeyPromise()
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
      // Setting a non-existing key as the default key should throw Pib.Error.
      return identity1.setDefaultKeyPromise(fixture.id1Key1Name)
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
      // Add a key.
      return identity1.addKeyPromise(fixture.id1Key1.buf(), fixture.id1Key1Name);
    })
    .then(function() {
      // Check that this doesn't throw an error.
      return identity1.getKeyPromise(fixture.id1Key1Name);
    })
    .then(function() {
      // A new key should become the default key when there is no default.
      return identity1.getDefaultKeyPromise();
    })
    .then(function(defaultKey0) {
      assert.ok(fixture.id1Key1Name.equals(defaultKey0.getName()));
      assert.ok(defaultKey0.getPublicKey().equals(fixture.id1Key1));

      // Remove a key.
      return identity1.removeKeyPromise(fixture.id1Key1Name);
    })
    .then(function() {
      return identity1.setDefaultKeyPromise(fixture.id1Key1Name)
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
      return identity1.getDefaultKeyPromise()
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
      // Set the default key directly.
      return identity1.setDefaultKeyPromise
        (fixture.id1Key1.buf(), fixture.id1Key1Name);
    })
    .then(function() {
      return identity1.getDefaultKeyPromise();
    })
    .then(function() {
      return identity1.getKeyPromise(fixture.id1Key1Name);
    })
    .then(function() {
      // Check for a default key.
      return identity1.getDefaultKeyPromise();
    })
    .then(function(defaultKey1) {
      assert.ok(fixture.id1Key1Name.equals(defaultKey1.getName()));
      assert.ok(defaultKey1.getPublicKey().equals(fixture.id1Key1));

      // Add another key.
      return identity1.addKeyPromise(fixture.id1Key2.buf(), fixture.id1Key2Name);
    })
    .then(function() {
      assert.equal(2, identity1.keys_.size());

      // Set the default key using a name.
      return identity1.setDefaultKeyPromise(fixture.id1Key2Name);
    })
    .then(function() {
      return identity1.getDefaultKeyPromise();
    })
    .then(function(defaultKey2) {
      assert.ok(fixture.id1Key2Name.equals(defaultKey2.getName()));
      assert.ok(defaultKey2.getPublicKey().equals(fixture.id1Key2));

      // Remove a key.
      return identity1.removeKeyPromise(fixture.id1Key1Name);
    })
    .then(function() {
      return identity1.getKeyPromise(fixture.id1Key1Name)
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
      assert.equal(1, identity1.keys_.size());

      // Seting the default key directly again should change the default.
      return identity1.setDefaultKeyPromise
        (fixture.id1Key1.buf(), fixture.id1Key1Name);
    })
    .then(function() {
      return identity1.getDefaultKeyPromise();
    })
    .then(function(defaultKey3) {
      assert.ok(fixture.id1Key1Name.equals(defaultKey3.getName()));
      assert.ok(defaultKey3.getPublicKey().equals(fixture.id1Key1));
      assert.equal(2, identity1.keys_.size());

      // Remove all keys.
      return identity1.removeKeyPromise(fixture.id1Key1Name);
    })
    .then(function() {
      return identity1.getKeyPromise(fixture.id1Key1Name)
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
      assert.equal(1, identity1.keys_.size());
      return identity1.removeKeyPromise(fixture.id1Key2Name);
    })
    .then(function() {
      return identity1.getKeyPromise(fixture.id1Key2Name)
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
      assert.equal(0, identity1.keys_.size());
      return identity1.getDefaultKeyPromise()
      .then(function() {
        assert.fail('', '', "Did not throw the expected exception");
      }, function(err) {
        if (err instanceof Pib.Error)
          return Promise.resolve();
        else
          assert.fail('', '', "Did not throw the expected exception");
      });
    })
    // When done is called, Mocha displays errors from assert.ok.
    .then(done, done);
  });

  it("Overwrite", function(done) {
    var fixture = this.fixture;
    var pibImpl = new PibMemory();
    var identity1;

    PibIdentityImpl.makePromise(fixture.id1, pibImpl, true)
    .then(function(pibIdentityImpl) {
      identity1 = pibIdentityImpl;

      return identity1.addKeyPromise(fixture.id1Key1.buf(), fixture.id1Key1Name);
    })
    .then(function() {
      return identity1.getKeyPromise(fixture.id1Key1Name);
    })
    .then(function(key) {
      assert.ok(key.getPublicKey().equals(fixture.id1Key1));

      // Overwriting the key should work.
      return identity1.addKeyPromise(fixture.id1Key2.buf(), fixture.id1Key1Name);
    })
    .then(function() {
      return identity1.getKeyPromise(fixture.id1Key1Name);
    })
    .then(function(key) {
      assert.ok(key.getPublicKey().equals(fixture.id1Key2));

      return Promise.resolve();
    })
    // When done is called, Mocha displays errors from assert.ok.
    .then(done, done);
  });

  it("Errors", function(done) {
    var fixture = this.fixture;
    var pibImpl = new PibMemory();
    var identity1;

    Promise.resolve()
    .then(function() {
      return PibIdentityImpl.makePromise(fixture.id1, pibImpl, false)
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
      return PibIdentityImpl.makePromise(fixture.id1, pibImpl, true);
    })
    .then(function(pibIdentityImpl) {
      identity1 = pibIdentityImpl;

      return identity1.addKeyPromise(fixture.id1Key1.buf(), fixture.id1Key1Name);
    })
    .then(function() {
      return identity1.addKeyPromise(fixture.id2Key1.buf(), fixture.id2Key1Name)
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
      return identity1.addKeyPromise(fixture.id1Key1.buf(), fixture.id1Key1Name);
    })
    .then(function() {
      return identity1.removeKeyPromise(fixture.id2Key1Name)
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
      return identity1.addKeyPromise(fixture.id1Key1.buf(), fixture.id1Key1Name);
    })
    .then(function() {
      return identity1.getKeyPromise(fixture.id2Key1Name)
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
      return identity1.addKeyPromise(fixture.id1Key1.buf(), fixture.id1Key1Name);
    })
    .then(function() {
      return identity1.setDefaultKeyPromise
        (fixture.id2Key1.buf(), fixture.id2Key1Name)
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
      return identity1.addKeyPromise(fixture.id1Key1.buf(), fixture.id1Key1Name);
    })
    .then(function() {
      return identity1.setDefaultKeyPromise(fixture.id2Key1Name)
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
