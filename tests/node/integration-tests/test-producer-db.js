/**
 * Copyright (C) 2015-2016 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt unit tests
 * https://github.com/named-data/ndn-group-encrypt/blob/master/tests/unit-tests/producer-db.t.cpp
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
var Blob = require('../../..').Blob;
var AesKeyParams = require('../../..').AesKeyParams;
var AesAlgorithm = require('../../..').AesAlgorithm;
var Sqlite3ProducerDb = require('../../..').Sqlite3ProducerDb;
var Common = require('../unit-tests/unit-tests-common.js').UnitTestsCommon;

var databaseFilePath;

describe ("TestProducerDb", function() {
  beforeEach(function(done) {
    databaseFilePath = "policy_config/test.db";
    try {
      fs.unlinkSync(databaseFilePath);
    }
    catch (e) {}

    done();
  });

  afterEach(function(done) {
    try {
      fs.unlinkSync(databaseFilePath);
    }
    catch (e) {}

    done();
  });

  it("DatabaseFunctions", function(done) {
    // Test construction.
    var database = new Sqlite3ProducerDb(databaseFilePath);

    // Create a member.
    var params = new AesKeyParams(128);
    var keyBlob1 = AesAlgorithm.generateKey(params).getKeyBits();
    var keyBlob2 = AesAlgorithm.generateKey(params).getKeyBits();

    var point1 = Common.fromIsoString("20150101T100000");
    var point2 = Common.fromIsoString("20150102T100000");
    var point3 = Common.fromIsoString("20150103T100000");
    var point4 = Common.fromIsoString("20150104T100000");

    // Add keys into the database.
    database.addContentKeyPromise(point1, keyBlob1)
    .then(function() {
      return database.addContentKeyPromise(point2, keyBlob1);
    })
    .then(function() {
      return database.addContentKeyPromise(point3, keyBlob2);
    })
    .then(function() {
      // Throw an exception when adding a key to an existing time slot.
      return database.addContentKeyPromise(point1, keyBlob1)
      .then(function() {
        assert.fail('', '', "addContentKey did not throw an exception");
      }, function(err) {
        // Got the expected error.
        return Promise.resolve();
      });
    })
    .then(function() {
      // Check has functions.
      return database.hasContentKeyPromise(point1);
    })
    .then(function(exists) {
      assert.equal(exists, true);
      return database.hasContentKeyPromise(point2);
    })
    .then(function(exists) {
      assert.equal(exists, true);
      return database.hasContentKeyPromise(point3);
    })
    .then(function(exists) {
      assert.equal(exists, true);
      return database.hasContentKeyPromise(point4);
    })
    .then(function(exists) {
      assert.equal(exists, false);

      // Get content keys.
      return database.getContentKeyPromise(point1);
    })
    .then(function(keyResult) {
      assert.ok(keyResult.equals(keyBlob1));

      return database.getContentKeyPromise(point3);
    })
    .then(function(keyResult) {
      assert.ok(keyResult.equals(keyBlob2));

      // Throw exception when there is no such time slot in the database.
      return database.getContentKeyPromise(point4)
      .then(function() {
        assert.fail('', '', "getContentKey did not throw an exception");
      }, function(err) {
        // Got the expected error.
        return Promise.resolve();
      });
    })
    .then(function() {
      // Delete content keys.
      return database.hasContentKeyPromise(point1);
    })
    .then(function(exists) {
      assert.equal(exists, true);
      return database.deleteContentKeyPromise(point1);
    })
    .then(function() {
      return database.hasContentKeyPromise(point1);
    })
    .then(function(exists) {
      assert.equal(exists, false);

      // Delete at a non-existing time slot.
      return database.deleteContentKeyPromise(point4)
      .then(function() {
        // No error, as expected.
        return Promise.resolve();
      }, function(err) {
        assert.fail('', '', "deleteContentKey threw an exception: " + err);
      });
    })
    // When done is called, Mocha displays errors from assert.ok.
    .then(done, done);
  });
});
