/**
 * Copyright (C) 2015-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/validator-null.t.cpp
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
var Data = require('../../..').Data;
var Interest = require('../../..').Interest;
var SigningInfo = require('../../..').SigningInfo;
var ValidatorNull = require('../../..').ValidatorNull;
var IdentityManagementFixture = require('./identity-management-fixture.js').IdentityManagementFixture;

describe ("TestValidatorNull", function() {
  beforeEach(function() {
    this.fixture_ = new IdentityManagementFixture();
  });

  it("ValidateData", function() {
    var identity = this.fixture_.addIdentity(new Name("/TestValidator/Null"));
    var data = new Data(new Name("/Some/Other/Data/Name"));
    this.fixture_.keyChain_.sign(data, new SigningInfo(identity));

    var validator = new ValidatorNull();
    validator.validate
      (data, function(data) {
        // Should succeed.
      }, function(data, error) {
        assert.fail("Validation should not have failed");
      });
  });

  it("ValidateInterest", function() {
    var identity = this.fixture_.addIdentity(new Name("/TestValidator/Null"));
    var interest = new Interest(new Name("/Some/Other/Interest/Name"));
    this.fixture_.keyChain_.sign(interest, new SigningInfo(identity));

    var validator = new ValidatorNull();
    validator.validate
      (interest, function(interest) {
        // Should succeed.
      }, function(interest, error) {
        assert.fail("Validation should not have failed");
      });
  });
});
