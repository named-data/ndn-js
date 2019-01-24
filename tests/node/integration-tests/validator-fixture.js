/**
 * Copyright (C) 2018-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/validator-fixture.cpp
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

var Interest = require('../../..').Interest;
var CertificateCacheV2 = require('../../..').CertificateCacheV2;
var Validator = require('../../..').Validator;
var CertificateFetcherFromNetwork = require('../../..').CertificateFetcherFromNetwork;
var IdentityManagementFixture = require('./identity-management-fixture.js').IdentityManagementFixture;

/**
 * @param {ValidationPolicy} policy
 * @constructor
 */
var ValidatorFixture = function ValidatorFixture(policy)
{
  // Call the base constructor.
  IdentityManagementFixture.call(this);

  this.face_ = new TestFace();
  // Set maxLifetime to 100 days.
  this.cache_ = new CertificateCacheV2(100 * 24 * 3600 * 1000.0);

  this.validator_ = new Validator(policy, new CertificateFetcherFromNetwork
    (this.face_));
  this.policy_ = policy;

  var thisFixture = this;
  this.face_.processInterest_ = function(interest, onData, onTimeout, onNetworkNack) {
    var certificate = thisFixture.cache_.find(interest);
    if (certificate != null)
      onData(interest, certificate);
    else
      onTimeout(interest);
  };
};

ValidatorFixture.prototype = new IdentityManagementFixture();
ValidatorFixture.prototype.name = "ValidatorFixture";

exports.ValidatorFixture = ValidatorFixture;

/**
 * TestFace extends Face to instantly simulate a call to expressInterest.
 * See expressInterest for details.
 */
var TestFace = function TestFace()
{
  this.processInterest_ = null;
  this.sentInterests_ = []; // of Interest
};

/**
 * If processInterest_ is not null, call
 * processInterest_(interest, onData, onTimeout, onNetworkNack)
 * which must call one of the callbacks to simulate the response. Otherwise,
 * just call onTimeout(interest) to simulate a timeout. This adds a copy of
 * the interest to sentInterests_ .
 */
TestFace.prototype.expressInterest = function
  (interest, onData, onTimeout, onNetworkNack)
{
  // Makes a copy of the interest.
  this.sentInterests_.push(new Interest(interest));

  if (this.processInterest_ != null)
    this.processInterest_(interest, onData, onTimeout, onNetworkNack);
  else
    onTimeout(interest);

  return 0;
};
