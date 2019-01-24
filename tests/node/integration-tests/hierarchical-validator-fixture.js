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

var Name = require('../../..').Name;
var CertificateV2 = require('../../..').CertificateV2;
var ValidationPolicyAcceptAll = require('../../..').ValidationPolicyAcceptAll;
var ValidatorFixture = require('./validator-fixture.js').ValidatorFixture;

/**
 * @param {ValidationPolicy} policy
 * @constructor
 */
var HierarchicalValidatorFixture = function HierarchicalValidatorFixture(policy)
{
  // Call the base constructor.
  ValidatorFixture.call(this, policy);

  this.identity_ = this.addIdentity(new Name("/Security/V2/ValidatorFixture"));
  this.subIdentity_ = this.addSubCertificate
    (new Name("/Security/V2/ValidatorFixture/Sub1"), this.identity_);
  this.subSelfSignedIdentity_ = this.addIdentity
    (new Name("/Security/V2/ValidatorFixture/Sub1/Sub2"));
  this.otherIdentity_ = this.addIdentity(new Name("/Security/V2/OtherIdentity"));

  this.validator_.loadAnchor
    ("", new CertificateV2(this.identity_.getDefaultKey().getDefaultCertificate()));

  this.cache_.insert(this.identity_.getDefaultKey().getDefaultCertificate());
  this.cache_.insert(this.subIdentity_.getDefaultKey().getDefaultCertificate());
  this.cache_.insert(this.subSelfSignedIdentity_.getDefaultKey().getDefaultCertificate());
  this.cache_.insert(this.otherIdentity_.getDefaultKey().getDefaultCertificate());
};

HierarchicalValidatorFixture.prototype = new ValidatorFixture
  (new ValidationPolicyAcceptAll());
HierarchicalValidatorFixture.prototype.name = "HierarchicalValidatorFixture";

exports.HierarchicalValidatorFixture = HierarchicalValidatorFixture;
