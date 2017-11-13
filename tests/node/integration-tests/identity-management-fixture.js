/**
 * Copyright (C) 2015-2017 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/identity-management-fixture.cpp
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

var KeyChain = require('../../..').KeyChain;
var Pib = require('../../..').Pib;
var CertificateV2 = require('../../..').CertificateV2;
var SigningInfo = require('../../..').SigningInfo;
var ValidityPeriod = require('../../..').ValidityPeriod;
var ContentType = require('../../..').ContentType;

var IdentityManagementFixture = function IdentityManagementFixture()
{
  this.keyChain_ = new KeyChain("pib-memory:", "tpm-memory:");
  this.identityNames_ = [];
  this.certificateFiles_ = [];
};

exports.IdentityManagementFixture = IdentityManagementFixture;

/**
 * Add an identity for the identityName.
 * @param {Name} identityName The name of the identity.
 * @param {KeyParams} params (optional) The key parameters if a key needs to
 * be generated for the identity. If omitted, use KeyChain.getDefaultKeyParams().
 * @return {PibIdentity} The created PibIdentity instance.
 */
IdentityManagementFixture.prototype.addIdentity = function(identityName, params)
{
  if (params == undefined)
    params = KeyChain.getDefaultKeyParams();

  var identity = this.keyChain_.createIdentityV2(identityName, params);
  if (this.identityNamesIndexOf_(identityName) < 0)
    this.identityNames_.push(identityName);
  return identity;
};

// This is needed because Array indexOf doesn't work for Name objects.
IdentityManagementFixture.prototype.identityNamesIndexOf_ = function(name)
{
  for (var i = 0; i < this.identityNames_.length; ++i) {
    if (this.identityNames_[i].equals(name))
      return i;
  }

  return -1;
};
