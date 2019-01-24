/**
 * Copyright (C) 2015-2019 Regents of the University of California.
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

var fs = require("fs");
var Name = require('../../..').Name;
var KeyChain = require('../../..').KeyChain;
var CertificateV2 = require('../../..').CertificateV2;
var SigningInfo = require('../../..').SigningInfo;
var ValidityPeriod = require('../../..').ValidityPeriod;
var ContentType = require('../../..').ContentType;

var IdentityManagementFixture = function IdentityManagementFixture()
{
  this.keyChain_ = new KeyChain("pib-memory:", "tpm-memory:");
  // The object keys are the set of identity name URIs, and each value is true.
  this.identityNameUris_ = {};
  // The object keys are the set of file paths, and each value is true.
  this.certificateFiles_ = {};
};

exports.IdentityManagementFixture = IdentityManagementFixture;

/**
 * Save the certificate Data packet to the file.
 * @param {Data} data The certificate Data packet.
 * @param {String} filePath The file path to save to.
 * @return {boolean} True for success, false for failure.
 */
IdentityManagementFixture.prototype.saveCertificateToFile = function
  (data, filePath)
{
  this.certificateFiles_[filePath] = true;

  try {
    var encoding = data.wireEncode();
    var encodedCertificate = encoding.buf().toString('base64');

    fs.writeFileSync(filePath, encodedCertificate);

    return true;
  }
  catch (ex) {
    return false;
  }
};

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
  this.identityNameUris_[identityName.toUri()] = true;
  return identity;
};

/**
 *  Save the identity's certificate to a file.
 *  @param {PibIdentity} identity The PibIdentity.
 *  @param {String} filePath The file path, which should be writable.
 *  @return {boolean} True if successful.
 */
IdentityManagementFixture.prototype.saveCertificate = function(identity, filePath)
{
  try {
    var certificate = identity.getDefaultKey().getDefaultCertificate();
    return this.saveCertificateToFile(certificate, filePath);
  }
  catch (ex) {
    return false;
  }
};

/**
 * Issue a certificate for subIdentityName signed by issuer. If the identity
 * does not exist, it is created. A new key is generated as the default key
 * for the identity. A default certificate for the key is signed by the
 * issuer using its default certificate.
 * @param {Name} subIdentityName The name to issue the certificate for.
 * @param {PibIdentity} issuer The identity of the signer.
 * @param {KeyParams} params (optional) The key parameters if a key needs to be
 * generated for the identity. If omitted, use KeyChain.getDefaultKeyParams().
 * @return {PibIdentity} The sub identity.
 */
IdentityManagementFixture.prototype.addSubCertificate = function
  (subIdentityName, issuer, params)
{
  if (params == undefined)
    params = KeyChain.getDefaultKeyParams();

  var subIdentity = this.addIdentity(subIdentityName, params);

  var request = subIdentity.getDefaultKey().getDefaultCertificate();

  request.setName(request.getKeyName().append("parent").appendVersion(1));

  var certificateParams = new SigningInfo(issuer);
  // Validity period of 20 years.
  var now = new Date().getTime();
  certificateParams.setValidityPeriod
    (new ValidityPeriod(now, now + 20 * 365 * 24 * 3600 * 1000.0));

  // Skip the AdditionalDescription.

  this.keyChain_.sign(request, certificateParams);
  this.keyChain_.setDefaultCertificate(subIdentity.getDefaultKey(), request);

  return subIdentity;
};

/**
 * Add a self-signed certificate made from the key and issuer ID.
 * @param {PibKey} key The key for the certificate.
 * @param {String} issuerId The issuer ID name component for the certificate name.
 * @return {CertificateV2} The new certificate.
 */
IdentityManagementFixture.prototype.addCertificate = function(key, issuerId)
{
  var certificateName = new Name(key.getName());
  certificateName.append(issuerId).appendVersion(3);
  var certificate = new CertificateV2();
  certificate.setName(certificateName);

  // Set the MetaInfo.
  certificate.getMetaInfo().setType(ContentType.KEY);
  // One hour.
  certificate.getMetaInfo().setFreshnessPeriod(3600 * 1000.);

  // Set the content.
  certificate.setContent(key.getPublicKey());

  var params = new SigningInfo(key);
  // Validity period of 10 days.
  var now = new Date().getTime();
  params.setValidityPeriod
    (new ValidityPeriod(now, now + 10 * 24 * 3600 * 1000.0));

  this.keyChain_.sign(certificate, params);
  return certificate;
};
