/**
 * Copyright (C) 2014-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/signing-info.t.cpp
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

var assert = require("assert");
var Name = require('../../..').Name;
var DigestAlgorithm = require('../../..').DigestAlgorithm;
var SigningInfo = require('../../..').SigningInfo;

describe('TestSigningInfo', function() {
  it('Basic', function() {
    var identityName = new Name("/my-identity");
    var keyName = new Name("/my-key");
    var certificateName = new Name("/my-cert");

    var info = new SigningInfo();

    assert.equal(SigningInfo.SignerType.NULL, info.getSignerType());
    assert.ok(new Name().equals(info.getSignerName()));
    assert.equal(DigestAlgorithm.SHA256, info.getDigestAlgorithm());

    info.setSigningIdentity(identityName);
    assert.equal(SigningInfo.SignerType.ID, info.getSignerType());
    assert.ok(identityName.equals(info.getSignerName()));
    assert.equal(DigestAlgorithm.SHA256, info.getDigestAlgorithm());

    var infoId = new SigningInfo(SigningInfo.SignerType.ID, identityName);
    assert.equal(SigningInfo.SignerType.ID, infoId.getSignerType());
    assert.ok(identityName.equals(infoId.getSignerName()));
    assert.equal(DigestAlgorithm.SHA256, infoId.getDigestAlgorithm());

    info.setSigningKeyName(keyName);
    assert.equal(SigningInfo.SignerType.KEY, info.getSignerType());
    assert.ok(keyName.equals(info.getSignerName()));
    assert.equal(DigestAlgorithm.SHA256, info.getDigestAlgorithm());

    var infoKey = new SigningInfo(SigningInfo.SignerType.KEY, keyName);
    assert.equal(SigningInfo.SignerType.KEY, infoKey.getSignerType());
    assert.ok(keyName.equals(infoKey.getSignerName()));
    assert.equal(DigestAlgorithm.SHA256, infoKey.getDigestAlgorithm());

    info.setSigningCertificateName(certificateName);
    assert.equal(SigningInfo.SignerType.CERT, info.getSignerType());
    assert.ok(certificateName.equals(info.getSignerName()));
    assert.equal(DigestAlgorithm.SHA256, info.getDigestAlgorithm());

    var infoCert = new SigningInfo(SigningInfo.SignerType.CERT, certificateName);
    assert.equal(SigningInfo.SignerType.CERT, infoCert.getSignerType());
    assert.ok(certificateName.equals(infoCert.getSignerName()));
    assert.equal(DigestAlgorithm.SHA256, infoCert.getDigestAlgorithm());

    info.setSha256Signing();
    assert.equal(SigningInfo.SignerType.SHA256, info.getSignerType());
    assert.ok(new Name().equals(info.getSignerName()));
    assert.equal(DigestAlgorithm.SHA256, info.getDigestAlgorithm());

    var infoSha256 = new SigningInfo(SigningInfo.SignerType.SHA256);
    assert.equal(SigningInfo.SignerType.SHA256, infoSha256.getSignerType());
    assert.ok(new Name().equals(infoSha256.getSignerName()));
    assert.equal(DigestAlgorithm.SHA256, infoSha256.getDigestAlgorithm());
  });

  it('FromString', function() {
    var infoDefault = new SigningInfo("");
    assert.equal(SigningInfo.SignerType.NULL, infoDefault.getSignerType());
    assert.ok(new Name().equals(infoDefault.getSignerName()));
    assert.equal(DigestAlgorithm.SHA256, infoDefault.getDigestAlgorithm());

    var infoId = new SigningInfo("id:/my-identity");
    assert.equal(SigningInfo.SignerType.ID, infoId.getSignerType());
    assert.ok(new Name("/my-identity").equals(infoId.getSignerName()));
    assert.equal(DigestAlgorithm.SHA256, infoId.getDigestAlgorithm());

    var infoKey = new SigningInfo("key:/my-key");
    assert.equal(SigningInfo.SignerType.KEY, infoKey.getSignerType());
    assert.ok(new Name("/my-key").equals(infoKey.getSignerName()));
    assert.equal(DigestAlgorithm.SHA256, infoKey.getDigestAlgorithm());

    var infoCert = new SigningInfo("cert:/my-cert");
    assert.equal(SigningInfo.SignerType.CERT, infoCert.getSignerType());
    assert.ok(new Name("/my-cert").equals(infoCert.getSignerName()));
    assert.equal(DigestAlgorithm.SHA256, infoCert.getDigestAlgorithm());

    var infoSha = new SigningInfo("id:/localhost/identity/digest-sha256");
    assert.equal(SigningInfo.SignerType.SHA256, infoSha.getSignerType());
    assert.ok(new Name().equals(infoSha.getSignerName()));
    assert.equal(DigestAlgorithm.SHA256, infoSha.getDigestAlgorithm());
  });

  it('ToString', function() {
    assert.equal("", new SigningInfo().toString());

    assert.equal("id:/my-identity",
      new SigningInfo(SigningInfo.SignerType.ID, new Name("/my-identity")).toString());
    assert.equal("key:/my-key",
      new SigningInfo(SigningInfo.SignerType.KEY, new Name("/my-key")).toString());
    assert.equal("cert:/my-cert",
      new SigningInfo(SigningInfo.SignerType.CERT, new Name("/my-cert")).toString());
    assert.equal("id:/localhost/identity/digest-sha256",
      new SigningInfo(SigningInfo.SignerType.SHA256).toString());
  });

  it('Chaining', function() {
    var info = new SigningInfo()
      .setSigningIdentity(new Name("/identity"))
      .setSigningKeyName(new Name("/key/name"))
      .setSigningCertificateName(new Name("/cert/name"))
      .setPibIdentity(null)
      .setPibKey(null)
      .setSha256Signing()
      .setDigestAlgorithm(DigestAlgorithm.SHA256);

    assert.equal("id:/localhost/identity/digest-sha256", info.toString());
  });
});
