/**
 * Copyright (C) 2014-2016 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From PyNDN unit-tests by Adeola Bannis.
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
var Name = require('../../..').Name;
var BasicIdentityStorage = require('../../..').BasicIdentityStorage;
var IdentityManager = require('../../..').IdentityManager;
var FilePrivateKeyStorage = require('../../..').FilePrivateKeyStorage;
var SelfVerifyPolicyManager = require('../../..').SelfVerifyPolicyManager;
var KeyChain = require('../../..').KeyChain;
var IdentityCertificate = require('../../..').IdentityCertificate;
var RsaKeyParams = require('../../..').RsaKeyParams;
var KeyType = require('../../..').KeyType;

var databaseFilePath;
var identityStorage;
var identityManager;
var policyManager;
var keyChain;

function getNowSeconds()
{
  var currentDate = new Date();
  return currentDate.getMilliseconds() / 1000.0;
}

var RSA_DER =
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuFoDcNtffwbfFix64fw0" +
"hI2tKMkFrc6Ex7yw0YLMK9vGE8lXOyBl/qXabow6RCz+GldmFN6E2Qhm1+AX3Zm5" +
"sj3H53/HPtzMefvMQ9X7U+lK8eNMWawpRzvBh4/36VrK/awlkNIVIQ9aXj6q6BVe" +
"zL+zWT/WYemLq/8A1/hHWiwCtfOH1xQhGqWHJzeSgwIgOOrzxTbRaCjhAb1u2TeV" +
"yx/I9H/DV+AqSHCaYbB92HDcDN0kqwSnUf5H1+osE9MR5DLBLhXdSiULSgxT3Or/" +
"y2QgsgUK59WrjhlVMPEiHHRs15NZJbL1uQFXjgScdEarohcY3dilqotineFZCeN8" +
"DwIDAQAB";

describe('SqlIdentityStorage', function() {
  beforeEach(function(done) {
    databaseFilePath = "policy_config/test-public-info.db";
    try {
      fs.unlinkSync(databaseFilePath);
    } catch (e) {}
    identityStorage = new BasicIdentityStorage(databaseFilePath);

    identityManager = new IdentityManager
      (identityStorage, new FilePrivateKeyStorage());
    policyManager = new SelfVerifyPolicyManager(identityStorage);
    keyChain = new KeyChain(identityManager, policyManager);

    done();
  });

  afterEach(function(done) {
    try {
      fs.unlinkSync(databaseFilePath);
    } catch (e) {}

    done();
  });

  it('IdentityCreateDelete', function(done) {
    var identityName = new Name("/TestIdentityStorage/Identity").appendVersion
      (getNowSeconds());

    var certificateName;
    var keyName;

    new Promise(function(resolve, reject) {
      keyChain.createIdentityAndCertificate
        (identityName, function(certificateName) { resolve(certificateName); },
         function(error) { reject(error); });
    })
    .then(function(localCertificateName) {
      certificateName = localCertificateName;
      keyName = IdentityCertificate.certificateNameToPublicKeyName
        (certificateName);

      return identityStorage.doesIdentityExistPromise(identityName);
    })
    .then(function(exists) {
      assert.ok(exists, "Identity was not added to IdentityStorage");
      return identityStorage.doesKeyExistPromise(keyName);
    })
    .then(function(exists) {
      assert.ok(exists, "Key was not added to IdentityStorage");

      return new Promise(function(resolve, reject) {
        keyChain.deleteIdentity
          (identityName, function() { resolve(); },
           function(error) { reject(error); });
      });
    })
    .then(function() {
      return identityStorage.doesIdentityExistPromise(identityName);
    })
    .then(function(exists) {
      assert.ok(!exists, "Identity still in IdentityStorage after identity was deleted");
      return identityStorage.doesKeyExistPromise(keyName);
    })
    .then(function(exists) {
      assert.ok(!exists, "Key still in IdentityStorage after identity was deleted");
      return identityStorage.doesCertificateExistPromise(certificateName);
    })
    .then(function(exists) {
      assert.ok(!exists, "Certificate still in IdentityStorage after identity was deleted");

      return identityManager.getDefaultCertificateNameForIdentityPromise(identityName)
      .then(function(result) {
        assert.fail('', '', "The default certificate name for the identity was not deleted");
      }, function(err) {
        // Got the expected error.
        return Promise.resolve();
      });
    })
    // When done is called, Mocha displays errors from assert.ok.
    .then(done, done);
  });

  it('KeyCreateDelete', function(done) {
    var identityName = new Name("/TestIdentityStorage/Identity").appendVersion
      (getNowSeconds());

    var keyName1;
    var keyName2;

    identityManager.generateKeyPairPromise
      (identityName, true, new RsaKeyParams(2048))
    .then(function(keyName) {
      keyName1 = keyName;
      return identityStorage.setDefaultKeyNameForIdentityPromise(keyName1);
    })
    .then(function() {
      return identityManager.generateKeyPairPromise
        (identityName, false, new RsaKeyParams(2048))
    })
    .then(function(keyName) {
      keyName2 = keyName;

      return identityStorage.getDefaultKeyNameForIdentityPromise(identityName);
    })
    .then(function(keyName) {
      assert.ok(keyName.equals(keyName1),
        "Default key name was changed without explicit request");
      assert.ok(!keyName.equals(keyName2),
        "Newly created key replaced default key without explicit request");

      return identityStorage.deletePublicKeyInfoPromise(keyName2);
    })
    .then(function() {
      return identityStorage.doesKeyExistPromise(keyName2);
    })
    .then(function(exists) {
      assert.ok(!exists);
      return identityStorage.deleteIdentityInfoPromise(identityName);
    })
    // When done is called, Mocha displays errors from assert.ok.
    .then(done, done);
  });

  it('AutoCreateIdentity', function(done) {
    var keyName1 = new Name("/TestSqlIdentityStorage/KeyType/RSA/ksk-12345");
    var identityName = keyName1.getPrefix(-1);

    var keyName2;
    var certName1;
    var certName2;

    var decodedKey = new Buffer(RSA_DER, 'base64');
    identityStorage.addKeyPromise(keyName1, KeyType.RSA, new Blob(decodedKey))
    .then(function() {
      return identityStorage.setDefaultKeyNameForIdentityPromise(keyName1);
    })
    .then(function() {
      return identityStorage.doesKeyExistPromise(keyName1);
    })
    .then(function(exists) {
      assert.ok(exists, "Key was not added");
      return identityStorage.doesIdentityExistPromise(identityName);
    })
    .then(function(exists) {
      assert.ok(exists, "Identity for key was not automatically created");

      return identityStorage.getDefaultKeyNameForIdentityPromise(identityName);
    })
    .then(function(keyName) {
      assert.ok(keyName.equals(keyName1),
        "Default key was not set on identity creation");

      return identityStorage.getDefaultCertificateNameForKeyPromise(keyName1)
      .then(function(result) {
        assert.fail('', '', "The default certificate name should not be set");
      }, function(err) {
        // Got the expected error.
        return Promise.resolve();
      });
    })
    .then(function() {
      // We have no private key for signing.
      return identityManager.selfSignPromise(keyName1)
      .then(function(result) {
        assert.fail('', '', "There should be no private key for signing");
      }, function(err) {
        // Got the expected error.
        return Promise.resolve();
      });
    })
    .then(function() {
      return identityStorage.getDefaultCertificateNameForKeyPromise(keyName1)
      .then(function(result) {
        assert.fail('', '', "The default certificate name should not be set");
      }, function(err) {
        // Got the expected error.
        return Promise.resolve();
      });
    })
    .then(function() {
      return identityManager.getDefaultCertificateNameForIdentityPromise(identityName)
      .then(function(result) {
        assert.fail('', '', "There should be no default certificate name for the identity");
      }, function(err) {
        // Got the expected error.
        return Promise.resolve();
      });
    })
    .then(function() {
      return identityManager.generateRSAKeyPairAsDefaultPromise
        (identityName, false, 2048);
    })
    .then(function(keyName) {
      keyName2 = keyName;
      return identityManager.selfSignPromise(keyName2);
    })
    .then(function(cert) {
      return identityManager.addCertificateAsIdentityDefaultPromise(cert);
    })
    .then(function() {
      return identityManager.getDefaultCertificateNameForIdentityPromise(identityName);
    })
    .then(function(certName) {
      certName1 = certName;
      return identityStorage.getDefaultCertificateNameForKeyPromise(keyName2);
    })
    .then(function(certName) {
      certName2 = certName;

      assert.ok(certName1.equals(certName2),
        "Key-certificate mapping and identity-certificate mapping are not consistent");

      return new Promise(function(resolve, reject) {
        keyChain.deleteIdentity
          (identityName, function() { resolve(); },
           function(error) { reject(error); });
      });
    })
    .then(function() {
      return identityStorage.doesKeyExistPromise(keyName1);
    })
    .then(function(exists) {
      assert.ok(!exists, "deleteIdentity did not delete the key");
      return Promise.resolve();
    })
    // When done is called, Mocha displays errors from assert.ok.
    .then(done, done);
  });

  it('CertificateAddDelete', function(done) {
    var cert2;
    var certName1;
    var certName2;

    var identityName = new Name("/TestIdentityStorage/Identity").appendVersion
      (getNowSeconds());

    new Promise(function(resolve, reject) {
      identityManager.createIdentityAndCertificate
        (identityName, KeyChain.DEFAULT_KEY_PARAMS,
         function(certificateName) { resolve(certificateName); },
         function(error) { reject(error); });
    })
    .then(function() {
      return identityStorage.getDefaultKeyNameForIdentityPromise(identityName);
    })
    .then(function(keyName1) {
      return identityManager.selfSignPromise(keyName1);
    })
    .then(function(cert) {
      cert2 = cert;

      return identityStorage.addCertificatePromise(cert2);
    })
    .then(function() {
      certName2 = cert2.getName();

      return identityManager.getDefaultCertificateNameForIdentityPromise
        (identityName);
    })
    .then(function(certName) {
      certName1 = certName;
      assert.ok(!certName1.equals(certName2),
        "New certificate was set as default without explicit request");

      return identityStorage.deleteCertificateInfoPromise(certName1);
    })
    .then(function() {
      return identityStorage.doesCertificateExistPromise(certName2);
    })
    .then(function(exists) {
      assert.ok(exists);
      return identityStorage.doesCertificateExistPromise(certName1);
    })
    .then(function(exists) {
      assert.ok(!exists);

      return new Promise(function(resolve, reject) {
        keyChain.deleteIdentity
          (identityName, function() { resolve(); },
           function(error) { reject(error); });
      });
    })
    .then(function() {
      return identityStorage.doesCertificateExistPromise(certName2);
    })
    .then(function(exists) {
      assert.ok(!exists);
      return Promise.resolve();
    })
    // When done is called, Mocha displays errors from assert.ok.
    .then(done, done);
  });

  it('Stress', function(done) {
    var certName1;
    var certName2;
    var certName3;
    var certName4;
    var certName5;
    var keyName1;
    var keyName2;
    var keyName3;

    var identityName = new Name("/TestSecPublicInfoSqlite3/Delete").appendVersion
      (getNowSeconds());

    // ndn-cxx returns the cert name, but the IndentityManager docstring
    // specifies a key.
    new Promise(function(resolve, reject) {
      keyChain.createIdentityAndCertificate
        (identityName, function(certificateName) { resolve(certificateName); },
         function(error) { reject(error); });
    })
    .then(function(certName) {
      certName1 = certName;
      keyName1 = IdentityCertificate.certificateNameToPublicKeyName(certName1);
      return identityManager.generateRSAKeyPairAsDefaultPromise
        (identityName, false, 2048);
    })
    .then(function(keyName) {
      keyName2 = keyName;

      return identityManager.selfSignPromise(keyName2);
    })
    .then(function(cert) {
      cert2 = cert;
      certName2 = cert2.getName();
      return new Promise(function(resolve, reject) {
        identityManager.addCertificateAsDefault
          (cert2, function() { resolve(); },
           function(error) { reject(error); });
      });
    })
    .then(function() {
      return identityManager.generateRSAKeyPairAsDefaultPromise
        (identityName, false, 2048);
    })
    .then(function(keyName) {
      keyName3 = keyName;
      return identityManager.selfSignPromise(keyName3);
    })
    .then(function(cert) {
      cert3 = cert;
      certName3 = cert3.getName();
      return new Promise(function(resolve, reject) {
        identityManager.addCertificateAsDefault
          (cert3, function() { resolve(); },
           function(error) { reject(error); });
      });
    })
    .then(function() {
      return identityManager.selfSignPromise(keyName3);
    })
    .then(function(cert) {
      cert4 = cert;
      return new Promise(function(resolve, reject) {
        identityManager.addCertificateAsDefault
          (cert4, function() { resolve(); },
           function(error) { reject(error); });
      });
    })
    .then(function() {
      certName4 = cert4.getName();

      return identityManager.selfSignPromise(keyName3);
    })
    .then(function(cert) {
      cert5 = cert;
      return new Promise(function(resolve, reject) {
        identityManager.addCertificateAsDefault
          (cert5, function() { resolve(); },
           function(error) { reject(error); });
      });
    })
    .then(function() {
      certName5 = cert5.getName();
      return identityStorage.doesIdentityExistPromise(identityName);
    })
    .then(function(exists) {
      assert.ok(exists);
      return identityStorage.doesKeyExistPromise(keyName1);
    })
    .then(function(exists) {
      assert.ok(exists);
      return identityStorage.doesKeyExistPromise(keyName2);
    })
    .then(function(exists) {
      assert.ok(exists);
      return identityStorage.doesKeyExistPromise(keyName3);
    })
    .then(function(exists) {
      assert.ok(exists);
      return identityStorage.doesCertificateExistPromise(certName1);
    })
    .then(function(exists) {
      assert.ok(exists);
      return identityStorage.doesCertificateExistPromise(certName2);
    })
    .then(function(exists) {
      assert.ok(exists);
      return identityStorage.doesCertificateExistPromise(certName3);
    })
    .then(function(exists) {
      assert.ok(exists);
      return identityStorage.doesCertificateExistPromise(certName4);
    })
    .then(function(exists) {
      assert.ok(exists);
      return identityStorage.doesCertificateExistPromise(certName5);
    })
    .then(function(exists) {
      assert.ok(exists);
      return identityStorage.deleteCertificateInfoPromise(certName5);
    })
    .then(function() {
      return identityStorage.doesCertificateExistPromise(certName5);
    })
    .then(function(exists) {
      assert.ok(!exists);
      return identityStorage.doesCertificateExistPromise(certName4);
    })
    .then(function(exists) {
      assert.ok(exists);
      return identityStorage.doesCertificateExistPromise(certName3);
    })
    .then(function(exists) {
      assert.ok(exists);
      return identityStorage.doesKeyExistPromise(keyName2);
    })
    .then(function(exists) {
      assert.ok(exists);

      return identityStorage.deletePublicKeyInfoPromise(keyName3);
    })
    .then(function() {
      return identityStorage.doesCertificateExistPromise(certName4);
    })
    .then(function(exists) {
      assert.ok(!exists);
      return identityStorage.doesCertificateExistPromise(certName3);
    })
    .then(function(exists) {
      assert.ok(!exists);
      return identityStorage.doesKeyExistPromise(keyName3);
    })
    .then(function(exists) {
      assert.ok(!exists);
      return identityStorage.doesKeyExistPromise(keyName2);
    })
    .then(function(exists) {
      assert.ok(exists);
      return identityStorage.doesKeyExistPromise(keyName1);
    })
    .then(function(exists) {
      assert.ok(exists);
      return identityStorage.doesIdentityExistPromise(identityName);
    })
    .then(function(exists) {
      assert.ok(exists);

      return new Promise(function(resolve, reject) {
        keyChain.deleteIdentity
          (identityName, function() { resolve(); },
           function(error) { reject(error); });
      });
    })
    .then(function() {
      return identityStorage.doesCertificateExistPromise(certName2);
    })
    .then(function(exists) {
      assert.ok(!exists);
      return identityStorage.doesKeyExistPromise(keyName2);
    })
    .then(function(exists) {
      assert.ok(!exists);
      return identityStorage.doesCertificateExistPromise(certName1);
    })
    .then(function(exists) {
      assert.ok(!exists);
      return identityStorage.doesKeyExistPromise(keyName1);
    })
    .then(function(exists) {
      assert.ok(!exists);
      return identityStorage.doesIdentityExistPromise(identityName);
    })
    .then(function(exists) {
      assert.ok(!exists);
      return Promise.resolve();
    })

    // When done is called, Mocha displays errors from assert.ok.
    .then(done, done);
  });

  // TODO: EcdsaIdentity.
});
