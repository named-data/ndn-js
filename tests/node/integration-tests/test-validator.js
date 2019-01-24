/**
 * Copyright (C) 2018-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/v2/validator.t.cpp
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
var Interest = require('../../..').Interest;
var Data = require('../../..').Data;
var NetworkNack = require('../../..').NetworkNack;
var ContentType = require('../../..').ContentType;
var RsaKeyParams = require('../../..').RsaKeyParams;
var SigningInfo = require('../../..').SigningInfo;
var ValidityPeriod = require('../../..').ValidityPeriod;
var CertificateV2 = require('../../..').CertificateV2;
var ValidationPolicySimpleHierarchy = require('../../..').ValidationPolicySimpleHierarchy;
var HierarchicalValidatorFixture = require('./hierarchical-validator-fixture.js').HierarchicalValidatorFixture;

describe ("TestValidator", function() {
  beforeEach(function() {
    this.fixture_ = new HierarchicalValidatorFixture
      (new ValidationPolicySimpleHierarchy());

    /**
     * Call fixture_.validator_.validate and if it calls the failureCallback then
     * fail the test with the given message.
     * @param {Data} data The Data to validate.
     * @param {String} message The message to show if the test fails.
     */
    this.validateExpectSuccess = function(data, message) {
      this.fixture_.validator_.validate
        (data,
         function(data) {},
         function(data, error) { assert.fail('', '', message); });
    };

    /**
     * Call fixture_.validator_.validate and if it calls the successCallback then
     * fail the test with the given message.
     * @param {Data} data The Data to validate.
     * @param {String} message The message to show if the test succeeds.
     */
    this.validateExpectFailure = function(data, message) {
      this.fixture_.validator_.validate
        (data,
         function(data) { assert.fail('', '', message); },
         function(data, error) {});
    };

    /**
     * Make a certificate and put it in the fixture_.cache_.
     * @param {PibKey} key
     * @param {PibKey} signer
     */
    this.makeCertificate = function(key, signer)
    {
      // Copy the default certificate.
      var request = new CertificateV2(key.getDefaultCertificate());
      request.setName(new Name(key.getName()).append("looper").appendVersion(1));

      // Set SigningInfo.
      var params = new SigningInfo(signer);
      // Validity period from 100 days before to 100 days after now.
      var now = new Date().getTime();
      params.setValidityPeriod(new ValidityPeriod
        (now - 100 * 24 * 3600 * 1000.0, now + 100 * 24 * 3600 * 1000.0));
      this.fixture_.keyChain_.sign(request, params);
      this.fixture_.keyChain_.addCertificate(key, request);

      this.fixture_.cache_.insert(request);
    };
  });

  it("ConstructorSetValidator", function() {
    var validator = this.fixture_.validator_;

    var middlePolicy = new ValidationPolicySimpleHierarchy();
    var innerPolicy = new ValidationPolicySimpleHierarchy();

    validator.getPolicy().setInnerPolicy(middlePolicy);
    validator.getPolicy().setInnerPolicy(innerPolicy);

    assert.ok(validator.getPolicy().validator_ != null);
    assert.ok(validator.getPolicy().getInnerPolicy().validator_ != null);
    assert.ok
      (validator.getPolicy().getInnerPolicy().getInnerPolicy().validator_ != null);
  });

  it("Timeouts", function() {
    // Disable responses from the simulated Face.
    this.fixture_.face_.processInterest_ = null;

    var data = new Data(new Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Data"));
    this.fixture_.keyChain_.sign(data, new SigningInfo(this.fixture_.subIdentity_));

    this.validateExpectFailure(data, "Should fail to retrieve certificate");
    // There should be multiple expressed interests due to retries.
    assert.ok(this.fixture_.face_.sentInterests_.length > 1);
  });

  it("NackedInterests", function() {
    this.fixture_.face_.processInterest_ = function
        (interest, onData, onTimeout, onNetworkNack) {
      var networkNack = new NetworkNack();
      networkNack.setReason(NetworkNack.Reason.NO_ROUTE);

      onNetworkNack(interest, networkNack);
    };

    var data = new Data(new Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Data"));
    this.fixture_.keyChain_.sign(data, new SigningInfo(this.fixture_.subIdentity_));

    this.validateExpectFailure(data, "All interests should get NACKed");
    // There should be multiple expressed interests due to retries.
    assert.ok(this.fixture_.face_.sentInterests_.length > 1);
  });

  it("MalformedCertificate", function() {
    // Copy the default certificate.
    var malformedCertificate = new Data
      (this.fixture_.subIdentity_.getDefaultKey().getDefaultCertificate());
    malformedCertificate.getMetaInfo().setType(ContentType.BLOB);
    this.fixture_.keyChain_.sign
      (malformedCertificate, new SigningInfo(this.fixture_.identity_));
    // It has the wrong content type and a missing ValidityPeriod.
    try {
      new CertificateV2(malformedCertificate).wireEncode();
      assert.fail('', '', "Did not throw the expected exception");
    } catch (ex) {
      if (!(ex instanceof CertificateV2.Error))
        assert.fail('', '', "Did not throw the expected exception");
    }

    var originalProcessInterest = this.fixture_.face_.processInterest_;
    this.fixture_.face_.processInterest_ = function
        (interest, onData, onTimeout, onNetworkNack) {
      if (interest.getName().isPrefixOf(malformedCertificate.getName()))
        onData(interest, malformedCertificate);
      else
        originalProcessInterest.processInterest
          (interest, onData, onTimeout, onNetworkNack);
    };

    var data = new Data(new Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Data"));
    this.fixture_.keyChain_.sign(data, new SigningInfo(this.fixture_.subIdentity_));

    this.validateExpectFailure(data, "Signed by a malformed certificate");
    assert.equal(1, this.fixture_.face_.sentInterests_.length);
  });

  it("ExpiredCertificate", function() {
    // Copy the default certificate.
    var expiredCertificate = new Data
      (this.fixture_.subIdentity_.getDefaultKey().getDefaultCertificate());
    var info = new SigningInfo(this.fixture_.identity_);
    // Validity period from 2 hours ago do 1 hour ago.
    var now =  new Date().getTime();
    info.setValidityPeriod
      (new ValidityPeriod(now - 2 * 3600 * 1000, now - 3600 * 1000.0));
    this.fixture_.keyChain_.sign(expiredCertificate, info);
    try {
      new CertificateV2(expiredCertificate).wireEncode();
    } catch (ex) {
      assert.fail('', '', "Unexpected exception: " + ex);
    }

    var originalProcessInterest = this.fixture_.face_.processInterest_;
    this.fixture_.face_.processInterest_ = function
        (interest, onData, onTimeout, onNetworkNack) {
      if (interest.getName().isPrefixOf(expiredCertificate.getName()))
        onData(interest, expiredCertificate);
      else
        originalProcessInterest.processInterest
          (interest, onData, onTimeout, onNetworkNack);
    };

    var data = new Data(new Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Data"));
    this.fixture_.keyChain_.sign(data, new SigningInfo(this.fixture_.subIdentity_));

    this.validateExpectFailure(data, "Signed by an expired certificate");
    assert.equal(1, this.fixture_.face_.sentInterests_.length);
  });

  it("ResetAnchors", function() {
    this.fixture_.validator_.resetAnchors();

    var data = new Data(new Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Data"));
    this.fixture_.keyChain_.sign(data, new SigningInfo(this.fixture_.subIdentity_));
    this.validateExpectFailure(data, "Should fail, as no anchors are configured");
  });

  it("TrustedCertificateCaching", function() {
    var data = new Data(new Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Data"));
    this.fixture_.keyChain_.sign(data, new SigningInfo(this.fixture_.subIdentity_));

    this.validateExpectSuccess
      (data, "Should get accepted, as signed by the policy-compliant certificate");
    assert.equal(1, this.fixture_.face_.sentInterests_.length);
    this.fixture_.face_.sentInterests_ = [];

    // Disable responses from the simulated Face.
    this.fixture_.face_.processInterest_ = null;

    this.validateExpectSuccess
      (data, "Should get accepted, based on the cached trusted certificate");
    assert.equal(0, this.fixture_.face_.sentInterests_.length);
    this.fixture_.face_.sentInterests_ = [];

    // Make the trusted cache simulate a time 2 hours later, after expiration.
    this.fixture_.validator_.setCacheNowOffsetMilliseconds_(2 * 3600 * 1000.0);

    this.validateExpectFailure(data, "Should try and fail to retrieve certificates");
    // There should be multiple expressed interests due to retries.
    assert.ok(this.fixture_.face_.sentInterests_.length > 1);
    this.fixture_.face_.sentInterests_ = [];
  });

  it("InfiniteCertificateChain", function() {
    var thisTest = this;

    this.fixture_.face_.processInterest_ = function
        (interest, onData, onTimeout, onNetworkNack) {
      try {
        // Create another key for the same identity and sign it properly.
        var parentKey =
          thisTest.fixture_.keyChain_.createKey(thisTest.fixture_.subIdentity_);
        var requestedKey =
          thisTest.fixture_.subIdentity_.getKey(interest.getName());

        // Copy the Name.
        var certificateName = new Name(requestedKey.getName());
        certificateName.append("looper").appendVersion(1);
        var certificate = new CertificateV2();
        certificate.setName(certificateName);

        // Set the MetaInfo.
        certificate.getMetaInfo().setType(ContentType.KEY);
        // Set the freshness period to one hour.
        certificate.getMetaInfo().setFreshnessPeriod(3600 * 1000.0);

        // Set the content.
        certificate.setContent(requestedKey.getPublicKey());

        // Set SigningInfo.
        var params = new SigningInfo(parentKey);
        // Validity period from 10 days before to 10 days after now.
        var now = new Date().getTime();
        params.setValidityPeriod(new ValidityPeriod
          (now - 10 * 24 * 3600 * 1000.0, now + 10 * 24 * 3600 * 1000.0));

        thisTest.fixture_.keyChain_.sign(certificate, params);
        onData(interest, certificate);
      } catch (ex) {
        assert.fail("Error in InfiniteCertificateChain: " + ex);
      }
    };

    var data = new Data(new Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Data"));
    this.fixture_.keyChain_.sign(data, new SigningInfo(this.fixture_.subIdentity_));

    this.fixture_.validator_.setMaxDepth(40);
    assert.equal(40, this.fixture_.validator_.getMaxDepth());
    this.validateExpectFailure(data, "Should fail since the certificate should be looped");
    assert.equal(40, this.fixture_.face_.sentInterests_.length);
    this.fixture_.face_.sentInterests_ = [];

    // Make the trusted cache simulate a time 5 hours later, after expiration.
    this.fixture_.validator_.setCacheNowOffsetMilliseconds_(5 * 3600 * 1000.0);

    this.fixture_.validator_.setMaxDepth(30);
    assert.equal(30, this.fixture_.validator_.getMaxDepth());
    this.validateExpectFailure(data, "Should fail since the certificate chain is infinite");
    assert.equal(30, this.fixture_.face_.sentInterests_.length);
  });

  it("LoopedCertificateChain", function() {
    var identity1 = this.fixture_.addIdentity(new Name("/loop"));
    var key1 = this.fixture_.keyChain_.createKey
      (identity1, new RsaKeyParams(new Name.Component("key1")));
    var key2 = this.fixture_.keyChain_.createKey
      (identity1, new RsaKeyParams(new Name.Component("key2")));
    var key3 = this.fixture_.keyChain_.createKey
      (identity1, new RsaKeyParams(new Name.Component("key3")));

    this.makeCertificate(key1, key2);
    this.makeCertificate(key2, key3);
    this.makeCertificate(key3, key1);

    var data = new Data(new Name("/loop/Data"));
    this.fixture_.keyChain_.sign(data, new SigningInfo(key1));
    this.validateExpectFailure(data, "Should fail since the certificate chain loops");
    assert.equal(3, this.fixture_.face_.sentInterests_.length);
  });
});

var ValidationPolicySimpleHierarchyForInterestOnly =
  function ValidationPolicySimpleHierarchyForInterestOnly()
{
  // Call the base constructor.
  ValidationPolicySimpleHierarchy.call(this);
};

ValidationPolicySimpleHierarchyForInterestOnly.prototype =
  new ValidationPolicySimpleHierarchy();
ValidationPolicySimpleHierarchyForInterestOnly.prototype.name =
  "ValidationPolicySimpleHierarchyForInterestOnly";

ValidationPolicySimpleHierarchyForInterestOnly.prototype.checkPolicy = function
  (dataOrInterest, state, continueValidation)
{
  if (dataOrInterest instanceof Data)
    continueValidation(null, state);
  else
    // Call the base method for the Interest.
    ValidationPolicySimpleHierarchy.prototype.checkPolicy.call
      (this, dataOrInterest, state, continueValidation);
};

describe ("TestValidatorInterestOnly", function() {
  beforeEach(function() {
    this.fixture_ = new HierarchicalValidatorFixture
      (new ValidationPolicySimpleHierarchyForInterestOnly());

    /**
     * Call fixture_.validator_.validate and if it calls the failureCallback then
     * fail the test with the given message.
     * @param {Data|Interest} dataOrInterest The Data or Interest to validate.
     * @param {String} message The message to show if the test fails.
     */
    this.validateExpectSuccess = function(dataOrInterest, message) {
      this.fixture_.validator_.validate
        (dataOrInterest,
         function(dataOrInterest) {},
         function(dataOrInterest, error) { assert.fail('', '', message); });
    };

    /**
     * Call fixture_.validator_.validate and if it calls the successCallback then
     * fail the test with the given message.
     * @param {Data|Interest} dataOrInterest The Data or Interest to validate.
     * @param {String} message The message to show if the test succeeds.
     */
    this.validateExpectFailure = function(dataOrInterest, message) {
      this.fixture_.validator_.validate
        (dataOrInterest,
         function(dataOrInterest) { assert.fail('', '', message); },
         function(dataOrInterest, error) {});
    };
  });

  it("ValidateInterestsButBypassForData", function() {
    var interest = new Interest
      (new Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Interest"));
    var data = new Data
      (new Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Interest"));

    this.validateExpectFailure(interest, "Unsigned");
    this.validateExpectSuccess
      (data, "The policy requests to bypass validation for all data");
    assert.equal(0, this.fixture_.face_.sentInterests_.length);
    this.fixture_.face_.sentInterests_ = [];

    interest = new Interest
      (new Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Interest"));
    this.fixture_.keyChain_.sign
      (interest, new SigningInfo(SigningInfo.SignerType.SHA256));
    this.fixture_.keyChain_.sign
      (data, new SigningInfo(SigningInfo.SignerType.SHA256));
    this.validateExpectFailure(interest,
      "Required KeyLocator/Name is missing (not passed to the policy)");
    this.validateExpectSuccess
      (data, "The policy requests to bypass validation for all data");
    assert.equal(0, this.fixture_.face_.sentInterests_.length);
    this.fixture_.face_.sentInterests_ = [];

    interest = new Interest
      (new Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Interest"));
    this.fixture_.keyChain_.sign(interest, new SigningInfo(this.fixture_.identity_));
    this.fixture_.keyChain_.sign(data, new SigningInfo(this.fixture_.identity_));
    this.validateExpectSuccess(interest,
      "Should be successful since it is signed by the anchor");
    this.validateExpectSuccess
      (data, "The policy requests to bypass validation for all data");
    assert.equal(0, this.fixture_.face_.sentInterests_.length);
    this.fixture_.face_.sentInterests_ = [];

    interest = new Interest
      (new Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Interest"));
    this.fixture_.keyChain_.sign(interest, new SigningInfo(this.fixture_.subIdentity_));
    this.fixture_.keyChain_.sign(data, new SigningInfo(this.fixture_.subIdentity_));
   this.validateExpectFailure(interest,
      "Should fail since the policy is not allowed to create new trust anchors");
    this.validateExpectSuccess
      (data, "The policy requests to bypass validation for all data");
    assert.equal(1, this.fixture_.face_.sentInterests_.length);
    this.fixture_.face_.sentInterests_ = [];

    interest = new Interest
      (new Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Interest"));
    this.fixture_.keyChain_.sign(interest, new SigningInfo(this.fixture_.otherIdentity_));
    this.fixture_.keyChain_.sign(data, new SigningInfo(this.fixture_.otherIdentity_));
    this.validateExpectFailure(interest,
      "Should fail since it is signed by a policy-violating certificate");
    this.validateExpectSuccess
      (data, "The policy requests to bypass validation for all data");
    // No network operations are expected since the certificate is not validated
    // by the policy.
    assert.equal(0, this.fixture_.face_.sentInterests_.length);
    this.fixture_.face_.sentInterests_ = [];

    // Make the trusted cache simulate a time 2 hours later, after expiration.
    this.fixture_.validator_.setCacheNowOffsetMilliseconds_(2 * 3600 * 1000.0);

    interest = new Interest
      (new Name("/Security/V2/ValidatorFixture/Sub1/Sub2/Interest"));
    this.fixture_.keyChain_.sign(interest, new SigningInfo(this.fixture_.subSelfSignedIdentity_));
    this.fixture_.keyChain_.sign(data, new SigningInfo(this.fixture_.subSelfSignedIdentity_));
    this.validateExpectFailure(interest,
     "Should fail since the policy is not allowed to create new trust anchors");
    this.validateExpectSuccess(data,
      "The policy requests to bypass validation for all data");
    assert.equal(1, this.fixture_.face_.sentInterests_.length);
    this.fixture_.face_.sentInterests_ = [];
  });
});
