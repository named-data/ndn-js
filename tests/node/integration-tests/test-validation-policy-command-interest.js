/**
 * Copyright (C) 2018-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx unit tests:
 * https://github.com/named-data/ndn-cxx/blob/master/tests/unit-tests/security/validation-policy-command-interest.t.cpp
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
var Blob = require('../../..').Blob;
var Name = require('../../..').Name;
var Interest = require('../../..').Interest;
var Data = require('../../..').Data;
var Sha256WithRsaSignature = require('../../..').Sha256WithRsaSignature;
var TlvWireFormat = require('../../..').TlvWireFormat;
var KeyLocator = require('../../..').KeyLocator;
var KeyLocatorType = require('../../..').KeyLocatorType;
var SigningInfo = require('../../..').SigningInfo;
var CommandInterestSigner = require('../../..').CommandInterestSigner;
var ValidationPolicyAcceptAll = require('../../..').ValidationPolicyAcceptAll;
var ValidationPolicyCommandInterest = require('../../..').ValidationPolicyCommandInterest;
var ValidationPolicySimpleHierarchy = require('../../..').ValidationPolicySimpleHierarchy;
var HierarchicalValidatorFixture = require('./hierarchical-validator-fixture.js').HierarchicalValidatorFixture;

/**
 * @param {ValidationPolicyCommandInterest.Options} options (optional)
 * @constructor
 */
var ValidationPolicyCommandInterestFixture = function ValidationPolicyCommandInterestFixture
  (options)
{
  // Call the base constructor.
  HierarchicalValidatorFixture.call(this, new ValidationPolicyCommandInterest
    (new ValidationPolicySimpleHierarchy(), options));

  this.signer_ = new CommandInterestSigner(this.keyChain_);
};

ValidationPolicyCommandInterestFixture.prototype = new HierarchicalValidatorFixture
  (new ValidationPolicyAcceptAll());
ValidationPolicyCommandInterestFixture.prototype.name = "ValidationPolicyCommandInterestFixture";

/**
 * @param {PibIdentity} identity
 * @returns {Interest}
 */
ValidationPolicyCommandInterestFixture.prototype.makeCommandInterest = function
  (identity)
{
  return this.signer_.makeCommandInterest
    (new Name(identity.getName()).append("CMD"), new SigningInfo(identity));
};

/**
 * Set the offset for the validation policy and signer.
 * @param {number} nowOffsetMilliseconds The offset in milliseconds.
 */
ValidationPolicyCommandInterestFixture.prototype.setNowOffsetMilliseconds = function
  (nowOffsetMilliseconds)
{
  this.validator_.getPolicy().setNowOffsetMilliseconds_(nowOffsetMilliseconds);
  this.validator_.setCacheNowOffsetMilliseconds_(nowOffsetMilliseconds);
  this.signer_.setNowOffsetMilliseconds_(nowOffsetMilliseconds);
};

/**
 * @param {Interest} interest
 * @param {number} index
 * @param {Name.Component|String|Array<number>|ArrayBuffer|Buffer} component
 */
function setNameComponent(interest, index, component)
{
  var name = interest.getName().getPrefix(index);
  name.append(new Name.Component(component));
  name.append(interest.getName().getSubName(name.size()));
  interest.setName(name);
}

describe ("TestValidationPolicyCommandInterest", function() {
  beforeEach(function() {
    this.fixture_ = new ValidationPolicyCommandInterestFixture();

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

  it("Basic", function() {
    var interest1 = this.fixture_.makeCommandInterest(this.fixture_.identity_);
    this.validateExpectSuccess(interest1, "Should succeed (within grace period)");

    this.fixture_.setNowOffsetMilliseconds(5 * 1000.0);
    var interest2 = this.fixture_.makeCommandInterest(this.fixture_.identity_);
    this.validateExpectSuccess(interest2,
      "Should succeed (timestamp larger than previous)");
  });

  it("DataPassthrough", function() {
    var data1 = new Data(new Name("/Security/V2/ValidatorFixture/Sub1"));
    this.fixture_.keyChain_.sign(data1);
    this.validateExpectSuccess(data1,
      "Should succeed (fallback on inner validation policy for data)");
  });

  it("NameTooShort", function() {
    var interest1 = new Interest(new Name("/name/too/short"));
    this.validateExpectFailure(interest1, "Should fail (name is too short)");
  });

  it("BadSignatureInfo", function() {
    var interest1 = this.fixture_.makeCommandInterest(this.fixture_.identity_);
    setNameComponent
      (interest1, CommandInterestSigner.POS_SIGNATURE_INFO, "not-SignatureInfo");
    this.validateExpectFailure(interest1, "Should fail (missing signature info)");
  });

  it("MissingKeyLocator", function() {
    var interest1 = this.fixture_.makeCommandInterest(this.fixture_.identity_);
    var signatureInfo = new Sha256WithRsaSignature();
    setNameComponent
      (interest1, CommandInterestSigner.POS_SIGNATURE_INFO,
       TlvWireFormat.get().encodeSignatureInfo(signatureInfo));
    this.validateExpectFailure(interest1, "Should fail (missing KeyLocator)");
  });

  it("BadKeyLocatorType", function() {
    var interest1 = this.fixture_.makeCommandInterest(this.fixture_.identity_);
    var keyLocator = new KeyLocator();
    keyLocator.setType(KeyLocatorType.KEY_LOCATOR_DIGEST);
    keyLocator.setKeyData(new Blob
      ([ 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd ]));
    var signatureInfo = new Sha256WithRsaSignature();
    signatureInfo.setKeyLocator(keyLocator);

    setNameComponent
      (interest1, CommandInterestSigner.POS_SIGNATURE_INFO,
       TlvWireFormat.get().encodeSignatureInfo(signatureInfo));
    this.validateExpectFailure(interest1, "Should fail (bad KeyLocator type)");
  });

  it("BadCertificateName", function() {
    var interest1 = this.fixture_.makeCommandInterest(this.fixture_.identity_);
    var keyLocator = new KeyLocator();
    keyLocator.setType(KeyLocatorType.KEYNAME);
    keyLocator.setKeyName(new Name("/bad/cert/name"));
    var signatureInfo = new Sha256WithRsaSignature();
    signatureInfo.setKeyLocator(keyLocator);

    setNameComponent
      (interest1, CommandInterestSigner.POS_SIGNATURE_INFO,
       TlvWireFormat.get().encodeSignatureInfo(signatureInfo));
    this.validateExpectFailure(interest1, "Should fail (bad certificate name)");
  });

  it("InnerPolicyReject", function() {
    var interest1 = this.fixture_.makeCommandInterest(this.fixture_.otherIdentity_);
    this.validateExpectFailure(interest1, "Should fail (inner policy should reject)");
  });

  it("TimestampOutOfGracePositive", function() {
    this.fixture_ = new ValidationPolicyCommandInterestFixture
      (new ValidationPolicyCommandInterest.Options(15 * 1000.0));

    // Signed at 0 seconds.
    var interest1 = this.fixture_.makeCommandInterest(this.fixture_.identity_);
    // Verifying at +16 seconds.
    this.fixture_.setNowOffsetMilliseconds(16 * 1000.0);
    this.validateExpectFailure(interest1,
      "Should fail (timestamp outside the grace period)");

    // Signed at +16 seconds.
    var interest2 = this.fixture_.makeCommandInterest(this.fixture_.identity_);
    this.validateExpectSuccess(interest2, "Should succeed");
  });

  it("TimestampOutOfGraceNegative", function() {
    this.fixture_ = new ValidationPolicyCommandInterestFixture
      (new ValidationPolicyCommandInterest.Options(15 * 1000.0));

    // Signed at 0 seconds.
    var interest1 = this.fixture_.makeCommandInterest(this.fixture_.identity_);
    // Signed at +1 seconds.
    this.fixture_.setNowOffsetMilliseconds(1 * 1000.0);
    var interest2 = this.fixture_.makeCommandInterest(this.fixture_.identity_);
    // Signed at +2 seconds.
    this.fixture_.setNowOffsetMilliseconds(2 * 1000.0);
    var interest3 = this.fixture_.makeCommandInterest(this.fixture_.identity_);

    // Verifying at -16 seconds.
    this.fixture_.setNowOffsetMilliseconds(-16 * 1000.0);
    this.validateExpectFailure(interest1,
      "Should fail (timestamp outside the grace period)");

    // The CommandInterestValidator should not remember interest1's timestamp.
    this.validateExpectFailure(interest2,
      "Should fail (timestamp outside the grace period)");

    // The CommandInterestValidator should not remember interest2's timestamp, and
    // should treat interest3 as initial.
    // Verifying at +2 seconds.
    this.fixture_.setNowOffsetMilliseconds(2 * 1000.0);
    this.validateExpectSuccess(interest3, "Should succeed");
  });

  it("TimestampReorderEqual", function() {
    // Signed at 0 seconds.
    var interest1 = this.fixture_.makeCommandInterest(this.fixture_.identity_);
    this.validateExpectSuccess(interest1, "Should succeed");

    // Signed at 0 seconds.
    var interest2 = this.fixture_.makeCommandInterest(this.fixture_.identity_);
    setNameComponent
      (interest2, CommandInterestSigner.POS_TIMESTAMP,
       interest1.getName().get(CommandInterestSigner.POS_TIMESTAMP));
    this.validateExpectFailure(interest2, "Should fail (timestamp reordered)");

    // Signed at +2 seconds.
    this.fixture_.setNowOffsetMilliseconds(2 * 1000.0);
    var interest3 = this.fixture_.makeCommandInterest(this.fixture_.identity_);
    this.validateExpectSuccess(interest3, "Should succeed");
  });

  it("TimestampReorderNegative", function() {
    // Signed at 0 seconds.
    var interest2 = this.fixture_.makeCommandInterest(this.fixture_.identity_);
    // Signed at +200 milliseconds.
    this.fixture_.setNowOffsetMilliseconds(200.0);
    var interest3 = this.fixture_.makeCommandInterest(this.fixture_.identity_);
    // Signed at +1100 milliseconds.
    this.fixture_.setNowOffsetMilliseconds(1100.0);
    var interest1 = this.fixture_.makeCommandInterest(this.fixture_.identity_);
    // Signed at +1400 milliseconds.
    this.fixture_.setNowOffsetMilliseconds(1400.0);
    var interest4 = this.fixture_.makeCommandInterest(this.fixture_.identity_);

    // Verifying at +1100 milliseconds.
    this.fixture_.setNowOffsetMilliseconds(1100.0);
    this.validateExpectSuccess(interest1, "Should succeed");

    // Verifying at 0 milliseconds.
    this.fixture_.setNowOffsetMilliseconds(0.0);
    this.validateExpectFailure(interest2, "Should fail (timestamp reordered)");

    // The CommandInterestValidator should not remember interest2's timestamp.
    // Verifying at +200 milliseconds.
    this.fixture_.setNowOffsetMilliseconds(200.0);
    this.validateExpectFailure(interest3, "Should fail (timestamp reordered)");

    // Verifying at +1400 milliseconds.
    this.fixture_.setNowOffsetMilliseconds(1400.0);
    this.validateExpectSuccess(interest4, "Should succeed");
  });

  it("LimitedRecords", function() {
    this.fixture_ = new ValidationPolicyCommandInterestFixture
      (new ValidationPolicyCommandInterest.Options(15 * 1000.0, 3));

    var identity1 = this.fixture_.addSubCertificate
      (new Name("/Security/V2/ValidatorFixture/Sub1"), this.fixture_.identity_);
    this.fixture_.cache_.insert(identity1.getDefaultKey().getDefaultCertificate());
    var identity2 = this.fixture_.addSubCertificate
      (new Name("/Security/V2/ValidatorFixture/Sub2"), this.fixture_.identity_);
    this.fixture_.cache_.insert(identity2.getDefaultKey().getDefaultCertificate());
    var identity3 = this.fixture_.addSubCertificate
      (new Name("/Security/V2/ValidatorFixture/Sub3"), this.fixture_.identity_);
    this.fixture_.cache_.insert(identity3.getDefaultKey().getDefaultCertificate());
    var identity4 = this.fixture_.addSubCertificate
      (new Name("/Security/V2/ValidatorFixture/Sub4"), this.fixture_.identity_);
    this.fixture_.cache_.insert(identity4.getDefaultKey().getDefaultCertificate());

    var interest1 = this.fixture_.makeCommandInterest(identity2);
    var interest2 = this.fixture_.makeCommandInterest(identity3);
    var interest3 = this.fixture_.makeCommandInterest(identity4);
    // Signed at 0 seconds.
    var interest00 = this.fixture_.makeCommandInterest(identity1);
    // Signed at +1 seconds.
    this.fixture_.setNowOffsetMilliseconds(1 * 1000.0);
    var interest01 = this.fixture_.makeCommandInterest(identity1);
    // Signed at +2 seconds.
    this.fixture_.setNowOffsetMilliseconds(2 * 1000.0);
    var interest02 = this.fixture_.makeCommandInterest(identity1);

    this.validateExpectSuccess(interest00, "Should succeed");

    this.validateExpectSuccess(interest02, "Should succeed");

    this.validateExpectSuccess(interest1, "Should succeed");

    this.validateExpectSuccess(interest2, "Should succeed");

    this.validateExpectSuccess(interest3, "Should succeed, forgets identity1");

    this.validateExpectSuccess(interest01,
      "Should succeed despite timestamp is reordered, because the record has been evicted");
  });

  it("UnlimitedRecords", function() {
    this.fixture_ = new ValidationPolicyCommandInterestFixture
      (new ValidationPolicyCommandInterest.Options(15 * 1000.0, -1));

    var identities = [];
    for (var i = 0; i < 20; ++i) {
      var identity = this.fixture_.addSubCertificate
        (new Name("/Security/V2/ValidatorFixture/Sub" + i), this.fixture_.identity_);
      this.fixture_.cache_.insert(identity.getDefaultKey().getDefaultCertificate());
      identities.push(identity);
    }

    // Signed at 0 seconds.
    var interest1 = this.fixture_.makeCommandInterest(identities[0]);
    this.fixture_.setNowOffsetMilliseconds(1 * 1000.0);
    for (var i = 0; i < 20; ++i) {
      // Signed at +1 seconds.
      var interest2 = this.fixture_.makeCommandInterest(identities[i]);

      this.validateExpectSuccess(interest2, "Should succeed");
    }

    this.validateExpectFailure(interest1, "Should fail (timestamp reorder)");
  });

  it("ZeroRecords", function() {
    this.fixture_ = new ValidationPolicyCommandInterestFixture
      (new ValidationPolicyCommandInterest.Options(15 * 1000.0, 0));

    // Signed at 0 seconds.
    var interest1 = this.fixture_.makeCommandInterest(this.fixture_.identity_);
    // Signed at +1 seconds.
    this.fixture_.setNowOffsetMilliseconds(1 * 1000.0);
    var interest2 = this.fixture_.makeCommandInterest(this.fixture_.identity_);
    this.validateExpectSuccess(interest2, "Should succeed");

    this.validateExpectSuccess(interest1,
      "Should succeed despite the timestamp being reordered, because the record isn't kept");
  });

  it("LimitedRecordLifetime", function() {
    this.fixture_ = new ValidationPolicyCommandInterestFixture
      (new ValidationPolicyCommandInterest.Options(400 * 1000.0, 1000, 300 * 1000.0));

    // Signed at 0 seconds.
    var interest1 = this.fixture_.makeCommandInterest(this.fixture_.identity_);
    // Signed at +240 seconds.
    this.fixture_.setNowOffsetMilliseconds(240 * 1000.0);
    var interest2 = this.fixture_.makeCommandInterest(this.fixture_.identity_);
    // Signed at +360 seconds.
    this.fixture_.setNowOffsetMilliseconds(360 * 1000.0);
    var interest3 = this.fixture_.makeCommandInterest(this.fixture_.identity_);

    // Validate at 0 seconds.
    this.fixture_.setNowOffsetMilliseconds(0.0);
    this.validateExpectSuccess(interest1, "Should succeed");

    this.validateExpectSuccess(interest3, "Should succeed");

    // Validate at +301 seconds.
    this.fixture_.setNowOffsetMilliseconds(301 * 1000.0);
    this.validateExpectSuccess(interest2,
      "Should succeed despite the timestamp being reordered, because the record has expired");
  });

  it("ZeroRecordLifetime", function() {
    this.fixture_ = new ValidationPolicyCommandInterestFixture
      (new ValidationPolicyCommandInterest.Options(15 * 1000.0, 1000, 0.0));

    // Signed at 0 seconds.
    var interest1 = this.fixture_.makeCommandInterest(this.fixture_.identity_);
    // Signed at +1 second.
    this.fixture_.setNowOffsetMilliseconds(1 * 1000.0);
    var interest2 = this.fixture_.makeCommandInterest(this.fixture_.identity_);
    this.validateExpectSuccess(interest2, "Should succeed");

    this.validateExpectSuccess(interest1,
      "Should succeed despite the timestamp being reordered, because the record has expired");
  });
});
