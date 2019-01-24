/**
 * Copyright (C) 2014-2019 Regents of the University of California.
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

var path = require("path");
var assert = require("assert");
var Name = require('../../..').Name;
var Data = require('../../..').Data;
var KeyLocator = require('../../..').KeyLocator;
var KeyLocatorType = require('../../..').KeyLocatorType;
var CertificateFetcherOffline = require('../../..').CertificateFetcherOffline;
var DataValidationState = require('../../..').DataValidationState;
var ValidatorConfig = require('../../..').ValidatorConfig;

/**
 * Create a TestValidationResult whose state_ will reference the given Data.
 * @param {Data} data The Data packed for the state_, which must remain valid.
 * @constructor
 */
var TestValidationResult = function TestValidationResult(data)
{
  this.data_ = data;
  this.reset();
};

/**
 * Reset all the results to false, to get ready for another result.
 */
TestValidationResult.prototype.reset = function()
{
  var thisResult = this;
  this.state_ = new DataValidationState
    (this.data_,
     function(data) { thisResult.calledSuccess_ = true; },
     function(data, error) { thisResult.calledFailure_ = true; });

  this.calledSuccess_ = false;
  this.calledFailure_ = false;
  this.calledContinue_ = false;
}

/**
 * Call reset() then call validator.checkPolicy to set this object's results.
 * When finished, you can check calledSuccess_, etc.
 * @param {ValidatorConfig} validator The ValidatorConfig for calling checkPolicy.
 */
TestValidationResult.prototype.checkPolicy = function(validator)
{
  this.reset();

  var thisResult = this;
  validator.getPolicy().checkPolicy
    (this.data_, this.state_, function(certificateRequest, state) {
      thisResult.calledContinue_ = true;
    });
}

describe('TestValidationPolicyConfig', function() {
  beforeEach(function() {
    this.policyConfigDirectory_ = "policy_config";
  });

  it('NameRelation', function() {
    // Set up the validators.
    var fetcher = new CertificateFetcherOffline();
    var validatorPrefix = new ValidatorConfig(fetcher);
    var validatorEqual = new ValidatorConfig(fetcher);
    var validatorStrict = new ValidatorConfig(fetcher);

    validatorPrefix.load
      (path.join(this.policyConfigDirectory_, "relation_ruleset_prefix.conf"));
    validatorEqual.load
      (path.join(this.policyConfigDirectory_, "relation_ruleset_equal.conf"));
    validatorStrict.load
      (path.join(this.policyConfigDirectory_, "relation_ruleset_strict.conf"));

    // Set up a Data packet and result object.
    var data = new Data();
    KeyLocator.getFromSignature(data.getSignature()).setType
      (KeyLocatorType.KEYNAME);
    KeyLocator.getFromSignature(data.getSignature()).setKeyName
      (new Name("/SecurityTestSecRule/KEY/123"));
    var result = new TestValidationResult(data);

    data.setName(new Name("/TestRule1"));
    result.checkPolicy(validatorPrefix);
    assert.ok(result.calledContinue_ && !result.calledFailure_,
      "Prefix relation should match prefix name");
    result.checkPolicy(validatorEqual);
    assert.ok(result.calledContinue_ && !result.calledFailure_,
      "Equal relation should match prefix name");
    result.checkPolicy(validatorStrict);
    assert.ok(result.calledFailure_ && !result.calledContinue_,
      "Strict-prefix relation should not match prefix name");

    data.setName(new Name("/TestRule1/hi"));
    result.checkPolicy(validatorPrefix);
    assert.ok(result.calledContinue_ && !result.calledFailure_,
      "Prefix relation should match longer name");
    result.checkPolicy(validatorEqual);
    assert.ok(result.calledFailure_ && !result.calledContinue_,
      "Equal relation should not match longer name");
    result.checkPolicy(validatorStrict);
    assert.ok(result.calledContinue_ && !result.calledFailure_,
      "Strict-prefix relation should match longer name");

    data.setName(new Name("/Bad/TestRule1/"));
    result.checkPolicy(validatorPrefix);
    assert.ok(result.calledFailure_ && !result.calledContinue_,
      "Prefix relation should not match inner components");
    result.checkPolicy(validatorEqual);
    assert.ok(result.calledFailure_ && !result.calledContinue_,
      "Equal relation should not match inner components");
    result.checkPolicy(validatorStrict);
    assert.ok(result.calledFailure_ && !result.calledContinue_,
      "Strict-prefix relation should  not match inner components");
  });

  it('SimpleRegex', function() {
    // Set up the validator.
    var fetcher = new CertificateFetcherOffline();
    var validator = new ValidatorConfig(fetcher);
    validator.load(path.join(this.policyConfigDirectory_, "regex_ruleset.conf"));

    // Set up a Data packet and result object.
    var data = new Data();
    KeyLocator.getFromSignature(data.getSignature()).setType(KeyLocatorType.KEYNAME);
    KeyLocator.getFromSignature(data.getSignature()).setKeyName
      (new Name("/SecurityTestSecRule/KEY/123"));
    var result = new TestValidationResult(data);

    data.setName(new Name("/SecurityTestSecRule/Basic"));
    result.checkPolicy(validator);
    assert.ok(result.calledContinue_ && !result.calledFailure_);

    data.setName(new Name("/SecurityTestSecRule/Basic/More"));
    result.checkPolicy(validator);
    assert.ok(result.calledFailure_ && !result.calledContinue_);

    data.setName(new Name("/SecurityTestSecRule/"));
    result.checkPolicy(validator);
    assert.ok(result.calledContinue_ && !result.calledFailure_);

    data.setName(new Name("/SecurityTestSecRule/Other/TestData"));
    result.checkPolicy(validator);
    assert.ok(result.calledContinue_ && !result.calledFailure_);

    data.setName(new Name("/Basic/Data"));
    result.checkPolicy(validator);
    assert.ok(result.calledFailure_ && !result.calledContinue_);
  });

  it('Hierarchical', function() {
    // Set up the validator.
    var fetcher = new CertificateFetcherOffline();
    var validator = new ValidatorConfig(fetcher);
    validator.load
      (path.join(this.policyConfigDirectory_, "hierarchical_ruleset.conf"));

    // Set up a Data packet and result object.
    var data = new Data();
    KeyLocator.getFromSignature(data.getSignature()).setType(KeyLocatorType.KEYNAME);
    KeyLocator.getFromSignature(data.getSignature()).setKeyName
      (new Name("/SecurityTestSecRule/Basic/Longer/KEY/123"));
    var result = new TestValidationResult(data);

    data.setName(new Name("/SecurityTestSecRule/Basic/Data1"));
    result.checkPolicy(validator);
    assert.ok(result.calledFailure_ && !result.calledContinue_);

    data.setName(new Name("/SecurityTestSecRule/Basic/Longer/Data2"));
    result.checkPolicy(validator);
    assert.ok(result.calledContinue_ && !result.calledFailure_);

    KeyLocator.getFromSignature(data.getSignature()).setKeyName
      (new Name("/SecurityTestSecRule/Basic/KEY/123"));

    data.setName(new Name("/SecurityTestSecRule/Basic/Data1"));
    result.checkPolicy(validator);
    assert.ok(result.calledContinue_ && !result.calledFailure_);

    data.setName(new Name("/SecurityTestSecRule/Basic/Longer/Data2"));
    result.checkPolicy(validator);
    assert.ok(result.calledContinue_ && !result.calledFailure_);
  });

  it('HyperRelation', function() {
    // Set up the validator.
    var fetcher = new CertificateFetcherOffline();
    var validator = new ValidatorConfig(fetcher);
    validator.load
      (path.join(this.policyConfigDirectory_, "hyperrelation_ruleset.conf"));

    // Set up a Data packet and result object.
    var data = new Data();
    KeyLocator.getFromSignature(data.getSignature()).setType(KeyLocatorType.KEYNAME);
    var result = new TestValidationResult(data);

    data.setName(new Name("/SecurityTestSecRule/Basic/Longer/Data2"));

    KeyLocator.getFromSignature(data.getSignature()).setKeyName
      (new Name("/SecurityTestSecRule/Basic/Longer/KEY/123"));
    result.checkPolicy(validator);
    assert.ok(result.calledFailure_ && !result.calledContinue_);
    KeyLocator.getFromSignature(data.getSignature()).setKeyName
      (new Name("/SecurityTestSecRule/Basic/KEY/123"));
    result.checkPolicy(validator);
    assert.ok(result.calledFailure_ && !result.calledContinue_);

    data.setName(new Name("/SecurityTestSecRule/Basic/Other/Data1"));

    KeyLocator.getFromSignature(data.getSignature()).setKeyName
      (new Name("/SecurityTestSecRule/Basic/Longer/KEY/123"));
    result.checkPolicy(validator);
    assert.ok(result.calledFailure_ && !result.calledContinue_);
    KeyLocator.getFromSignature(data.getSignature()).setKeyName
      (new Name("/SecurityTestSecRule/Basic/KEY/123"));
    result.checkPolicy(validator);
    assert.ok(result.calledFailure_ && !result.calledContinue_);
  });
});
