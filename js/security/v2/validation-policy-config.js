/**
 * Copyright (C) 2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/validation-policy-config.cpp
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
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

/** @ignore */
var BoostInfoParser = require('../../util/boost-info-parser.js').BoostInfoParser; /** @ignore */
var CertificateRequest = require('./certificate-request.js').CertificateRequest; /** @ignore */
var ValidatorConfigError = require('../validator-config-error.js').ValidatorConfigError; /** @ignore */
var ValidationError = require('./validation-error.js').ValidationError; /** @ignore */
var CertificateV2 = require('./certificate-v2.js').CertificateV2; /** @ignore */
var ConfigRule = require('./validator-config/config-rule.js').ConfigRule; /** @ignore */
var Data = require('../../data.js').Data; /** @ignore */
var Interest = require('../../interest.js').Interest; /** @ignore */
var ValidationPolicy = require('./validation-policy.js').ValidationPolicy;

/**
 * ValidationPolicyConfig implements a validator which can be set up via a
 * configuration file. For command Interest validation, this policy must be
 * combined with ValidationPolicyCommandInterest in order to guard against
 * replay attacks.
 * @note This policy does not support inner policies (a sole policy or a
 * terminal inner policy).
 * See https://named-data.net/doc/ndn-cxx/current/tutorials/security-validator-config.html
 * @constructor
 */
var ValidationPolicyConfig = function ValidationPolicyConfig()
{
  // Call the base constructor.
  ValidationPolicy.call(this);

  this.shouldBypass_ = false;
  this.isConfigured_ = false;
  this.dataRules_ = [];     // of ConfigRule
  this.interestRules_ = []; // of ConfigRule
};

ValidationPolicyConfig.prototype = new ValidationPolicy();
ValidationPolicyConfig.prototype.name = "ValidationPolicyConfig";

exports.ValidationPolicyConfig = ValidationPolicyConfig;

/**
 * There are three forms of load:
 * load(filePath) - Load the configuration from the given config file.
 * load(input, inputName) - Load the configuration from the given input string.
 * load(configSection, inputName) - Load the configuration from the given
 * configSection.
 * Each of these forms of load replaces any existing configuration.
 * @param {String} filePath The The path of the config file.
 * @param {String} input The contents of the configuration rules, with lines
 * separated by "\n" or "\r\n".
 * @param {BoostInfoTree} configSection The configuration section loaded from
 * the config file. It should have one "validator" section.
 * @param {String} inputName Used for log messages, etc.
 */
ValidationPolicyConfig.prototype.load = function
  (filePathOrInputOrConfigSection, inputName)
{
  if (typeof filePathOrInputOrConfigSection === 'string' &&
      inputName == undefined) {
    var filePath = filePathOrInputOrConfigSection;

    var parser = new BoostInfoParser();
    parser.read(filePath);
    this.load(parser.getRoot(), filePath);
  }
  else if (typeof filePathOrInputOrConfigSection === 'string' &&
      typeof inputName === 'string') {
    var input = filePathOrInputOrConfigSection;

    var parser = new BoostInfoParser();
    parser.read(input, inputName);
    this.load(parser.getRoot(), inputName);
  }
  else {
    var configSection = filePathOrInputOrConfigSection;

    if (this.isConfigured_) {
      // Reset the previous configuration.
      this.shouldBypass_ = false;
      this.dataRules_ = [];
      this.interestRules_ = [];

      this.validator_.resetAnchors();
      this.validator_.resetVerifiedCertificates();
    }
    this.isConfigured_ = true;

    var validatorList = configSection.get("validator");
    if (validatorList.length != 1)
      throw new ValidatorConfigError(new Error
        ("ValidationPolicyConfig: Expected one validator section"));
    var validatorSection = validatorList[0];

    // Get the rules.
    var ruleList = validatorSection.get("rule");
    for (var i = 0; i < ruleList.length; ++i) {
      var rule = ConfigRule.create(ruleList[i]);
      if (rule.getIsForInterest())
        this.interestRules_.push(rule);
      else
        this.dataRules_.push(rule);
    }

    // Get the trust anchors.
    var trustAnchorList = validatorSection.get("trust-anchor");
    for (var i = 0; i < trustAnchorList.length; ++i)
      this.processConfigTrustAnchor_(trustAnchorList[i], inputName);
  }
};

/**
 * @param {Data|Interest} dataOrInterest
 * @param {ValidationState} state
 * @param {function} continueValidation
 */
ValidationPolicyConfig.prototype.checkPolicy = function
  (dataOrInterest, state, continueValidation)
{
  if (this.hasInnerPolicy())
    throw new ValidatorConfigError(new Error
      ("ValidationPolicyConfig must be a terminal inner policy"));

  if (this.shouldBypass_) {
    continueValidation(null, state);
    return;
  }

  var keyLocatorName = ValidationPolicy.getKeyLocatorName(dataOrInterest, state);
  if (state.isOutcomeFailed())
    // Already called state.fail() .
    return;

  if (dataOrInterest instanceof Data) {
    var data = dataOrInterest;

    for (var i = 0; i < this.dataRules_.length; ++i) {
      var rule = this.dataRules_[i];

      if (rule.match(false, data.getName())) {
        if (rule.check(false, data.getName(), keyLocatorName, state)) {
          continueValidation
            (new CertificateRequest(new Interest(keyLocatorName)), state);
          return;
        }
        else
          // rule.check failed and already called state.fail() .
          return;
      }
    }

    state.fail(new ValidationError(ValidationError.POLICY_ERROR,
      "No rule matched for data `" + data.getName().toUri() + "`"));
  }
  else {
    var interest = dataOrInterest;

    for (var i = 0; i < this.interestRules_.length; ++i) {
      var rule = this.interestRules_[i];

      if (rule.match(true, interest.getName())) {
        if (rule.check(true, interest.getName(), keyLocatorName, state)) {
          continueValidation
            (new CertificateRequest(new Interest(keyLocatorName)), state);
          return;
        }
        else
          // rule.check failed and already called state.fail() .
          return;
      }
    }

    state.fail(new ValidationError(ValidationError.POLICY_ERROR,
      "No rule matched for interest `" + interest.getName().toUri() + "`"));
  }
};

/**
 * Process the trust-anchor configuration section and call
 * validator_.loadAnchor as needed.
 * @param {BoostInfoTree} configSection The section containing the definition of
 * the trust anchor, e.g. one of "validator.trust-anchor".
 * @param {String} inputName Used for log messages, etc.
 */
ValidationPolicyConfig.prototype.processConfigTrustAnchor_ = function
  (configSection, inputName)
{
  var anchorType = configSection.getFirstValue("type");
  if (anchorType == null)
    throw new ValidatorConfigError(new Error("Expected <trust-anchor.type>"));

  if (anchorType.toLowerCase() == "file") {
    // Get trust-anchor.file .
    var fileName = configSection.getFirstValue("file-name");
    if (fileName == null)
      throw new ValidatorConfigError(new Error("Expected <trust-anchor.file-name>"));

    var refreshPeriod = ValidationPolicyConfig.getRefreshPeriod_(configSection);
    this.validator_.loadAnchor(fileName, fileName, refreshPeriod, false);

    return;
  }
  else if (anchorType.toLowerCase() == "base64") {
    // Get trust-anchor.base64-string .
    var base64String = configSection.getFirstValue("base64-string");
    if (base64String == null)
      throw new ValidatorConfigError(new Error
        ("Expected <trust-anchor.base64-string>"));

    var encoding = new Buffer(base64String, 'base64');
    var certificate = new CertificateV2();
    try {
      certificate.wireDecode(encoding);
    } catch (ex) {
      throw new ValidatorConfigError(new Error
        ("Cannot decode certificate from base64-string: " + ex));
    }
    this.validator_.loadAnchor("", certificate);

    return;
  }
  else if (anchorType.toLowerCase() == "dir") {
    // Get trust-anchor.dir .
    var dirString = configSection.getFirstValue("dir");
    if (dirString == null)
      throw new ValidatorConfigError(new Error("Expected <trust-anchor.dir>"));

    var refreshPeriod = ValidationPolicyConfig.getRefreshPeriod_(configSection);
    this.validator_.loadAnchor(dirString, dirString, refreshPeriod, true);

    return;
  }
  else if (anchorType.toLowerCase() == "any")
    this.shouldBypass_ = true;
  else
    throw new ValidatorConfigError(new Error("Unsupported trust-anchor.type"));
};

/**
 * Get the "refresh" value. If the value is 9, return a period of one hour.
 * @param {BoostInfoTree} configSection The section containing the definition of
 * the trust anchor, e.g. one of "validator.trust-anchor".
 * @return {number} The refresh period in milliseconds. However if there is no
 * "refresh" value, return a large number (effectively no refresh).
 */
ValidationPolicyConfig.getRefreshPeriod_ = function(configSection)
{
  var refreshString = configSection.getFirstValue("refresh");
  if (refreshString == null)
    // Return a large value (effectively no refresh).
    return 1e14;

  var refreshSeconds = 0.0;
  var refreshMatch = refreshString.match(/(\d+)([hms])/);;
  if (refreshMatch != null) {
    refreshSeconds = parseInt(refreshMatch[1]);
    if (refreshMatch[2] != 's') {
      refreshSeconds *= 60;
      if (refreshMatch[2] != 'm')
        refreshSeconds *= 60;
    }
  }

  if (refreshSeconds == 0.0)
    // Use an hour instead of 0.
    return 3600 * 1000.0;
  else
    // Convert from seconds to milliseconds.
    return refreshSeconds * 1000.0;
};
