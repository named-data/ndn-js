/**
 * Copyright (C) 2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/validator-config/checker.cpp
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
var Name = require('../../../name.js').Name; /** @ignore */
var PibKey = require('../../pib/pib-key.js').PibKey; /** @ignore */
var ValidationError = require('../validation-error.js').ValidationError; /** @ignore */
var ConfigNameRelation = require('./config-name-relation.js').ConfigNameRelation; /** @ignore */
var NdnRegexTopMatcher = require('../../../util/regex/ndn-regex-top-matcher.js').NdnRegexTopMatcher; /** @ignore */
var ValidatorConfigError = require('../../validator-config-error.js').ValidatorConfigError;

/**
 * A ConfigChecker is an abstract base class for ConfigNameRelationChecker, etc.
 * used by ValidatorConfig to check if a packet name and KeyLocator satisfy the
 * conditions in a configuration section.
 * @constructor
 */
var ConfigChecker = function ConfigChecker()
{
};

exports.ConfigChecker = ConfigChecker;

/**
 * Check if the packet name ane KeyLocator name satisfy this checker's
 * conditions.
 * @param {boolean} isForInterest True if packetName is for an Interest, false
 * if for a Data packet.
 * @param {Name} packetName The packet name. For a signed interest, the last two
 * components are skipped but not removed.
 * @param {Name} keyLocatorName The KeyLocator's name.
 * @param {ValidationState} state This calls state.fail() if the packet is
 * invalid.
 * @return {boolean} True if further signature verification is needed, or false
 * if the packet is immediately determined to be invalid in which case this
 * calls state.fail() with the proper code and message.
 */
ConfigChecker.prototype.check = function
  (isForInterest, packetName, keyLocatorName, state)
{
  if (isForInterest) {
    var signedInterestMinSize = 2;

    if (packetName.size() < signedInterestMinSize)
      return false;

    return this.checkNames
      (packetName.getPrefix(-signedInterestMinSize), keyLocatorName, state);
  }
  else
    return this.checkNames(packetName, keyLocatorName, state);
};

/**
 * Create a checker from the configuration section.
 * @param {BoostInfoTree} configSection The section containing the definition of
 * the checker, e.g. one of "validation.rule.checker".
 * @return {ConfigChecker} A new checker created from the configuration section.
 */
ConfigChecker.create = function(configSection)
{
  // Get checker.type.
  var checkerType = configSection.getFirstValue("type");
  if (checkerType == null)
    throw new ValidatorConfigError(new Error("Expected <checker.type>"));

  if (checkerType.toLowerCase() == "customized")
    return ConfigChecker.createCustomizedChecker_(configSection);
  else if (checkerType.toLowerCase() == "hierarchical")
    return ConfigChecker.createHierarchicalChecker_(configSection);
  else
    throw new ValidatorConfigError(new Error
      ("Unsupported checker type: " + checkerType));
};

/**
 * Check if the packet name ane KeyLocator name satisfy this checker's
 * conditions.
 * @param {Name} packetName The packet name, which is already stripped of
 * signature components if this is a signed Interest name.
 * @param {Name} keyLocatorName The KeyLocator's name.
 * @param {ValidationState} state This calls state.fail() if the packet is
 * invalid.
 * @return {boolean} True if further signature verification is needed, or false
 * if the packet is immediately determined to be invalid in which case this
 * calls state.fail() with the proper code and message.
 */
ConfigChecker.prototype.checkNames = function
  (packetName, keyLocatorName, state)
{
  throw new Error("ConfigChecker.checkNames is not implemented");
};

/**
 * @param {BoostInfoTree} configSection
 * @return {ConfigChecker}
 */
ConfigChecker.createCustomizedChecker_ = function( configSection)
{
  // Ignore sig-type.
  // Get checker.key-locator .
  keyLocatorSection = configSection.get("key-locator");
  if (keyLocatorSection.length != 1)
    throw new ValidatorConfigError(new Error("Expected one <checker.key-locator>"));

  return ConfigChecker.createKeyLocatorChecker_(keyLocatorSection[0]);
};

/**
 * @param {BoostInfoTree} configSection
 * @return {ConfigChecker}
 */
ConfigChecker.createHierarchicalChecker_ = function(configSection)
{
  // Ignore sig-type.
  return new ConfigHyperRelationChecker
    ("^(<>*)$",        "\\1",
     "^(<>*)<KEY><>$", "\\1",
     ConfigNameRelation.Relation.IS_PREFIX_OF);
};

/**
 * @param {BoostInfoTree} configSection
 * @return {ConfigChecker}
 */
ConfigChecker.createKeyLocatorChecker_ = function(configSection)
{
  // Get checker.key-locator.type .
  var keyLocatorType = configSection.getFirstValue("type");
  if (keyLocatorType == null)
    throw new ValidatorConfigError(new Error("Expected <checker.key-locator.type>"));

  if (keyLocatorType.toLowerCase() == "name")
    return ConfigChecker.createKeyLocatorNameChecker_(configSection);
  else
    throw new ValidatorConfigError(new Error
      ("Unsupported checker.key-locator.type: " + keyLocatorType));
};

/**
 * @param {BoostInfoTree} configSection
 * @return {ConfigChecker}
 */
ConfigChecker.createKeyLocatorNameChecker_ = function(configSection)
{
  var nameUri = configSection.getFirstValue("name");
  if (nameUri != null) {
    var name = new Name(nameUri);

    var relationValue = configSection.getFirstValue("relation");
    if (relationValue == null)
      throw new ValidatorConfigError(new Error
        ("Expected <checker.key-locator.relation>"));

    relation = ConfigNameRelation.getNameRelationFromString(relationValue);
    return new ConfigNameRelationChecker(name, relation);
  }

  var regexString = configSection.getFirstValue("regex");
  if (regexString != null) {
    try {
      return new ConfigRegexChecker(regexString);
    }
    catch (ex) {
      throw new ValidatorConfigError(new Error
        ("Invalid checker.key-locator.regex: " + regexString));
    }
  }

  var hyperRelationList = configSection.get("hyper-relation");
  if (hyperRelationList.length == 1) {
    var hyperRelation = hyperRelationList[0];

    // Get k-regex.
    var keyRegex = hyperRelation.getFirstValue("k-regex");
    if (keyRegex == null)
      throw new ValidatorConfigError(new Error
        ("Expected <checker.key-locator.hyper-relation.k-regex>"));

    // Get k-expand.
    var keyExpansion = hyperRelation.getFirstValue("k-expand");
    if (keyExpansion == null)
      throw new ValidatorConfigError(new Error
        ("Expected <checker.key-locator.hyper-relation.k-expand"));

    // Get h-relation.
    var hyperRelationString = hyperRelation.getFirstValue("h-relation");
    if (hyperRelationString == null)
      throw new ValidatorConfigError(new Error
        ("Expected <checker.key-locator.hyper-relation.h-relation>"));

    // Get p-regex.
    var packetNameRegex = hyperRelation.getFirstValue("p-regex");
    if (packetNameRegex == null)
      throw new ValidatorConfigError(new Error
        ("Expected <checker.key-locator.hyper-relation.p-regex>"));

    // Get p-expand.
    var packetNameExpansion = hyperRelation.getFirstValue("p-expand");
    if (packetNameExpansion == null)
      throw new ValidatorConfigError(new Error
        ("Expected <checker.key-locator.hyper-relation.p-expand>"));

    var relation =
      ConfigNameRelation.getNameRelationFromString(hyperRelationString);

    try {
      return new ConfigHyperRelationChecker
        (packetNameRegex, packetNameExpansion, keyRegex, keyExpansion, relation);
    }
    catch (ex) {
      throw new ValidatorConfigError(new Error
        ("Invalid regex for key-locator.hyper-relation"));
    }
  }

  throw new ValidatorConfigError(new Error("Unsupported checker.key-locator"));
};

/**
 * ConfigNameRelationChecker extends ConfigChecker.
 * @param {Name} name
 * @param {number} relation The value for the ConfigNameRelation.Relation enum.
 * @constructor
 */
var ConfigNameRelationChecker = function ConfigNameRelationChecker(name, relation)
{
  // Call the base constructor.
  ConfigChecker.call(this);

  this.name_ = name;
  this.relation_ = relation;
};

ConfigNameRelationChecker.prototype = new ConfigChecker();
ConfigNameRelationChecker.prototype.name = "ConfigNameRelationChecker";

exports.ConfigNameRelationChecker = ConfigNameRelationChecker;

/**
 * @param {Name} packetName
 * @param {Name} keyLocatorName
 * @param {ValidationState} state
 * @return {boolean}
 */
ConfigNameRelationChecker.prototype.checkNames = function
  (packetName, keyLocatorName, state)
{
  // packetName is not used in this check.

  var identity = PibKey.extractIdentityFromKeyName(keyLocatorName);
  var result = ConfigNameRelation.checkNameRelation
    (this.relation_, this.name_, identity);
  if (!result)
    state.fail(new ValidationError(ValidationError.POLICY_ERROR,
      "KeyLocator check failed: name relation " + this.name_.toUri() + " " +
      ConfigNameRelation.toString(this.relation_) + " for packet " +
      packetName.toUri() + " is invalid (KeyLocator=" +
      keyLocatorName.toUri() + ", identity=" + identity.toUri() + ")"));

  return result;
};

/**
 * ConfigRegexChecker extends ConfigChecker.
 * @param {String} regexString
 * @constructor
 */
var ConfigRegexChecker = function ConfigRegexChecker(regexString)
{
  // Call the base constructor.
  ConfigChecker.call(this);

  this.regex_ = new NdnRegexTopMatcher(regexString);
};

ConfigRegexChecker.prototype = new ConfigChecker();
ConfigRegexChecker.prototype.name = "ConfigRegexChecker";

exports.ConfigRegexChecker = ConfigRegexChecker;

/**
 * @param {Name} packetName
 * @param {Name} keyLocatorName
 * @param {ValidationState} state
 * @return {boolean}
 */
ConfigRegexChecker.prototype.checkNames = function
  (packetName, keyLocatorName, state)
{
  var result = this.regex_.match(keyLocatorName);
  if (!result)
    state.fail(new ValidationError(ValidationError.POLICY_ERROR,
      "KeyLocator check failed: regex " + this.regex_.getExpr() + " for packet " +
      packetName.toUri() + " is invalid (KeyLocator=" + keyLocatorName.toUri() +
      ")"));

  return result;
};

/**
 * ConfigHyperRelationChecker extends ConfigChecker.
 * @param {String} packetNameRegexString
 * @param {String} packetNameExpansion
 * @param {String} keyNameRegexString
 * @param {String} keyNameExpansion
 * @param {number} hyperRelation The value for the ConfigNameRelation.Relation enum.
 * @constructor
 */
var ConfigHyperRelationChecker = function ConfigHyperRelationChecker
  (packetNameRegexString, packetNameExpansion, keyNameRegexString,
   keyNameExpansion, hyperRelation)
{
  // Call the base constructor.
  ConfigChecker.call(this);

  this.packetNameRegex_ = new NdnRegexTopMatcher(packetNameRegexString);
  this.packetNameExpansion_ = packetNameExpansion;
  this.keyNameRegex_ = new NdnRegexTopMatcher(keyNameRegexString);
  this.keyNameExpansion_ = keyNameExpansion;
  this.hyperRelation_ = hyperRelation;
};

ConfigHyperRelationChecker.prototype = new ConfigChecker();
ConfigHyperRelationChecker.prototype.name = "ConfigHyperRelationChecker";

exports.ConfigHyperRelationChecker = ConfigHyperRelationChecker;

/**
 * @param {Name} packetName
 * @param {Name} keyLocatorName
 * @param {ValidationState} state
 * @return {boolean}
 */
ConfigHyperRelationChecker.prototype.checkNames = function
  (packetName, keyLocatorName, state)
{
  if (!this.packetNameRegex_.match(packetName)) {
    state.fail(new ValidationError(ValidationError.POLICY_ERROR,
      "The packet " + packetName.toUri() + " (KeyLocator=" +
      keyLocatorName.toUri() +
      ") does not match the hyper relation packet name regex " +
      this.packetNameRegex_.getExpr()));
    return false;
  }
  if (!this.keyNameRegex_.match(keyLocatorName)) {
    state.fail(new ValidationError(ValidationError.POLICY_ERROR,
      "The packet " + packetName.toUri() + " (KeyLocator=" +
      keyLocatorName.toUri() +
      ") does not match the hyper relation key name regex " +
      this.keyNameRegex_.getExpr()));
    return false;
  }

  var keyNameMatchExpansion = this.keyNameRegex_.expand(this.keyNameExpansion_);
  var packetNameMatchExpansion =
    this.packetNameRegex_.expand(this.packetNameExpansion_);
  var result = ConfigNameRelation.checkNameRelation
    (this.hyperRelation_, keyNameMatchExpansion, packetNameMatchExpansion);
  if (!result)
    state.fail(new ValidationError(ValidationError.POLICY_ERROR,
      "KeyLocator check failed: hyper relation " +
      ConfigNameRelation.toString(this.hyperRelation_) + " packet name match=" +
      packetNameMatchExpansion.toUri() + ", key name match=" +
      keyNameMatchExpansion.toUri() + " of packet " + packetName.toUri() +
      " (KeyLocator=" + keyLocatorName.toUri() + ") is invalid"));

  return result;
};
