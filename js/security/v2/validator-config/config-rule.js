/**
 * Copyright (C) 2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/validator-config/rule.cpp
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
var ConfigChecker = require('./config-checker.js').ConfigChecker; /** @ignore */
var ConfigFilter = require('./config-filter.js').ConfigFilter; /** @ignore */
var ValidatorConfigError = require('../../validator-config-error.js').ValidatorConfigError; /** @ignore */
var LOG = require('../../../log.js').Log.LOG;

/**
 * A ConfigRule represents a rule configuration section, used by ConfigValidator.
 *
 * Create a ConfigRule with empty filters and checkers.
 * @param {String} id The rule ID from the configuration section.
 * @param {boolean} isForInterest True if the rule is for an Interest packet,
 * false if it is for a Data packet.
 * @constructor
 */
var ConfigRule = function ConfigRule(id, isForInterest)
{
  this.id_ = id;
  this.isForInterest_ = isForInterest;
  this.filters_ = [];  // of ConfigFilter
  this.checkers_ = []; // of ConfigChecker
};

exports.ConfigRule = ConfigRule;

/**
 * Get the rule ID.
 * @return {String} The rule ID.
 */
ConfigRule.prototype.getId = function() { return this.id_; };

/**
 * Get the isForInterest flag.
 * @return {boolean} True if the rule is for an Interest packet, false if it is
 * for a Data packet.
 */
ConfigRule.prototype.getIsForInterest = function() { return this.isForInterest_; };

/**
 * Add the ConfigFilter to the list of filters.
 * @param {ConfigFilter} filter The ConfigFilter.
 */
ConfigRule.prototype.addFilter = function(filter)
{
  this.filters_.push(filter);
};

/**
 * Add the ConfigChecker to the list of checkers.
 * @param {ConfigChecker} checker The ConfigChecker.
 */
ConfigRule.prototype.addChecker = function(checker)
{
  this.checkers_.push(checker);
};

/**
 * Check if the packet name matches the rule's filter.
 * If no filters were added, the rule matches everything.
 * @param {boolean} isForInterest True if packetName is for an Interest, false
 * if for a Data packet.
 * @param {Name} packetName The packet name. For a signed interest, the last two
 * components are skipped but not removed.
 * @return {boolean} True if at least one filter matches the packet name, false
 * if none of the filters match the packet name.
 * @throws ValidatorConfigError if the supplied isForInterest doesn't match the
 * one for which the rule is designed.
 */
ConfigRule.prototype.match = function(isForInterest, packetName)
{
  if (LOG > 3) console.log("Trying to match " + packetName.toUri());

  if (isForInterest != this.isForInterest_)
    throw new ValidatorConfigError(new Error
      ("Invalid packet type supplied ( " +
       (isForInterest ? "interest" : "data") + " != " +
       (this.isForInterest_ ? "interest" : "data") + ")"));

  if (this.filters_.length == 0)
    return true;

  var result = false;
  for (var i = 0; i < this.filters_.length; ++i) {
    result = (result || this.filters_[i].match(isForInterest, packetName));
    if (result)
      break;
  }

  return result;
};

/**
 * Check if the packet satisfies the rule's condition.
 * @param {boolean} isForInterest True if packetName is for an Interest, false
 * if for a Data packet.
 * @param {Name} packetName The packet name. For a signed interest, the last two
 * components are skipped but not removed.
 * @param {Name} keyLocatorName The KeyLocator's name.
 * @param {ValidationState} state This calls state.fail() if the packet is invalid.
 * @return {boolean} True if further signature verification is needed, or false
 * if the packet is immediately determined to be invalid in which case this
 * calls state.fail() with the proper code and message.
 * @throws ValidatorConfigError if the supplied isForInterest doesn't match the
 * one for which the rule is designed.
 */
ConfigRule.prototype.check = function
  (isForInterest, packetName, keyLocatorName, state)
{
  if (LOG > 3) console.log("Trying to check " +  packetName.toUri() +
    " with keyLocator " +keyLocatorName.toUri());

  if (isForInterest != this.isForInterest_)
    throw new ValidatorConfigError(new Error
      ("Invalid packet type supplied ( " +
       (isForInterest ? "interest" : "data") + " != " +
       (this.isForInterest_ ? "interest" : "data") + ")"));

  var hasPendingResult = false;
  for (var i = 0; i < this.checkers_.length; ++i) {
    var result = this.checkers_[i].check
      (isForInterest, packetName, keyLocatorName, state);
    if (!result)
      return result;
    hasPendingResult = true;
  }

  return hasPendingResult;
};

/**
 * Create a rule from configuration section.
 * @param {BoostInfoTree} configSection The section containing the definition of
 * the checker, e.g. one of "validator.rule".
 * @return {ConfigRule} A new ConfigRule created from the configuration
 */
ConfigRule.create = function(configSection)
{
  // Get rule.id .
  var ruleId = configSection.getFirstValue("id");
  if (ruleId == null)
    throw new ValidatorConfigError(new Error("Expecting <rule.id>"));

  // Get rule.for .
  var usage = configSection.getFirstValue("for");
  if (usage == null)
    throw new ValidatorConfigError(new Error
      ("Expecting <rule.for> in rule: " + ruleId));

  var isForInterest;
  if (usage.toLowerCase() == "data")
    isForInterest = false;
  else if (usage.toLowerCase() == "interest")
    isForInterest = true;
  else
    throw new ValidatorConfigError(new Error
      ("Unrecognized <rule.for>: " + usage + " in rule: " + ruleId));

  var rule = new ConfigRule(ruleId, isForInterest);

  // Get rule.filter(s)
  var filterList = configSection.get("filter");
  for (var i = 0; i < filterList.length; ++i)
    rule.addFilter(ConfigFilter.create(filterList[i]));

  // Get rule.checker(s)
  var checkerList = configSection.get("checker");
  for (var i = 0; i < checkerList.length; ++i)
    rule.addChecker(ConfigChecker.create(checkerList[i]));

  // Check other stuff.
  if (checkerList.length == 0)
    throw new ValidatorConfigError(new Error
      ("No <rule.checker> is specified in rule: " + ruleId));

  return rule;
};
