/**
 * Copyright (C) 2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/validator-config/filter.cpp
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
var ConfigNameRelation = require('./config-name-relation.js').ConfigNameRelation; /** @ignore */
var NdnRegexTopMatcher = require('../../../util/regex/ndn-regex-top-matcher.js').NdnRegexTopMatcher; /** @ignore */
var ValidatorConfigError = require('../../validator-config-error.js').ValidatorConfigError;

/**
 * ConfigFilter is an abstract base class for RegexNameFilter, etc. used by
 * ValidatorConfig. The ValidatorConfig class consists of a set of rules.
 * The Filter class is a part of a rule and is used to match a packet.
 * Matched packets will be checked against the checkers defined in the rule.
 * @constructor
 */
var ConfigFilter = function ConfigFilter()
{
};

exports.ConfigFilter = ConfigFilter;

/**
 * Call the virtual matchName method based on the packet type.
 * @param {boolean} isForInterest True if packetName is for an Interest, false
 * if for a Data packet.
 * @param {Name} packetName The packet name. For a signed interest, the last two
 * components are skipped but not removed.
 * @return {boolean} True for a match.
 */
ConfigFilter.prototype.match = function(isForInterest, packetName)
{
  if (isForInterest) {
    var signedInterestMinSize = 2;

    if (packetName.size() < signedInterestMinSize)
      return false;

    return this.matchName(packetName.getPrefix(-signedInterestMinSize));
  }
  else
    // Data packet.
    return this.matchName(packetName);
};

/**
 * Create a filter from the configuration section.
 * @param {BoostInfoTree} configSection The section containing the definition of
 * the filter, e.g. one of "validator.rule.filter".
 * @return {ConfigFilter} A new filter created from the configuration section.
 */
ConfigFilter.create = function(configSection)
{
  var filterType = configSection.getFirstValue("type");
  if (filterType == null)
    throw new ValidatorConfigError(new Error("Expected <filter.type>"));

  if (filterType.toLowerCase() == "name")
    return ConfigFilter.createNameFilter_(configSection);
  else
    throw new ValidatorConfigError(new Error
      ("Unsupported filter.type: " + filterType));
};

/**
 * Implementation of the check for match.
 * @param {Name} packetName The packet name, which is already stripped of
 * signature components if this is a signed Interest name.
 * @return {boolean} True for a match.
 */
ConfigFilter.prototype.matchName = function(packetName)
{
  throw new Error("ConfigFilter.matchName is not implemented");
};

/**
 * This is a helper for create() to create a filter from the configuration
 * section which is type "name".
 * @param {BoostInfoTree} configSection The section containing the definition of
 * the filter.
 * @return {ConfigFilter} A new filter created from the configuration section.
 */
ConfigFilter.createNameFilter_ = function(configSection)
{
  var nameUri = configSection.getFirstValue("name");
  if (nameUri != null) {
    // Get the filter.name.
    var name = new Name(nameUri);

    // Get the filter.relation.
    var relationValue = configSection.getFirstValue("relation");
    if (relationValue == null)
      throw new ValidatorConfigError(new Error("Expected <filter.relation>"));

    var relation = ConfigNameRelation.getNameRelationFromString(relationValue);

    return new ConfigRelationNameFilter(name, relation);
  }

  var regexString = configSection.getFirstValue("regex");
  if (regexString != null) {
    try {
      return new ConfigRegexNameFilter(regexString);
    }
    catch (ex) {
      throw new ValidatorConfigError(new Error
        ("Wrong filter.regex: " + regexString));
    }
  }

  throw new ValidatorConfigError(new Error("Wrong filter(name) properties"));
};

/**
 * ConfigRelationNameFilter extends ConfigFilter to check that the name is in
 * the given relation to the packet name.
 * The configuration
 * "filter
 * {
 *   type name
 *   name /example
 *   relation is-prefix-of
 * }"
 * creates ConfigRelationNameFilter("/example",
 *   ConfigNameRelation.Relation.IS_PREFIX_OF) .
 *
 * Create a ConfigRelationNameFilter for the given values.
 * @param {Name} name The relation name, which is copied.
 * @param {number} relation The relation type as a
 * ConfigNameRelation.Relation enum.
 * @constructor
 */
var ConfigRelationNameFilter = function ConfigRelationNameFilter
  (name, relation)
{
  // Call the base constructor.
  ConfigFilter.call(this);

  // Copy the Name.
  this.name_ = new Name(name);
  this.relation_ = relation;
};

ConfigRelationNameFilter.prototype = new ConfigFilter();
ConfigRelationNameFilter.prototype.name = "ConfigRelationNameFilter";

exports.ConfigRelationNameFilter = ConfigRelationNameFilter;

/**
 * Implementation of the check for match.
 * @param {Name} packetName The packet name, which is already stripped of
 * signature components if this is a signed Interest name.
 * @return {boolean} True for a match.
 */
ConfigRelationNameFilter.prototype.matchName = function(packetName)
{
  return ConfigNameRelation.checkNameRelation
    (this.relation_, this.name_, packetName);
};

/**
 * ConfigRegexNameFilter extends ConfigFilter to check that the packet name
 * matches the specified regular expression.
 * The configuration
 * {@code
 * "filter
 * {
 *   type name
 *   regex ^[^<KEY>]*<KEY><>*<ksk-.*>$
 * }"}
 * creates
 * {@code ConfigRegexNameFilter("^[^<KEY>]*<KEY><>*<ksk-.*>$") }.
 *
 * Create a ConfigRegexNameFilter from the regex string.
 * @param {String} regexString The regex string.
 * @constructor
 */
var ConfigRegexNameFilter = function ConfigRegexNameFilter(regexString)
{
  // Call the base constructor.
  ConfigFilter.call(this);

  this.regex_ = new NdnRegexTopMatcher(regexString);
};

ConfigRegexNameFilter.prototype = new ConfigFilter();
ConfigRegexNameFilter.prototype.name = "ConfigRegexNameFilter";

exports.ConfigRegexNameFilter = ConfigRegexNameFilter;

/**
 * Implementation of the check for match.
 * @param {Name} packetName The packet name, which is already stripped of
 * signature components if this is a signed Interest name.
 * @return {boolean} True for a match.
 */
ConfigRegexNameFilter.prototype.matchName = function(packetName)
{
  return this.regex_.match(packetName);
};
