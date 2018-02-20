/**
 * Copyright (C) 2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/v2/validator-config/name-relation.cpp
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
var ValidatorConfigError = require('../../validator-config-error.js').ValidatorConfigError;

/**
 * ConfigNameRelation defines the ConfigNameRelation.Relation enum and static
 * methods to work with name relations for the ValidatorConfig.
 * @constructor
 */
var ConfigNameRelation = function ConfigNameRelation()
{
};

exports.ConfigNameRelation = ConfigNameRelation;

ConfigNameRelation.Relation = function ConfigNameRelationRelation() {};

ConfigNameRelation.Relation.EQUAL = 0;
ConfigNameRelation.Relation.IS_PREFIX_OF = 1;
ConfigNameRelation.Relation.IS_STRICT_PREFIX_OF = 2;

/**
 * Get a string representation of the Relation enum.
 * @param {number} relation The value for the ConfigNameRelation.Relation enum.
 * @return {String} The string representation.
 */
ConfigNameRelation.toString = function(relation)
{
  if (relation == ConfigNameRelation.Relation.EQUAL)
    return "equal";
  else if (relation == ConfigNameRelation.Relation.IS_PREFIX_OF)
    return "is-prefix-of";
  else if (relation == ConfigNameRelation.Relation.IS_STRICT_PREFIX_OF)
    return "is-strict-prefix-of";
  else
    // We don't expect this to happen.
    return "";
};

/**
 * Check whether name1 and name2 satisfy the relation.
 * @param {number} relation The value for the ConfigNameRelation.Relation enum.
 * @param {Name} name1 The first name to check.
 * @param {Name} name2 The second name to check.
 * @return {boolean} True if the names satisfy the relation.
 */
ConfigNameRelation.checkNameRelation = function(relation, name1, name2)
{
  if (relation == ConfigNameRelation.Relation.EQUAL)
    return name1.equals(name2);
  else if (relation == ConfigNameRelation.Relation.IS_PREFIX_OF)
    return name1.isPrefixOf(name2);
  else if (relation == ConfigNameRelation.Relation.IS_STRICT_PREFIX_OF)
    return name1.isPrefixOf(name2) && name1.size() < name2.size();
  else
    // We don't expect this to happen.
    return false;
};

/**
 * Convert relationString to a Relation enum.
 * @param {String} relationString the string to convert.
 * @return {number} The value for the ConfigNameRelation.Relation enum.
 * @throws ValidatorConfigError if relationString cannot be converted.
 */
ConfigNameRelation.getNameRelationFromString = function(relationString)
{
  if (relationString.toLowerCase() == "equal")
    return ConfigNameRelation.Relation.EQUAL;
  else if (relationString.toLowerCase() == "is-prefix-of")
    return ConfigNameRelation.Relation.IS_PREFIX_OF;
  else if (relationString.toLowerCase() == "is-strict-prefix-of")
    return ConfigNameRelation.Relation.IS_STRICT_PREFIX_OF;
  else
    throw new ValidatorConfigError(new Error
      ("Unsupported relation: " + relationString));
};
