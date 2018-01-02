/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Yingdi Yu <http://irl.cs.ucla.edu/~yingdi/>
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
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
var Name = require('../../name.js').Name; /** @ignore */
var NdnRegexMatcherBase = require('./ndn-regex-matcher-base.js').NdnRegexMatcherBase;

/**
 * Create an NdnRegexPseudoMatcher.
 * @constructor
 */
var NdnRegexPseudoMatcher = function NdnRegexPseudoMatcher()
{
  // Call the base constructor.
  NdnRegexMatcherBase.call
    (this, "", NdnRegexMatcherBase.NdnRegexExprType.PSEUDO);
};

NdnRegexPseudoMatcher.prototype = new NdnRegexMatcherBase();
NdnRegexPseudoMatcher.prototype.name = "NdnRegexPseudoMatcher";

exports.NdnRegexPseudoMatcher = NdnRegexPseudoMatcher;

NdnRegexPseudoMatcher.prototype.compile_ = function()
{
};

/**
 * @param {string} value
 */
NdnRegexPseudoMatcher.prototype.setMatchResult = function(value)
{
  this.matchResult_.push(new Name.Component(value));
};

NdnRegexPseudoMatcher.prototype.resetMatchResult = function()
{
  this.matchResult_ = [];
};
