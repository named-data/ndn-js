/**
 * Copyright (C) 2015-2018 Regents of the University of California.
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
var Name = require('./name.js').Name; /** @ignore */
var NdnRegexTopMatcher = require('./util/regex/ndn-regex-top-matcher.js').NdnRegexTopMatcher;

/**
 * An InterestFilter holds a Name prefix and optional regex match expression for
 * use in Face.setInterestFilter.
 *
 * Create an InterestFilter to match any Interest whose name starts with the
 * given prefix. If the optional regexFilter is provided then the remaining
 * components match the regexFilter regular expression as described in doesMatch.
 * @param {InterestFilter|Name|string} prefix If prefix is another
 * InterestFilter copy its values. If prefix is a Name then this makes a copy of
 * the Name. Otherwise this creates a Name from the URI string.
 * @param {string} regexFilter (optional) The regular expression for matching
 * the remaining name components.
 * @constructor
 */
var InterestFilter = function InterestFilter(prefix, regexFilter)
{
  if (typeof prefix === 'object' && prefix instanceof InterestFilter) {
    // The copy constructor.
    var interestFilter = prefix;
    this.prefix = new Name(interestFilter.prefix);
    this.regexFilter = interestFilter.regexFilter;
    this.regexFilterPattern = interestFilter.regexFilterPattern;
  }
  else {
    this.prefix = new Name(prefix);
    if (regexFilter) {
      this.regexFilter = regexFilter;
      this.regexFilterPattern = InterestFilter.makePattern(regexFilter);
    }
    else {
      this.regexFilter = null;
      this.regexFilterPattern = null;
    }
  }
};

exports.InterestFilter = InterestFilter;

/**
 * Check if the given name matches this filter. Match if name starts with this
 * filter's prefix. If this filter has the optional regexFilter then the
 * remaining components match the regexFilter regular expression.
 * For example, the following InterestFilter:
 *
 *    InterestFilter("/hello", "<world><>+")
 *
 * will match all Interests, whose name has the prefix `/hello` which is
 * followed by a component `world` and has at least one more component after it.
 * Examples:
 *
 *    /hello/world/!
 *    /hello/world/x/y/z
 *
 * Note that the regular expression will need to match all remaining components
 * (e.g., there are implicit heading `^` and trailing `$` symbols in the
 * regular expression).
 * @param {Name} name The name to check against this filter.
 * @return {boolean} True if name matches this filter, otherwise false.
 */
InterestFilter.prototype.doesMatch = function(name)
{
  if (name.size() < this.prefix.size())
    return false;

  if (this.hasRegexFilter()) {
    // Perform a prefix match and regular expression match for the remaining
    // components.
    if (!this.prefix.match(name))
      return false;

    return new NdnRegexTopMatcher(this.regexFilterPattern).match
      (name.getSubName(this.prefix.size()));
  }
  else
    // Just perform a prefix match.
    return this.prefix.match(name);
};

/**
 * Get the prefix given to the constructor.
 * @return {Name} The prefix Name which you should not modify.
 */
InterestFilter.prototype.getPrefix = function() { return this.prefix; };

/**
 * Check if a regexFilter was supplied to the constructor.
 * @return {boolean} True if a regexFilter was supplied to the constructor.
 */
InterestFilter.prototype.hasRegexFilter = function()
{
  return this.regexFilter != null;
};

/**
 * Get the regex filter. This is only valid if hasRegexFilter() is true.
 * @return {string} The regular expression for matching the remaining name
 * components.
 */
InterestFilter.prototype.getRegexFilter = function() { return this.regexFilter; };

/**
 * If regexFilter doesn't already have them, add ^ to the beginning and $ to
 * the end since these are required by NdnRegexTopMatcher.
 * @param {string} regexFilter The regex filter.
 * @return {string} The regex pattern with ^ and $.
 */
InterestFilter.makePattern = function(regexFilter)
{
  var pattern = regexFilter;
  if (!(pattern.length >= 1 && pattern[0] == '^'))
    pattern = "^" + pattern;
  if (!(pattern.length >= 1 && pattern[-1] == '$'))
    pattern = pattern + "$";

  return pattern;
};
