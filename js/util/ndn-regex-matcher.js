/**
 * Copyright (C) 2014-2016 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From PyNDN ndn_regex.py by Adeola Bannis.
 * Originally from Yingdi Yu <http://irl.cs.ucla.edu/~yingdi/>.
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
var Name = require('../name.js').Name;

/**
 * An NdnRegexMatcher has static methods to convert an NDN regex
 * (http://redmine.named-data.net/projects/ndn-cxx/wiki/Regex) to a JavaScript
 * RegExp that can match against URIs.
 * @constructor
 */
var NdnRegexMatcher = function NdnRegexMatcher()
{
};

exports.NdnRegexMatcher = NdnRegexMatcher;

/**
 * Determine if the provided NDN regex matches the given Name.
 * @param {string} pattern The NDN regex.
 * @param {Name} name The Name to match against the regex.
 * @returns {Object} The match object from String.match, or null if the pattern
 * does not match.
 */
NdnRegexMatcher.match = function(pattern, name)
{
  var nameUri = name.toUri();

  pattern = NdnRegexMatcher.sanitizeSets(pattern);

  pattern = pattern.replace(/<>/g, "(?:<.+?>)");
  pattern = pattern.replace(/>/g, "");
  pattern = pattern.replace(/<(?!!)/g, "/");

  return nameUri.match(new RegExp(pattern));
};

NdnRegexMatcher.sanitizeSets = function(pattern)
{
  var newPattern = pattern;

  // Positive sets can be changed to (comp1|comp2).
  // Negative sets must be changed to negative lookahead assertions.

  var regex1 = /\[(\^?)(.*?)\]/g;
  var match;
  while ((match = regex1.exec(pattern)) !== null) {
    // Insert | between components.
    // Match 2 is the last match, so we use the hack of working backwards from
    //   lastIndex.  If possible, this should be changed to a more direct solution.
    var start = regex1.lastIndex - "]".length - match[2].length;
    var end = start + match[2].length;
    if (start - end === 0)
      continue;
    var oldStr = match[2];
    var newStr = oldStr.replace(/></g, ">|<");
    newPattern = newPattern.substr(0, start) + newStr + newPattern.substr(end);
  }

  // Replace [] with (),  or (?! ) for negative lookahead.
  // If we use negative lookahead, we also have to consume one component.
  var isNegative = newPattern.indexOf("[^") >= 0;
  if (isNegative) {
    newPattern = newPattern.replace(/\[\^/g, "(?:(?!");
    newPattern = newPattern.replace(/\]/g, ")(?:/.*)*)");
  }
  else {
    newPattern = newPattern.replace(/\[/g, "(");
    newPattern = newPattern.replace(/\]/g, ")");
  }

  return newPattern;
};
