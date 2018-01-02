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
var NdnRegexBackrefManager = require('./ndn-regex-backref-manager.js').NdnRegexBackrefManager;

/**
 * Create an instance of the abstract class NdnRegexMatcherBase.
 * @param {string} expr The expression.
 * @param {number} type The type as an int from the
 * NdnRegexMatcherBase.NdnRegexExprType enum.
 * @param {NdnRegexBackrefManager} backrefManager (optional) The
 * NdnRegexBackrefManager to use. If omitted, use a new
 * NdnRegexBackrefManager().
 * @constructor
 */
var NdnRegexMatcherBase = function NdnRegexMatcherBase
  (expr, type, backrefManager)
{
  // Array of NdnRegexMatcherBase
  this.matchers_ = [];
  // Array of Name.Component
  this.matchResult_ = [];

  this.expr_ = expr;
  this.type_ = type;
  if (backrefManager == undefined)
    backrefManager = new NdnRegexBackrefManager();
  this.backrefManager_ = backrefManager;
};

exports.NdnRegexMatcherBase = NdnRegexMatcherBase;

/**
 * Create a new NdnRegexMatcherBase.Error to report errors using
 * NdnRegexMatcherBase methods.
 * Call with: throw new NdnRegexMatcherBase.Error(new Error("message")).
 * @constructor
 * @param {Error} error The exception created with new Error.
 */
NdnRegexMatcherBase.Error = function NdnRegexMatcherBaseError(error)
{
  if (error) {
    error.__proto__ = NdnRegexMatcherBase.Error.prototype;
    return error;
  }
};

NdnRegexMatcherBase.Error.prototype = new Error();
NdnRegexMatcherBase.Error.prototype.name = "NdnRegexMatcherBaseError";

NdnRegexMatcherBase.NdnRegexExprType = {
  TOP:            0,
  PATTERN_LIST:   1,
  REPEAT_PATTERN: 2,
  BACKREF:        3,
  COMPONENT_SET:  4,
  COMPONENT:      5,
  PSEUDO:         6
};

/**
 * @param {Name} name
 * @param {number} offset
 * @param {number} len
 * @return {boolean}
 */
NdnRegexMatcherBase.prototype.match = function(name, offset, len)
{
  var result = false;

  this.matchResult_ = [];

  if (this.recursiveMatch_(0, name, offset, len)) {
    var i = offset;
    while (i < offset + len) {
      this.matchResult_.push(name.get(i));
      ++i;
    }
    result = true;
  }
  else
    result = false;

  return result;
};

/**
 * Get the list of matched name components.
 * @return {Array<Name.Component>} The matched name components. You must not
 * modify this list.
 */
NdnRegexMatcherBase.prototype.getMatchResult = function()
{
  return this.matchResult_;
};

/**
 * @return {string}
 */
NdnRegexMatcherBase.prototype.getExpr = function()
{
  return this.expr_;
};

/**
 * Compile the regular expression to generate more matchers when necessary.
 */
NdnRegexMatcherBase.prototype.compile_ = function()
{
  throw new Error("NdnRegexMatcherBase.compile is not implemented");
};

/**
 *
 * @param {number} matcherNo
 * @param {Name} name
 * @param {number} offset
 * @param {number} len
 * @return {boolean}
 */
NdnRegexMatcherBase.prototype.recursiveMatch_ = function
  (matcherNo, name, offset, len)
{
  var tried = len;

  if (matcherNo >= this.matchers_.length)
      return (len == 0);

  var matcher = this.matchers_[matcherNo];

  while (tried >= 0) {
    if (matcher.match(name, offset, tried) &&
        this.recursiveMatch_
          (matcherNo + 1, name, offset + tried, len - tried))
      return true;
    --tried;
  }

  return false;
};
