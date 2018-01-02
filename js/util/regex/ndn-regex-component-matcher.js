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
var NdnRegexMatcherBase = require('./ndn-regex-matcher-base.js').NdnRegexMatcherBase; /** @ignore */
var NdnRegexPseudoMatcher = require('./ndn-regex-pseudo-matcher.js').NdnRegexPseudoMatcher;

/**
 * Create a RegexComponent matcher from expr.
 * @param {string} expr The standard regular expression to match a component.
 * @param {NdnRegexBackrefManager} backrefManager The back-reference manager.
 * @param {boolean} isExactMatch (optional) The flag to provide exact match. If
 * omitted, use true.
 * @constructor
 */
var NdnRegexComponentMatcher = function NdnRegexComponentMatcher
  (expr, backrefManager, isExactMatch)
{
  // Call the base constructor.
  NdnRegexMatcherBase.call
    (this, expr, NdnRegexMatcherBase.NdnRegexExprType.COMPONENT, backrefManager);

  if (isExactMatch === undefined)
    isExactMatch = true;

  this.componentRegex_ = null;
  // Array of NdnRegexPseudoMatcher
  this.pseudoMatchers_ = [];

  this.isExactMatch_ = isExactMatch;

  this.compile_();
};

NdnRegexComponentMatcher.prototype = new NdnRegexMatcherBase();
NdnRegexComponentMatcher.prototype.name = "NdnRegexComponentMatcher";

exports.NdnRegexComponentMatcher = NdnRegexComponentMatcher;

/**
 * @param {Name} name
 * @param {number} offset
 * @param {number} len
 * @return {boolean}
 */
NdnRegexComponentMatcher.prototype.match = function(name, offset, len)
{
  this.matchResult_ = [];

  if (this.expr_ == "") {
    this.matchResult_.push(name.get(offset));
    return true;
  }

  if (this.isExactMatch_) {
    var targetStr = name.get(offset).toEscapedString();
    var subResult = targetStr.match(this.componentRegex_);
    if (subResult !== null) {
      for (var i = 1; i < subResult.length; ++i) {
        this.pseudoMatchers_[i].resetMatchResult();
        this.pseudoMatchers_[i].setMatchResult(subResult[i]);
      }

      this.matchResult_.push(name.get(offset));
      return true;
    }
  }
  else
    throw new NdnRegexMatcherBase.Error(new Error
      ("Non-exact component search is not supported yet"));

  return false;
};

NdnRegexComponentMatcher.prototype.compile_ = function()
{
  this.componentRegex_ = new RegExp(this.expr_);

  this.pseudoMatchers_ = [];
  this.pseudoMatchers_.push(new NdnRegexPseudoMatcher());

  // Imitate C++ mark_count by just counting the number of open parentheses.
  if (this.expr_.indexOf('\\(') >= 0)
    // We don't expect escaped parentheses, so don't try to handle them.
    throw new NdnRegexMatcherBase.Error(new Error
      ("Can't count subexpressions in regex with escaped parentheses: " + expr_));
  var markCount = 0;
  for (var i = 0; i < this.expr_.length; ++i) {
    if (this.expr_[i] === '(')
      ++markCount;
  }

  for (var i = 1; i <= markCount; ++i) {
    var pMatcher = new NdnRegexPseudoMatcher();
    this.pseudoMatchers_.push(pMatcher);
    this.backrefManager_.pushRef(pMatcher);
  }
};
