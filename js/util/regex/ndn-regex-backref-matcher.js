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
var NdnRegexMatcherBase = require('./ndn-regex-matcher-base.js').NdnRegexMatcherBase;

/**
 * Create an NdnRegexBackrefMatcher.
 * @param {string} expr
 * @param {NdnRegexBackrefManager} backrefManager The back-reference manager.
 * @constructor
 */
var NdnRegexBackrefMatcher = function NdnRegexBackrefMatcher
  (expr, backrefManager)
{
  // Call the base constructor.
  NdnRegexMatcherBase.call
    (this, expr, NdnRegexMatcherBase.NdnRegexExprType.BACKREF, backrefManager);
};

NdnRegexBackrefMatcher.prototype = new NdnRegexMatcherBase();
NdnRegexBackrefMatcher.prototype.name = "NdnRegexBackrefMatcher";

exports.NdnRegexBackrefMatcher = NdnRegexBackrefMatcher;

NdnRegexBackrefMatcher.prototype.lateCompile = function()
{
  this.compile_();
};

NdnRegexBackrefMatcher.prototype.compile_ = function()
{
  if (this.expr_.length < 2)
    throw new NdnRegexMatcherBase.Error(new Error
      ("Unrecognized format: " + this.expr_));

  var lastIndex = this.expr_.length - 1;
  if ('(' === this.expr_[0] && ')' === this.expr_[lastIndex]) {
    var matcher = new NdnRegexPatternListMatcher
      (this.expr_.substring(1, lastIndex), this.backrefManager_);
    this.matchers_.push(matcher);
  }
  else
    throw new NdnRegexMatcherBase.Error(new Error
      ("Unrecognized format: " + this.expr_));
};

// Put this last to avoid a require loop.
/** @ignore */
var NdnRegexPatternListMatcher = require('./ndn-regex-pattern-list-matcher.js').NdnRegexPatternListMatcher;
