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
 * Create an NdnRegexPatternListMatcher.
 * @param {string} expr
 * @param {NdnRegexBackrefManager} backrefManager The back-reference manager.
 * @constructor
 */
var NdnRegexPatternListMatcher = function NdnRegexPatternListMatcher
  (expr, backrefManager)
{
  // Call the base constructor.
  NdnRegexMatcherBase.call
    (this, expr, NdnRegexMatcherBase.NdnRegexExprType.PATTERN_LIST,
     backrefManager);

  this.compile_();
};

NdnRegexPatternListMatcher.prototype = new NdnRegexMatcherBase();
NdnRegexPatternListMatcher.prototype.name = "NdnRegexPatternListMatcher";

exports.NdnRegexPatternListMatcher = NdnRegexPatternListMatcher;

NdnRegexPatternListMatcher.prototype.compile_ = function()
{
  var length = this.expr_.length;
  var index = [0];
  var subHead = index[0];

  while (index[0] < length) {
    subHead = index[0];

    if (!this.extractPattern_(subHead, index))
      throw new NdnRegexMatcherBase.Error(new Error("Compile error"));
  }
};

/**
 * @param {number} index
 * @param {Array<number>} Update next[0].
 * @return {boolean}
 */
NdnRegexPatternListMatcher.prototype.extractPattern_ = function(index, next)
{
  var start = index;
  var end = index;
  var indicator = index;

  if (this.expr_[index] === '(') {
    index += 1;
    index = this.extractSubPattern_('(', ')', index);
    indicator = index;
    end = this.extractRepetition_(index);
    if (indicator === end) {
      var matcher = new NdnRegexBackrefMatcher
        (this.expr_.substring(start, end), this.backrefManager_);
      this.backrefManager_.pushRef(matcher);
      matcher.lateCompile();

      this.matchers_.push(matcher);
    }
    else
      this.matchers_.push(new NdnRegexRepeatMatcher
        (this.expr_.substring(start, end), this.backrefManager_,
         indicator - start));
  }
  else if (this.expr_[index] === '<') {
    index += 1;
    index = this.extractSubPattern_('<', '>', index);
    indicator = index;
    end = this.extractRepetition_(index);
    this.matchers_.push(new NdnRegexRepeatMatcher
      (this.expr_.substring(start, end), this.backrefManager_, indicator - start));
  }
  else if (this.expr_[index] === '[') {
    index += 1;
    index = this.extractSubPattern_('[', ']', index);
    indicator = index;
    end = this.extractRepetition_(index);
    this.matchers_.push(new NdnRegexRepeatMatcher
      (this.expr_.substring(start, end), this.backrefManager_,
       indicator - start));
  }
  else
    throw new NdnRegexMatcherBase.Error(new Error("Unexpected syntax"));

  next[0] = end;

  return true;
};

/**
 * @param {string} left
 * @param {string} right
 * @param {number} index
 * @return {number}
 */
NdnRegexPatternListMatcher.prototype.extractSubPattern_ = function
  (left, right, index)
{
  var lcount = 1;
  var rcount = 0;

  while (lcount > rcount) {
    if (index >= this.expr_.length)
      throw new NdnRegexMatcherBase.Error(new Error("Parenthesis mismatch"));

    if (left == this.expr_[index])
      lcount += 1;

    if (right == this.expr_[index])
      rcount += 1;

    index += 1;
  }

  return index;
};

/**
 * @param {number} index
 * @return {number}
 */
NdnRegexPatternListMatcher.prototype.extractRepetition_ = function(index)
{
  var exprSize = this.expr_.length;

  if (index === exprSize)
    return index;

  if ('+' == this.expr_[index] || '?' == this.expr_[index] ||
      '*' == this.expr_[index]) {
    ++index;
    return index;
  }

  if ('{' == this.expr_[index]) {
    while ('}' != this.expr_[index]) {
      ++index;
      if (index === exprSize)
        break;
    }

    if (index === exprSize)
      throw new NdnRegexMatcherBase.Error(new Error("Missing right brace bracket"));
    else {
      ++index;
      return index;
    }
  }
  else
    return index;
};

// Put these last to avoid a require loop.
/** @ignore */
var NdnRegexBackrefMatcher = require('./ndn-regex-backref-matcher.js').NdnRegexBackrefMatcher; /** @ignore */
var NdnRegexRepeatMatcher = require('./ndn-regex-repeat-matcher.js').NdnRegexRepeatMatcher;
