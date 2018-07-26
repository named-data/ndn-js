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
 * Create an NdnRegexRepeatMatcher.
 * @param {string} expr
 * @param {NdnRegexBackrefManager} backrefManager The back-reference manager.
 * @param {number} indicator
 * @constructor
 */
var NdnRegexRepeatMatcher = function NdnRegexRepeatMatcher
  (expr, backrefManager, indicator)
{
  // Call the base constructor.
  NdnRegexMatcherBase.call
    (this, expr, NdnRegexMatcherBase.NdnRegexExprType.REPEAT_PATTERN,
     backrefManager);
  this.repeatMin_ = 0;
  this.repeatMax_ = 0;

  this.indicator_ = indicator;

  this.compile_();
};

NdnRegexRepeatMatcher.prototype = new NdnRegexMatcherBase();
NdnRegexRepeatMatcher.prototype.name = "NdnRegexRepeatMatcher";

exports.NdnRegexRepeatMatcher = NdnRegexRepeatMatcher;

/**
 * @param {Name} name
 * @param {number} offset
 * @param {number} len
 * @return {boolean}
 */
NdnRegexRepeatMatcher.prototype.match = function(name, offset, len)
{
  this.matchResult_ = [];

  if (0 === this.repeatMin_) {
    if (0 === len)
      return true;
  }

  if (this.recursiveMatch2_(0, name, offset, len)) {
    for (var i = offset; i < offset + len; ++i)
      this.matchResult_.push(name.get(i));
    return true;
  }
  else
    return false;
};

/**
 * Compile the regular expression to generate more matchers when necessary.
 */
NdnRegexRepeatMatcher.prototype.compile_ = function()
{
  var matcher;

  if ('(' == this.expr_[0]) {
    matcher = new NdnRegexBackrefMatcher
      (this.expr_.substring(0, this.indicator_), this.backrefManager_);
    this.backrefManager_.pushRef(matcher);
    matcher.lateCompile();
  }
  else
    matcher = new NdnRegexComponentSetMatcher
      (this.expr_.substring(0, this.indicator_), this.backrefManager_);

  this.matchers_.push(matcher);

  this.parseRepetition_();
};

NdnRegexRepeatMatcher.prototype.parseRepetition_ = function()
{
  var exprSize = this.expr_.length;
  var MAX_REPETITIONS = 32767;

  if (exprSize === this.indicator_) {
    this.repeatMin_ = 1;
    this.repeatMax_ = 1;

    return true;
  }
  else {
    if (exprSize === this.indicator_ + 1) {
      if ('?' == this.expr_[this.indicator_]) {
        this.repeatMin_ = 0;
        this.repeatMax_ = 1;
        return true;
      }
      if ('+' == this.expr_[this.indicator_]) {
        this.repeatMin_ = 1;
        this.repeatMax_ = MAX_REPETITIONS;
        return true;
      }
      if ('*' == this.expr_[this.indicator_]) {
        this.repeatMin_ = 0;
        this.repeatMax_ = MAX_REPETITIONS;
        return true;
      }
    }
    else {
      var repeatStruct = this.expr_.substring(this.indicator_, exprSize);
      var rsSize = repeatStruct.length;
      var min = 0;
      var max = 0;

      if (repeatStruct.match(new RegExp("\\{[0-9]+,[0-9]+\\}")) != null) {
        separator = repeatStruct.indexOf(',');
        min = parseInt(repeatStruct.substring(1, separator));
        max = parseInt(repeatStruct.substring(separator + 1, rsSize - 1));
      }
      else if (repeatStruct.match(new RegExp("\\{,[0-9]+\\}")) != null) {
        separator = repeatStruct.indexOf(',');
        min = 0;
        max = parseInt(repeatStruct.substring(separator + 1, rsSize - 1));
      }
      else if (repeatStruct.match(new RegExp("\\{[0-9]+,\\}")) != null) {
        separator = repeatStruct.indexOf(',');
        min = parseInt(repeatStruct.substring(1, separator));
        max = MAX_REPETITIONS;
      }
      else if (repeatStruct.match(new RegExp("\\{[0-9]+\\}")) != null) {
        min = parseInt(repeatStruct.substring(1, rsSize - 1));
        max = min;
      }
      else
        throw new NdnRegexMatcherBase.Error(new Error
          ("Error: RegexRepeatMatcher.ParseRepetition(): Unrecognized format " +
           this.expr_));

      if (min > MAX_REPETITIONS || max > MAX_REPETITIONS || min > max)
        throw new NdnRegexMatcherBase.Error(new Error
          ("Error: RegexRepeatMatcher.ParseRepetition(): Wrong number " +
           this.expr_));

      this.repeatMin_ = min;
      this.repeatMax_ = max;

      return true;
    }
  }

  return false;
};

/**
 *
 * @param {number} repeat
 * @param {Name} name
 * @param {number} offset
 * @param {number} len
 * @return {boolean}
 */
NdnRegexRepeatMatcher.prototype.recursiveMatch2_ = function
  (repeat, name, offset, len)
{
  var tried = len;
  var matcher = this.matchers_[0];

  if (0 < len && repeat >= this.repeatMax_)
    return false;

  if (0 === len && repeat < this.repeatMin_)
    return false;

  if (0 == len && repeat >= this.repeatMin_)
    return true;

  while (tried >= 0) {
    if (matcher.match(name, offset, tried) &&
        this.recursiveMatch2_(repeat + 1, name, offset + tried,
                              len - tried))
      return true;
    --tried;
  }

  return false;
};

// Put these last to avoid a require loop.
/** @ignore */
var NdnRegexBackrefMatcher = require('./ndn-regex-backref-matcher.js').NdnRegexBackrefMatcher; /** @ignore */
var NdnRegexComponentSetMatcher = require('./ndn-regex-component-set-matcher.js').NdnRegexComponentSetMatcher;
