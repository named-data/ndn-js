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
 * Create an NdnRegexComponentSetMatcher matcher from expr.
 * @param {string} expr The standard regular expression to match a component.
 * @param {NdnRegexBackrefManager} backrefManager The back-reference manager.
 * @constructor
 */
var NdnRegexComponentSetMatcher = function NdnRegexComponentSetMatcher
  (expr, backrefManager)
{
  // Call the base constructor.
  NdnRegexMatcherBase.call
    (this, expr, NdnRegexMatcherBase.NdnRegexExprType.COMPONENT_SET,
     backrefManager);

  // Array of NdnRegexComponentMatcher
  this.components_ = [];
  this.isInclusion_ = true;

  this.compile_();
};

NdnRegexComponentSetMatcher.prototype = new NdnRegexMatcherBase();
NdnRegexComponentSetMatcher.prototype.name = "NdnRegexComponentSetMatcher";

exports.NdnRegexComponentSetMatcher = NdnRegexComponentSetMatcher;

/**
 * @param {Name} name
 * @param {number} offset
 * @param {number} len
 * @return {boolean}
 */
NdnRegexComponentSetMatcher.prototype.match = function(name, offset, len)
{
  isMatched = false;

  // ComponentSet only matches one component.
  if (len !== 1)
    return false;

  for (var i = 0; i < this.components_.length; ++i) {
    var matcher = this.components_[i];
    if (matcher.match(name, offset, len)) {
      isMatched = true;
      break;
    }
  }

  this.matchResult_ = [];

  if (this.isInclusion_ ? isMatched : !isMatched) {
    this.matchResult_.push(name.get(offset));
    return true;
  }
  else
    return false;
};

/**
 * Compile the regular expression to generate more matchers when necessary.
 */
NdnRegexComponentSetMatcher.prototype.compile_ = function()
{
  if (this.expr_.length < 2)
    throw new NdnRegexMatcherBase.Error(new Error
      ("Regexp compile error (cannot parse " + this.expr_ + ")"));

  if (this.expr_[0] === '<')
    this.compileSingleComponent_();
  else if (this.expr_[0] === '[') {
    var lastIndex = this.expr_.length - 1;
    if (']' !== this.expr_[lastIndex])
      throw new NdnRegexMatcherBase.Error(new Error
        ("Regexp compile error (no matching ']' in " + this.expr_ + ")"));

    if ('^' === this.expr_[1]) {
      this.isInclusion_ = false;
      this.compileMultipleComponents_(2, lastIndex);
    }
    else
      this.compileMultipleComponents_(1, lastIndex);
  }
  else
    throw new NdnRegexMatcherBase.Error(new Error
      ("Regexp compile error (cannot parse " + this.expr_ + ")"));
};

/**
 * @param {number} index
 * @return {number}
 */
NdnRegexComponentSetMatcher.prototype.extractComponent_ = function(index)
{
  var lcount = 1;
  var rcount = 0;

  while (lcount > rcount) {
    if (index >= this.expr_.length)
      throw new NdnRegexMatcherBase.Error(new Error
        ("Error: angle brackets mismatch"));

    if (this.expr_[index] === '<')
      lcount += 1;
    else if (this.expr_[index] === '>')
      rcount += 1;

    index += 1;
  }

  return index;
};

NdnRegexComponentSetMatcher.prototype.compileSingleComponent_ = function()
{
  var end = this.extractComponent_(1);

  if (this.expr_.length !== end)
    throw new NdnRegexMatcherBase.Error(new Error
      ("Component expr error " + this.expr_));
  else {
    component = new NdnRegexComponentMatcher
      (this.expr_.substring(1, end - 1), this.backrefManager_);

    this.components_.push(component);
  }
};

/**
 * @param {number} start
 * @param {number} lastIndex
 */
NdnRegexComponentSetMatcher.prototype.compileMultipleComponents_ = function
  (start, lastIndex)
{
  var index = start;
  var tempIndex = start;

  while (index < lastIndex) {
    if ('<' !== this.expr_[index])
      throw new NdnRegexMatcherBase.Error(new Error
        ("Component expr error " + this.expr_));

    tempIndex = index + 1;
    index = this.extractComponent_(tempIndex);

    component = new NdnRegexComponentMatcher
      (this.expr_.substring(tempIndex, index - 1), this.backrefManager_);

    this.components_.push(component);
  }

  if (index != lastIndex)
    throw new NdnRegexMatcherBase.Error(new Error
      ("Not sufficient expr to parse " + this.expr_));
};

// Put this last to avoid a require loop.
/** @ignore */
var NdnRegexComponentMatcher = require('./ndn-regex-component-matcher.js').NdnRegexComponentMatcher;
