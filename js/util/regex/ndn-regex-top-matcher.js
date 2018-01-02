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
var NdnRegexBackrefManager = require('./ndn-regex-backref-manager.js').NdnRegexBackrefManager;
var NdnRegexPatternListMatcher = require('./ndn-regex-pattern-list-matcher.js').NdnRegexPatternListMatcher;

/**
 * Create an NdnRegexTopMatcher.
 * @param {string} expr The expression.
 * @param {string} expand (optional) If omitted, use "".
 * @constructor
 */
var NdnRegexTopMatcher = function NdnRegexTopMatcher(expr, expand)
{
  // Call the base constructor.
  NdnRegexMatcherBase.call
    (this, expr, NdnRegexMatcherBase.NdnRegexExprType.TOP);

  if (expand == undefined)
    expand = "";

  this.primaryMatcher_ = null;
  this.secondaryMatcher_ = null;
  this.primaryBackrefManager_ = new NdnRegexBackrefManager();
  this.secondaryBackrefManager_ = new NdnRegexBackrefManager();
  this.isSecondaryUsed_ = false;

  this.expand_ = expand;

  this.compile_();
};

NdnRegexTopMatcher.prototype = new NdnRegexMatcherBase();
NdnRegexTopMatcher.prototype.name = "NdnRegexTopMatcher";

exports.NdnRegexTopMatcher = NdnRegexTopMatcher;

/**
 * @param {Name} name
 * @param {number} offset (optinal) Ignored.
 * @param {number} len (optinal) Ignored.
 * @return {boolean}
 */
NdnRegexTopMatcher.prototype.match = function(name, offset, len)
{
  this.isSecondaryUsed_ = false;

  this.matchResult_ = [];

  if (this.primaryMatcher_.match(name, 0, name.size())) {
    this.matchResult_ = [];
    var result = this.primaryMatcher_.getMatchResult();
    for (var i = 0; i < result.length; ++i)
      this.matchResult_.push(result[i]);
    return true;
  }
  else {
    if (this.secondaryMatcher_ != null &&
        this.secondaryMatcher_.match(name, 0, name.size())) {
      this.matchResult_ = [];
      var result = this.secondaryMatcher_.getMatchResult();
      for (var i = 0; i < result.length; ++i)
        this.matchResult_.push(result[i]);
      this.isSecondaryUsed_ = true;
      return true;
    }

    return false;
  }
};

/**
 * @param {string} expandStr (optional) If omitted, use "".
 */
NdnRegexTopMatcher.prototype.expand = function(expandStr)
{
  if (expandStr == undefined)
    expandStr = "";

  var result = new Name();

  var backrefManager = (this.isSecondaryUsed_ ? this.secondaryBackrefManager_
                                              : this.primaryBackrefManager_);

  var backrefNo = backrefManager.size();

  var usingExpand;
  if (expandStr != "")
    usingExpand = expandStr;
  else
    usingExpand = this.expand_;

  var offset = [0];
  while (offset[0] < usingExpand.length) {
    var item = NdnRegexTopMatcher.getItemFromExpand_(usingExpand, offset);
    if (item[0] == '<')
      result.append(item.substring(1, item.length - 1));

    if (item[0] == '\\') {
      var index = parseInt(item.substring(1, item.length));

      if (0 === index) {
        for (var i = 0; i < this.matchResult_.length; ++i)
          result.append(this.matchResult_[i]);
      }
      else if (index <= backrefNo) {
        var tempResult = backrefManager.getBackref(index - 1).getMatchResult();
        for (var i = 0; i < tempResult.length; ++i)
          result.append(tempResult[i]);
      }
      else
        throw new NdnRegexMatcherBase.Error(new Error
          ("Exceeded the range of back reference"));
    }
  }

  return result;
};

/**
 * @param {Name} name
 * @param {boolean} hasAnchor (optional) If omitted, use false.
 * @return {NdnRegexTopMatcher}
 */
NdnRegexTopMatcher.fromName = function(name, hasAnchor)
{
  if (hasAnchor == undefined)
    hasAnchor = false;

  var regexStr = "^";

  for (var i = 0; i < name.size(); ++i) {
    regexStr += "<";
    regexStr += NdnRegexTopMatcher.convertSpecialChar_
      (name.get(i).toEscapedString());
    regexStr += ">";
  }

  if (hasAnchor)
    regexStr += "$";

  return new NdnRegexTopMatcher(regexStr);
};

NdnRegexTopMatcher.prototype.compile_ = function()
{
  var errMsg = "Error: RegexTopMatcher.Compile(): ";

  var expr = this.expr_;

  if ('$' != expr[expr.length - 1])
    expr = expr + "<.*>*";
  else
    expr = expr.substring(0, expr.length - 1);

  if ('^' != expr[0])
    this.secondaryMatcher_ = new NdnRegexPatternListMatcher
      ("<.*>*" + expr, this.secondaryBackrefManager_);
  else
    expr = expr.substring(1);

  this.primaryMatcher_ = new NdnRegexPatternListMatcher
     (expr, this.primaryBackrefManager_);
};

/**
 * @param {string} expand
 * @param {Array<number>} offset This updates offset[0].
 * #return {string}
 */
NdnRegexTopMatcher.getItemFromExpand_ = function(expand, offset)
{
  var begin = offset[0];

  if (expand[offset[0]] == '\\') {
    ++offset[0];
    if (offset[0] >= expand.length)
      throw new NdnRegexMatcherBase.Error(new Error
        ("Wrong format of expand string!"));

    while (offset[0] < expand.length &&
           expand[offset[0]] <= '9' && expand[offset[0]] >= '0') {
      ++offset[0];
      if (offset[0] > expand.length)
        throw new NdnRegexMatcherBase.Error(new Error
          ("Wrong format of expand string!"));
    }

    if (offset[0] > begin + 1)
      return expand.substring(begin, offset[0]);
    else
      throw new NdnRegexMatcherBase.Error(new Error
        ("Wrong format of expand string!"));
  }
  else if (expand[offset[0]] == '<') {
    ++offset[0];
    if (offset[0] >= expand.length)
      throw new NdnRegexMatcherBase.Error(new Error
        ("Wrong format of expand string!"));

    var left = 1;
    var right = 0;
    while (right < left) {
      if (expand[offset[0]] == '<')
        ++left;
      if (expand[offset[0]] == '>')
        ++right;

      ++offset[0];
      if (offset[0] >= expand.length)
        throw new NdnRegexMatcherBase.Error(new Error
          ("Wrong format of expand string!"));
    }

    return expand.substring(begin, offset[0]);
  }
  else
    throw new NdnRegexMatcherBase.Error(new Error
      ("Wrong format of expand string!"));
};

/**
 * @param {string} str
 * @return {string}
 */
NdnRegexTopMatcher.convertSpecialChar_ = function(str)
{
  newStr = "";
  for (var i = 0; i < str.length; ++i) {
    var c = str[i];
    if (c == '.' ||
        c == '[' ||
        c == '{' ||
        c == '}' ||
        c == '(' ||
        c == ')' ||
        c == '\\' ||
        c == '*' ||
        c == '+' ||
        c == '?' ||
        c == '|' ||
        c == '^' ||
        c == '$') {
      newStr += '\\';
      newStr += c;
    }
    else
      newStr += c;
  }

  return newStr;
};
