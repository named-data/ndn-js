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

/**
 * @constructor
 */
var NdnRegexBackrefManager = function NdnRegexBackrefManager()
{
  // Array of NdnRegexMatcherBase
  this.backrefs_ = []
};

exports.NdnRegexBackrefManager = NdnRegexBackrefManager;

/**
 * @param {NdnRegexMatcherBase} matcher
 * @return {number}
 */
NdnRegexBackrefManager.prototype.pushRef = function(matcher)
{
  last = this.backrefs_.length;
  this.backrefs_.push(matcher);

  return last;
};

NdnRegexBackrefManager.prototype.popRef = function()
{
  this.backrefs_.pop();
};

/**
 * @return {number}
 */
NdnRegexBackrefManager.prototype.size = function()
{
  return this.backrefs_.length;
};

/**
 * @param {number} i
 * @return {NdnRegexMatcherBase}
 */
NdnRegexBackrefManager.prototype.getBackref = function(i)
{
  return this.backrefs_[i];
};
