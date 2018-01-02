/**
 * Copyright (C) 2014-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From code in ndn-cxx by Yingdi Yu <yingdi@cs.ucla.edu>
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
var OID = function OID(oid)
{
  if (typeof oid === 'string') {
    var splitString = oid.split(".");
    this.oid = [];
    for (var i = 0; i < splitString.length; ++i)
      this.oid.push(parseInt(splitString[i]));
  }
  else
    // Assume oid is an array of int.  Make a copy.
    this.oid = oid.slice(0, oid.length);
};

exports.OID = OID;

OID.prototype.getIntegerList = function()
{
  return this.oid;
};

OID.prototype.setIntegerList = function(oid)
{
  // Make a copy.
  this.oid = oid.slice(0, oid.length);
};

OID.prototype.toString = function()
{
  var result = "";
  for (var i = 0; i < this.oid.length; ++i) {
    if (i !== 0)
      result += ".";
    result += this.oid[i];
  }

  return result;
};

OID.prototype.equals = function(other)
{
  if (!(other instanceof OID))
    return false;
  if (this.oid.length !== other.oid.length)
    return false;

  for (var i = 0; i < this.oid.length; ++i) {
    if (this.oid[i] != other.oid[i])
      return false;
  }
  return true;
};
