/**
 * Copyright (C) 2015-2016 Regents of the University of California.
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
 * UnitTestsCommon has static methods to help in unit tests.
 */
var UnitTestsCommon = function UnitTestsCommon()
{
};

exports.UnitTestsCommon = UnitTestsCommon;

/**
 * Convert a UNIX timestamp to ISO time representation with the "T" in the middle.
 * @param {number} msSince1970 Timestamp as milliseconds since Jan 1, 1970 UTC.
 * @returns {string} The string representation.
 */
UnitTestsCommon.toIsoString = function(msSince1970)
{
  var utcTime = new Date(Math.round(msSince1970));
  return utcTime.getUTCFullYear() +
         UnitTestsCommon.to2DigitString(utcTime.getUTCMonth() + 1) +
         UnitTestsCommon.to2DigitString(utcTime.getUTCDate()) +
         "T" +
         UnitTestsCommon.to2DigitString(utcTime.getUTCHours()) +
         UnitTestsCommon.to2DigitString(utcTime.getUTCMinutes()) +
         UnitTestsCommon.to2DigitString(utcTime.getUTCSeconds());
};

/**
 * A private method to zero pad an integer to 2 digits.
 * @param {number} x The number to pad.  Assume it is a non-negative integer.
 * @returns {string} The padded string.
 */
UnitTestsCommon.to2DigitString = function(x)
{
  var result = x.toString();
  return result.length === 1 ? "0" + result : result;
};

/**
 * Convert an ISO time representation with the "T" in the middle to a UNIX
 * timestamp.
 * @param {string} timeString The ISO time representation.
 * @returns {number} The timestamp as milliseconds since Jan 1, 1970 UTC.
 */
UnitTestsCommon.fromIsoString = function(timeString)
{
  if (timeString.length != 15 || timeString.substr(8, 1) != 'T')
    throw new Error("fromIsoString: Format is not the expected yyyymmddThhmmss");

  return Date.UTC
    (parseInt(timeString.substr(0, 4)),
     parseInt(timeString.substr(4, 2) - 1),
     parseInt(timeString.substr(6, 2)),
     parseInt(timeString.substr(9, 2)),
     parseInt(timeString.substr(11, 2)),
     parseInt(timeString.substr(13, 2)));
};
