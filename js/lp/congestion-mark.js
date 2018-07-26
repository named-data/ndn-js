/**
 * Copyright (C) 2018 Regents of the University of California.
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
 * CongestionMark represents the congestion mark header field in an NDNLPv2
 * packet.
 * http://redmine.named-data.net/projects/nfd/wiki/NDNLPv2
 * @constructor
 */
var CongestionMark = function CongestionMark()
{
  this.congestionMark_ = 0;
};

exports.CongestionMark = CongestionMark;

/**
 * Get the congestion mark value.
 * @return {number} The congestion mark value.
 */
CongestionMark.prototype.getCongestionMark = function()
{
  return this.congestionMark_;
};

/**
 * Set the congestion mark value.
 * @param {number} congestionMark The congestion mark ID value.
 */
CongestionMark.prototype.setCongestionMark = function(congestionMark)
{
  this.congestionMark_ = congestionMark;
};

/**
 * Get the first header field in lpPacket which is a CongestionMark. This is
 * an internal method which the application normally would not use.
 * @param {LpPacket} lpPacket The LpPacket with the header fields to search.
 * @return {CongestionMark} The first CongestionMark header field, or null if
 * not found.
 */
CongestionMark.getFirstHeader = function(lpPacket)
{
  for (var i = 0; i < lpPacket.countHeaderFields(); ++i) {
    var field = lpPacket.getHeaderField(i);
    if (field instanceof CongestionMark)
      return field;
  }

  return null;
};
