/**
 * Copyright (C) 2016-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx fields.hpp https://github.com/named-data/ndn-cxx/blob/master/src/lp/fields.hpp
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
 * IncomingFaceId represents the incoming face ID header field in an NDNLPv2 packet.
 * http://redmine.named-data.net/projects/nfd/wiki/NDNLPv2
 * @constructor
 */
var IncomingFaceId = function IncomingFaceId()
{
  this.faceId_ = null;
};

exports.IncomingFaceId = IncomingFaceId;

/**
 * Get the incoming face ID value.
 * @return {number} The face ID value.
 */
IncomingFaceId.prototype.getFaceId = function() { return this.faceId_; };

/**
 * Set the face ID value.
 * @param {number} faceId The incoming face ID value.
 */
IncomingFaceId.prototype.setFaceId = function(faceId)
{
  this.faceId_ = faceId;
};

/**
 * Get the first header field in lpPacket which is an IncomingFaceId. This is
 * an internal method which the application normally would not use.
 * @param {LpPacket} lpPacket The LpPacket with the header fields to search.
 * @return {IncomingFaceId} The first IncomingFaceId header field, or null if
 * not found.
 */
IncomingFaceId.getFirstHeader = function(lpPacket)
{
  for (var i = 0; i < lpPacket.countHeaderFields(); ++i) {
    var field = lpPacket.getHeaderField(i);
    if (field instanceof IncomingFaceId)
      return field;
  }

  return null;
};
