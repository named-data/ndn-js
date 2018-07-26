/**
 * Copyright (C) 2016-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx nack.hpp https://github.com/named-data/ndn-cxx/blob/master/src/lp/nack.hpp
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
 * NetworkNack represents a network Nack packet and includes a Nack reason.
 * @constructor
 */
var NetworkNack = function NetworkNack()
{
  this.reason_ = NetworkNack.Reason.NONE;
  this.otherReasonCode_ = -1;
};

exports.NetworkNack = NetworkNack;

/**
 * A NetworkNack.Reason specifies the reason in a NetworkNack packet. If the
 * reason code in the packet is not a recognized enum value, then we use
 * Reason.OTHER_CODE and you can call getOtherReasonCode(). We do this to keep
 * the recognized reason values independent of packet encoding formats.
 */
NetworkNack.Reason = {
  NONE:         0,
  CONGESTION:  50,
  DUPLICATE:  100,
  NO_ROUTE:   150,
  OTHER_CODE: 0x7fff
};

/**
 * Get the network Nack reason.
 * @return {number} The reason enum value from NetworkNack.Reason. If this is
 * Reason.OTHER_CODE, then call getOtherReasonCode() to get the unrecognized
 * reason code.
 */
NetworkNack.prototype.getReason = function() { return this.reason_; };

/**
 * Get the reason code from the packet which is other than a recognized
 * Reason enum value. This is only meaningful if getReason() is
 * Reason.OTHER_CODE.
 * @return {number} The reason code.
 */
NetworkNack.prototype.getOtherReasonCode = function()
{
  return this.otherReasonCode_;
};

/**
 * Set the network Nack reason.
 * @param {number} reason The network Nack reason enum value from
 * NetworkNack.Reason. If the packet's reason code is not a recognized Reason
 * enum value, use Reason.OTHER_CODE and call setOtherReasonCode().
 */
NetworkNack.prototype.setReason = function(reason) { this.reason_ = reason; };

/**
 * Set the packet's reason code to use when the reason enum is
 * Reason.OTHER_CODE. If the packet's reason code is a recognized enum value,
 * just call setReason().
 * @param {number} otherReasonCode The packet's unrecognized reason code, which
 * must be non-negative.
 */
NetworkNack.prototype.setOtherReasonCode = function(otherReasonCode)
{
  if (otherReasonCode < 0)
    throw new Error("NetworkNack other reason code must be non-negative");
  this.otherReasonCode_ = otherReasonCode;
};

/**
 * Get the first header field in lpPacket which is a NetworkNack. This is
 * an internal method which the application normally would not use.
 * @param {LpPacket} lpPacket The LpPacket with the header fields to search.
 * @return {NetworkNack} The first NetworkNack header field, or null if not
 * found.
 */
NetworkNack.getFirstHeader = function(lpPacket)
{
  for (var i = 0; i < lpPacket.countHeaderFields(); ++i) {
    var field = lpPacket.getHeaderField(i);
    if (field instanceof NetworkNack)
      return field;
  }

  return null;
};
