/**
 * Copyright (C) 2013-2015 Regents of the University of California.
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
 * A ForwardingFlags object holds the flags which specify how the forwarding daemon should forward an interest for
 * a registered prefix.  We use a separate ForwardingFlags object to retain future compatibility if the daemon forwarding
 * bits are changed, amended or deprecated.
 * Create a new ForwardingFlags with "active" and "childInherit" set and all other flags cleared.
 */
var ForwardingFlags = function ForwardingFlags(value)
{
  if (typeof value === 'object' && value instanceof ForwardingFlags) {
    // Make a copy.
    this.active = value.active;
    this.childInherit = value.childInherit;
    this.advertise = value.advertise;
    this.last = value.last;
    this.capture = value.capture;
    this.local = value.local;
    this.tap = value.tap;
    this.captureOk = value.captureOk;
  }
  else {
    this.active = true;
    this.childInherit = true;
    this.advertise = false;
    this.last = false;
    this.capture = false;
    this.local = false;
    this.tap = false;
    this.captureOk = false;
  }
};

exports.ForwardingFlags = ForwardingFlags;

ForwardingFlags.ForwardingEntryFlags_ACTIVE         = 1;
ForwardingFlags.ForwardingEntryFlags_CHILD_INHERIT  = 2;
ForwardingFlags.ForwardingEntryFlags_ADVERTISE      = 4;
ForwardingFlags.ForwardingEntryFlags_LAST           = 8;
ForwardingFlags.ForwardingEntryFlags_CAPTURE       = 16;
ForwardingFlags.ForwardingEntryFlags_LOCAL         = 32;
ForwardingFlags.ForwardingEntryFlags_TAP           = 64;
ForwardingFlags.ForwardingEntryFlags_CAPTURE_OK   = 128;

ForwardingFlags.NfdForwardingFlags_CHILD_INHERIT = 1;
ForwardingFlags.NfdForwardingFlags_CAPTURE       = 2;

/**
 * Get an integer with the bits set according to the flags as used by the ForwardingEntry message.
 * @returns {number} An integer with the bits set.
 */
ForwardingFlags.prototype.getForwardingEntryFlags = function()
{
  var result = 0;

  if (this.active)
    result |= ForwardingFlags.ForwardingEntryFlags_ACTIVE;
  if (this.childInherit)
    result |= ForwardingFlags.ForwardingEntryFlags_CHILD_INHERIT;
  if (this.advertise)
    result |= ForwardingFlags.ForwardingEntryFlags_ADVERTISE;
  if (this.last)
    result |= ForwardingFlags.ForwardingEntryFlags_LAST;
  if (this.capture)
    result |= ForwardingFlags.ForwardingEntryFlags_CAPTURE;
  if (this.local)
    result |= ForwardingFlags.ForwardingEntryFlags_LOCAL;
  if (this.tap)
    result |= ForwardingFlags.ForwardingEntryFlags_TAP;
  if (this.captureOk)
    result |= ForwardingFlags.ForwardingEntryFlags_CAPTURE_OK;

  return result;
};

/**
 * Set the flags according to the bits in forwardingEntryFlags as used by the ForwardingEntry message.
 * @param {number} forwardingEntryFlags An integer with the bits set.
 */
ForwardingFlags.prototype.setForwardingEntryFlags = function(forwardingEntryFlags)
{
  this.active = ((forwardingEntryFlags & ForwardingFlags.ForwardingEntryFlags_ACTIVE) != 0);
  this.childInherit = ((forwardingEntryFlags & ForwardingFlags.ForwardingEntryFlags_CHILD_INHERIT) != 0);
  this.advertise = ((forwardingEntryFlags & ForwardingFlags.ForwardingEntryFlags_ADVERTISE) != 0);
  this.last = ((forwardingEntryFlags & ForwardingFlags.ForwardingEntryFlags_LAST) != 0);
  this.capture = ((forwardingEntryFlags & ForwardingFlags.ForwardingEntryFlags_CAPTURE) != 0);
  this.local = ((forwardingEntryFlags & ForwardingFlags.ForwardingEntryFlags_LOCAL) != 0);
  this.tap = ((forwardingEntryFlags & ForwardingFlags.ForwardingEntryFlags_TAP) != 0);
  this.captureOk = ((forwardingEntryFlags & ForwardingFlags.ForwardingEntryFlags_CAPTURE_OK) != 0);
};

/**
 * Get an integer with the bits set according to the NFD forwarding flags as
 * used in the ControlParameters of the command interest.
 * @returns {number} An integer with the bits set.
 */
ForwardingFlags.prototype.getNfdForwardingFlags = function()
{
  var result = 0;

  if (this.childInherit)
    result |= ForwardingFlags.NfdForwardingFlags_CHILD_INHERIT;
  if (this.capture)
    result |= ForwardingFlags.NfdForwardingFlags_CAPTURE;

  return result;
};

/**
 * Set the flags according to the NFD forwarding flags as used in the
 * ControlParameters of the command interest.
 * @param {number} nfdForwardingFlags An integer with the bits set.
 */
ForwardingFlags.prototype.setNfdForwardingFlags = function(nfdForwardingFlags)
{
  this.childInherit =
    ((nfdForwardingFlags & ForwardingFlags.NfdForwardingFlags_CHILD_INHERIT) != 0);
  this.capture =
    ((nfdForwardingFlags & ForwardingFlags.NfdForwardingFlags_CAPTURE) != 0);
};

/**
 * Get the value of the "active" flag.
 * @returns {Boolean} true if the flag is set, false if it is cleared.
 */
ForwardingFlags.prototype.getActive = function() { return this.active; };

/**
 * Get the value of the "childInherit" flag.
 * @returns {Boolean} true if the flag is set, false if it is cleared.
 */
ForwardingFlags.prototype.getChildInherit = function() { return this.childInherit; };

/**
 * Get the value of the "advertise" flag.
 * @returns {Boolean} true if the flag is set, false if it is cleared.
 */
ForwardingFlags.prototype.getAdvertise = function() { return this.advertise; };

/**
 * Get the value of the "last" flag.
 * @returns {Boolean} true if the flag is set, false if it is cleared.
 */
ForwardingFlags.prototype.getLast = function() { return this.last; };

/**
 * Get the value of the "capture" flag.
 * @returns {Boolean} true if the flag is set, false if it is cleared.
 */
ForwardingFlags.prototype.getCapture = function() { return this.capture; };

/**
 * Get the value of the "local" flag.
 * @returns {Boolean} true if the flag is set, false if it is cleared.
 */
ForwardingFlags.prototype.getLocal = function() { return this.local; };

/**
 * Get the value of the "tap" flag.
 * @returns {Boolean} true if the flag is set, false if it is cleared.
 */
ForwardingFlags.prototype.getTap = function() { return this.tap; };

/**
 * Get the value of the "captureOk" flag.
 * @returns {Boolean} true if the flag is set, false if it is cleared.
 */
ForwardingFlags.prototype.getCaptureOk = function() { return this.captureOk; };

/**
 * Set the value of the "active" flag
 * @param {number} value true to set the flag, false to clear it.
 */
ForwardingFlags.prototype.setActive = function(value) { this.active = value; };

/**
 * Set the value of the "childInherit" flag
 * @param {number} value true to set the flag, false to clear it.
 */
ForwardingFlags.prototype.setChildInherit = function(value) { this.childInherit = value; };

/**
 * Set the value of the "advertise" flag
 * @param {number} value true to set the flag, false to clear it.
 */
ForwardingFlags.prototype.setAdvertise = function(value) { this.advertise = value; };

/**
 * Set the value of the "last" flag
 * @param {number} value true to set the flag, false to clear it.
 */
ForwardingFlags.prototype.setLast = function(value) { this.last = value; };

/**
 * Set the value of the "capture" flag
 * @param {number} value true to set the flag, false to clear it.
 */
ForwardingFlags.prototype.setCapture = function(value) { this.capture = value; };

/**
 * Set the value of the "local" flag
 * @param {number} value true to set the flag, false to clear it.
 */
ForwardingFlags.prototype.setLocal = function(value) { this.local = value; };

/**
 * Set the value of the "tap" flag
 * @param {number} value true to set the flag, false to clear it.
 */
ForwardingFlags.prototype.setTap = function(value) { this.tap = value; };

/**
 * Set the value of the "captureOk" flag
 * @param {number} value true to set the flag, false to clear it.
 */
ForwardingFlags.prototype.setCaptureOk = function(value) { this.captureOk = value; };
