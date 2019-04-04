/**
 * Copyright (C) 2019 Regents of the University of California.
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
 * A RegistrationOptions holds the options used when registering with the
 * forwarder to specify how to forward an interest and other options. We use a
 * separate RegistrationOptions object to retain future compatibility if the
 * format of the registration command is changed.
 * (This class was renamed from ForwardingFlags, which is deprecated.)
 * Create a new RegistrationOptions object, possibly copying values from another
 * object.
 * @param {RegistrationOptions} value (optional) If value is a
 * RegistrationOptions, copy its values. If value is omitted, the type is the
 * default with "childInherit" true and other flags false.
 * @constructor
 */
var RegistrationOptions = function RegistrationOptions(value)
{
  if (typeof value === 'object' && value instanceof RegistrationOptions) {
    // Make a copy.
    this.childInherit = value.childInherit;
    this.capture = value.capture;
    this.origin = value.origin;
  }
  else {
    this.childInherit = true;
    this.capture = false;
    this.origin = null;
  }
};

exports.RegistrationOptions = RegistrationOptions;

RegistrationOptions.NfdForwardingFlags_CHILD_INHERIT = 1;
RegistrationOptions.NfdForwardingFlags_CAPTURE       = 2;

/**
 * Get an integer with the bits set according to the NFD forwarding flags as
 * used in the ControlParameters of the command interest.
 * @return {number} An integer with the bits set.
 */
RegistrationOptions.prototype.getNfdForwardingFlags = function()
{
  var result = 0;

  if (this.childInherit)
    result |= RegistrationOptions.NfdForwardingFlags_CHILD_INHERIT;
  if (this.capture)
    result |= RegistrationOptions.NfdForwardingFlags_CAPTURE;

  return result;
};

/**
 * Set the flags according to the NFD forwarding flags as used in the
 * ControlParameters of the command interest.
 * This ignores the origin value.
 * @param {number} nfdForwardingFlags An integer with the bits set.
 * @return {RegistrationOptions} This RegistrationOptions so that you can chain
 * calls to update values.
 */
RegistrationOptions.prototype.setNfdForwardingFlags = function(nfdForwardingFlags)
{
  this.childInherit =
    ((nfdForwardingFlags & RegistrationOptions.NfdForwardingFlags_CHILD_INHERIT) != 0);
  this.capture =
    ((nfdForwardingFlags & RegistrationOptions.NfdForwardingFlags_CAPTURE) != 0);
  return this;
};

/**
 * Get the value of the "childInherit" flag.
 * @return {Boolean} true if the flag is set, false if it is cleared.
 */
RegistrationOptions.prototype.getChildInherit = function() { return this.childInherit; };

/**
 * Get the value of the "capture" flag.
 * @return {Boolean} true if the flag is set, false if it is cleared.
 */
RegistrationOptions.prototype.getCapture = function() { return this.capture; };

/**
 * Get the origin value.
 * @return {number} The origin value, or null if not specified.
 */
RegistrationOptions.prototype.getOrigin = function()
{
  return this.origin;
};

/**
 * Set the value of the "childInherit" flag
 * @param {number} childInherit true to set the "childInherit" flag, false to
 * clear it.
 * @return {RegistrationOptions} This RegistrationOptions so that you can chain
 * calls to update values.
 */
RegistrationOptions.prototype.setChildInherit = function(childInherit)
{ 
  this.childInherit = childInherit;
  return this;
};

/**
 * Set the value of the "capture" flag
 * @param {number} capture true to set the "capture" flag, false to clear it.
 * @return {RegistrationOptions} This RegistrationOptions so that you can chain
 * calls to update values.
 */
RegistrationOptions.prototype.setCapture = function(capture)
{ 
  this.capture = capture;
  return this;
};

/**
 * Set the origin value.
 * @param {number} origin The new origin value, or null for not specified.
 * @return {RegistrationOptions} This RegistrationOptions so that you can chain
 * calls to update values.
 */
RegistrationOptions.prototype.setOrigin = function(origin)
{
  this.origin = origin;
  return this;
};
