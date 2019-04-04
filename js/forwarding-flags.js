/**
 * Copyright (C) 2013-2019 Regents of the University of California.
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
var RegistrationOptions = require('./registration-options.js').RegistrationOptions;

/**
 * Create a new ForwardingFlags object, possibly copying values from another
 * object.
 * @param {ForwardingFlags} value (optional) If value is a
 * RegistrationOptions (or ForwardingFlags), copy its values. If value is
 * omitted, the type is the default with "childInherit" true and other flags
 * false.
 * @deprecated Use RegistrationOptions.
 * @constructor
 */
var ForwardingFlags = function ForwardingFlags(value)
{
  // Call the base constructor.
  RegistrationOptions.call(this, value);
};

ForwardingFlags.prototype = new RegistrationOptions();

exports.ForwardingFlags = ForwardingFlags;

ForwardingFlags.NfdForwardingFlags_CHILD_INHERIT = RegistrationOptions.NfdForwardingFlags_CHILD_INHERIT;
ForwardingFlags.NfdForwardingFlags_CAPTURE       = RegistrationOptions.NfdForwardingFlags_CAPTURE;
