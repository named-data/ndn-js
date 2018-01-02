/**
 * Copyright (C) 2013-2018 Regents of the University of California.
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
var WireFormat = require('./wire-format.js').WireFormat; /** @ignore */
var Tlv0_1_1WireFormat = require('./tlv-0_1_1-wire-format.js').Tlv0_1_1WireFormat;

/**
 * A Tlv0_1WireFormat extends Tlv0_1_1WireFormat so that it is an alias in case
 * any applications use Tlv0_1WireFormat directly.  These two wire formats are
 * the same except that Tlv0_1_1WireFormat adds support for
 * Sha256WithEcdsaSignature.
 * @constructor
 */
var Tlv0_1WireFormat = function Tlv0_1WireFormat()
{
  // Inherit from Tlv0_1_1WireFormat.
  Tlv0_1_1WireFormat.call(this);
};

Tlv0_1WireFormat.prototype = new Tlv0_1_1WireFormat();
Tlv0_1WireFormat.prototype.name = "Tlv0_1WireFormat";

exports.Tlv0_1WireFormat = Tlv0_1WireFormat;

// Default object.
Tlv0_1WireFormat.instance = null;

/**
 * Get a singleton instance of a Tlv0_1WireFormat.
 * @return {Tlv0_1WireFormat} The singleton instance.
 */
Tlv0_1WireFormat.get = function()
{
  if (Tlv0_1WireFormat.instance === null)
    Tlv0_1WireFormat.instance = new Tlv0_1WireFormat();
  return Tlv0_1WireFormat.instance;
};
