/**
 * Copyright (C) 2016-2018 Regents of the University of California.
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
var Name = require('./name.js').Name; /** @ignore */
var Blob = require('./util/blob.js').Blob; /** @ignore */
var WireFormat = require('./encoding/wire-format.js').WireFormat;

/**
 * A DelegationSet holds a list of DelegationSet.Delegation entries which is
 * used as the content of a Link instance. If you add elements with add(), then
 * the list is a set sorted by preference number then by name. But wireDecode
 * will add the elements from the wire encoding, preserving the given order and
 * possible duplicates (in which case a DelegationSet really holds a "list" and
 * not necessarily a "set").
 *
 * Create a new DelegationSet object, possibly copying values from another
 * object.
 *
 * @param {DelegationSet} value (optional) If value is a DelegationSet, copy its
 * values.
 * @constructor
 */
var DelegationSet = function DelegationSet(value)
{
  if (typeof value === 'object' && value instanceof DelegationSet)
    // Copy the list.
    this.delegations_ = value.delegations_.slice(0);
  else
    this.delegations_ = []; // of DelegationSet.Delegation.

  this.changeCount_ = 0;
};

exports.DelegationSet = DelegationSet;

/**
 * A DelegationSet.Delegation holds a preference number and delegation name.
 * Create a new DelegationSet.Delegation with the given values.
 * @param {number} preference The preference number.
 * @param {Name} name The delegation name. This makes a copy of the name.
 * @constructor
 */
DelegationSet.Delegation = function DelegationSetDelegation(preference, name)
{
  this.preference_ = preference;
  this.name_ = new Name(name);
};

/**
 * Get the preference number.
 * @return {number} The preference number.
 */
DelegationSet.Delegation.prototype.getPreference = function()
{
  return this.preference_;
};

/**
 * Get the delegation name.
 * @return {Name} The delegation name. NOTE: You must not change the name object -
 * if you need to change it then make a copy.
 */
DelegationSet.Delegation.prototype.getName = function()
{
  return this.name_;
};

/**
 * Compare this Delegation with other according to the ordering, based first
 * on the preference number, then on the delegation name.
 * @param {DelegationSet.Delegation} other The other Delegation to compare with.
 * @return {number} 0 If they compare equal, -1 if this Delegation comes before
 * other in the ordering, or 1 if this Delegation comes after.
 */
DelegationSet.Delegation.prototype.compare = function(other)
{
  if (this.preference_ < other.preference_)
    return -1;
  if (this.preference_ > other.preference_)
    return 1;

  return this.name_.compare(other.name_);
};

/**
 * Add a new DelegationSet.Delegation to the list of delegations, sorted by
 * preference number then by name. If there is already a delegation with the
 * same name, update its preference, and remove any extra delegations with the
 * same name.
 * @param {number} preference The preference number.
 * @param {Name} name The delegation name. This makes a copy of the name.
 */
DelegationSet.prototype.add = function(preference, name)
{
  this.remove(name);

  var newDelegation = new DelegationSet.Delegation(preference, name);
  // Find the index of the first entry where it is not less than newDelegation.
  var i = 0;
  while (i < this.delegations_.length) {
    if (this.delegations_[i].compare(newDelegation) >= 0)
      break;

    ++i;
  }

  this.delegations_.splice(i, 0, newDelegation);
  ++this.changeCount_;
};

/**
 * Add a new DelegationSet.Delegation to the end of the list of delegations,
 * without sorting or updating any existing entries. This is useful for adding
 * preferences from a wire encoding, preserving the supplied ordering and
 * possible duplicates.
 * @param {number} preference The preference number.
 * @param {Name} name The delegation name. This makes a copy of the name.
 */
DelegationSet.prototype.addUnsorted = function(preference, name)
{
  this.delegations_.push(new DelegationSet.Delegation(preference, name));
  ++this.changeCount_;
};

/**
 * Remove every DelegationSet.Delegation with the given name.
 * @param {Name} name The name to match the name of the delegation(s) to be
 * removed.
 * @return {boolean} True if a DelegationSet.Delegation was removed, otherwise
 * false.
 */
DelegationSet.prototype.remove = function(name)
{
  var wasRemoved = false;
  // Go backwards through the list so we can remove entries.
  for (var i = this.delegations_.length - 1; i >= 0; --i) {
    if (this.delegations_[i].getName().equals(name)) {
      wasRemoved = true;
      this.delegations_.splice(i, 1);
    }
  }

  if (wasRemoved)
    ++this.changeCount_;
  return wasRemoved;
};

/**
 * Clear the list of delegations.
 */
DelegationSet.prototype.clear = function()
{
  this.delegations_ = [];
  ++this.changeCount_;
};

/**
 * Get the number of delegation entries.
 * @return {number} The number of delegation entries.
 */
DelegationSet.prototype.size = function() { return this.delegations_.length; };

/**
 * Get the delegation at the given index, according to the ordering described
 * in add().
 * @param {number} i The index of the component, starting from 0.
 * @return {DelegationSet.Delegation} The delegation at the index.
 */
DelegationSet.prototype.get = function(i) { return this.delegations_[i]; };

/**
 * Find the first delegation with the given name and return its index.
 * @param {Name} name Then name of the delegation to find.
 * @return {number} The index of the delegation, or -1 if not found.
 */
DelegationSet.prototype.find = function(name)
{
  for (var i = 0; i < this.delegations_.length; ++i) {
    if (this.delegations_[i].getName().equals(name))
      return i;
  }

  return -1;
};

/**
 * Encode this DelegationSet for a particular wire format.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * this object. If omitted, use WireFormat.getDefaultWireFormat().
 * @return {Blob} The encoded buffer in a Blob object.
 */
DelegationSet.prototype.wireEncode = function(wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
  return wireFormat.encodeDelegationSet(this);
};

/**
 * Decode the input using a particular wire format and update this DelegationSet.
 * @param {Blob|Buffer} input The buffer with the bytes to decode.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to decode
 * this object. If omitted, use WireFormat.getDefaultWireFormat().
 */
DelegationSet.prototype.wireDecode = function(input, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());
  if (typeof input === 'object' && input instanceof Blob)
    // Input is a blob, so get its buf() and set copy false.
    wireFormat.decodeDelegationSet(this, input.buf(), false);
  else
    wireFormat.decodeDelegationSet(this, input, true);
};

/**
 * Get the change count, which is incremented each time this object is changed.
 * @return {number} The change count.
 */
DelegationSet.prototype.getChangeCount = function()
{
  return this.changeCount_;
};
