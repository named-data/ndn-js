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
var LOG = require('../log.js').Log.LOG;

/**
 * A RegisteredPrefixTable is an internal class to hold a list of registered
 * prefixes with information necessary to remove the registration later.
 * @param {InterestFilterTable} interestFilterTable See removeRegisteredPrefix(),
 * which may call interestFilterTable.unsetInterestFilter().
 * @constructor
 */
var RegisteredPrefixTable = function RegisteredPrefixTable(interestFilterTable)
{
  this.interestFilterTable_ = interestFilterTable;
  this.table_ = []; // of Entry
  this.removeRequests_ = []; // of number
};

exports.RegisteredPrefixTable = RegisteredPrefixTable;

/**
 * Add a new entry to the table. However, if removeRegisteredPrefix was already
 * called with the registeredPrefixId, don't add an entry and return false.
 * @param {number} registeredPrefixId The ID from Node.getNextEntryId().
 * @param {Name} prefix The name prefix.
 * @param {number} relatedInterestFilterId (optional) The related
 * interestFilterId for the filter set in the same registerPrefix operation. If
 * omitted, set to 0.
 * return {boolean} True if added an entry, false if removeRegisteredPrefix was
 * already called with the registeredPrefixId.
 */
RegisteredPrefixTable.prototype.add = function
  (registeredPrefixId, prefix, relatedInterestFilterId)
{
  var removeRequestIndex = this.removeRequests_.indexOf(registeredPrefixId);
  if (removeRequestIndex >= 0) {
    // removeRegisteredPrefix was called with the registeredPrefixId returned by
    //   registerPrefix before we got here, so don't add a registered prefix
    //   table entry.
    this.removeRequests_.splice(removeRequestIndex, 1);
    return false;
  }

  this.table_.push(new RegisteredPrefixTable._Entry
    (registeredPrefixId, prefix, relatedInterestFilterId));
  return true;
};

/**
 * Remove the registered prefix entry with the registeredPrefixId from the
 * registered prefix table. This does not affect another registered prefix with
 * a different registeredPrefixId, even if it has the same prefix name. If an
 * interest filter was automatically created by registerPrefix, also call
 * interestFilterTable_.unsetInterestFilter to remove it.
 * If there is no entry with the registeredPrefixId, do nothing.
 * @param {number} registeredPrefixId The ID returned from registerPrefix.
 */
RegisteredPrefixTable.prototype.removeRegisteredPrefix = function
  (registeredPrefixId)
{
  // Go backwards through the list so we can erase entries.
  // Remove all entries even though registeredPrefixId should be unique.
  var count = 0;
  for (var i = this.table_.length - 1; i >= 0; --i) {
    var entry = this.table_[i];
    if (entry.getRegisteredPrefixId() == registeredPrefixId) {
      ++count;

      if (entry.getRelatedInterestFilterId() > 0)
        // Remove the related interest filter.
        this.interestFilterTable_.unsetInterestFilter
          (entry.getRelatedInterestFilterId());

      this.table_.splice(i, 1);
    }
  }

  if (count === 0)
    if (LOG > 0) console.log
      ("removeRegisteredPrefix: Didn't find registeredPrefixId " + registeredPrefixId);

  if (count === 0) {
    // The registeredPrefixId was not found. Perhaps this has been called before
    //   the callback in registerPrefix can add to the registered prefix table.
    //   Add this removal request which will be checked before adding to the
    //   registered prefix table.
    if (this.removeRequests_.indexOf(registeredPrefixId) < 0)
      // Not already requested, so add the request.
      this.removeRequests_.push(registeredPrefixId);
  }
};

/**
 * RegisteredPrefixTable._Entry holds a registeredPrefixId and information
 * necessary to remove the registration later. It optionally holds a related
 * interestFilterId if the InterestFilter was set in the same registerPrefix
 * operation.
 * Create a RegisteredPrefixTable.Entry with the given values.
 * @param {number} registeredPrefixId The ID from Node.getNextEntryId().
 * @param {Name} prefix The name prefix.
 * @param {number} relatedInterestFilterId (optional) The related
 * interestFilterId for the filter set in the same registerPrefix operation. If
 * omitted, set to 0.
 * @constructor
 */
RegisteredPrefixTable._Entry = function RegisteredPrefixTableEntry
  (registeredPrefixId, prefix, relatedInterestFilterId)
{
  this.registeredPrefixId_ = registeredPrefixId;
  this.prefix_ = prefix;
  this.relatedInterestFilterId_ = relatedInterestFilterId;
};

/**
 * Get the registeredPrefixId given to the constructor.
 * @return {number} The registeredPrefixId.
 */
RegisteredPrefixTable._Entry.prototype.getRegisteredPrefixId = function()
{
  return this.registeredPrefixId_;
};

/**
 * Get the name prefix given to the constructor.
 * @return {Name} The name prefix.
 */
RegisteredPrefixTable._Entry.prototype.getPrefix = function()
{
  return this.prefix_;
};

/**
 * Get the related interestFilterId given to the constructor.
 * @return {number} The related interestFilterId.
 */
RegisteredPrefixTable._Entry.prototype.getRelatedInterestFilterId = function()
{
  return this.relatedInterestFilterId_;
};
