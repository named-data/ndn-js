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
 * An InterestFilterTable is an internal class to hold a list of entries with
 * an interest Filter and its OnInterestCallback.
 * @constructor
 */
var InterestFilterTable = function InterestFilterTable()
{
  this.table_ = []; // of Entry
};

exports.InterestFilterTable = InterestFilterTable;

/**
 * InterestFilterTable.Entry holds an interestFilterId, an InterestFilter and
 * the OnInterestCallback with its related Face.
 * Create a new Entry with the given values.
 * @param {number} interestFilterId The ID from getNextEntryId().
 * @param {InterestFilter} filter The InterestFilter for this entry.
 * @param {function} onInterest The callback to call.
 * @param {Face} face The face on which was called registerPrefix or
 * setInterestFilter which is passed to the onInterest callback.
 * @constructor
 */
InterestFilterTable.Entry = function InterestFilterTableEntry
  (interestFilterId, filter, onInterest, face)
{
  this.interestFilterId_ = interestFilterId;
  this.filter_ = filter;
  this.onInterest_ = onInterest;
  this.face_ = face;
};

/**
 * Get the interestFilterId given to the constructor.
 * @return {number} The interestFilterId.
 */
InterestFilterTable.Entry.prototype.getInterestFilterId = function()
{
  return this.interestFilterId_;
};

/**
 * Get the InterestFilter given to the constructor.
 * @return {InterestFilter} The InterestFilter.
 */
InterestFilterTable.Entry.prototype.getFilter = function()
{
  return this.filter_;
};

/**
 * Get the onInterest callback given to the constructor.
 * @return {function} The onInterest callback.
 */
InterestFilterTable.Entry.prototype.getOnInterest = function()
{
  return this.onInterest_;
};

/**
 * Get the Face given to the constructor.
 * @return {Face} The Face.
 */
InterestFilterTable.Entry.prototype.getFace = function()
{
  return this.face_;
};

/**
 * Add a new entry to the table.
 * @param {number} interestFilterId The ID from Node.getNextEntryId().
 * @param {InterestFilter} filter The InterestFilter for this entry.
 * @param {function} onInterest The callback to call.
 * @param {Face} face The face on which was called registerPrefix or
 * setInterestFilter which is passed to the onInterest callback.
 */
InterestFilterTable.prototype.setInterestFilter = function
  (interestFilterId, filter, onInterest, face)
{
  this.table_.push(new InterestFilterTable.Entry
    (interestFilterId, filter, onInterest, face));
};

/**
 * Find all entries from the interest filter table where the interest conforms
 * to the entry's filter, and add to the matchedFilters list.
 * @param {Interest} interest The interest which may match the filter in
 * multiple entries.
 * @param {Array<InterestFilterTable.Entry>} matchedFilters Add each matching
 * InterestFilterTable.Entry from the interest filter table.  The caller should
 * pass in an empty array.
 */
InterestFilterTable.prototype.getMatchedFilters = function
  (interest, matchedFilters)
{
  for (var i = 0; i < this.table_.length; ++i) {
    var entry = this.table_[i];
    if (entry.getFilter().doesMatch(interest.getName()))
      matchedFilters.push(entry);
  }
};

/**
 * Remove the interest filter entry which has the interestFilterId from the
 * interest filter table. This does not affect another interest filter with a
 * different interestFilterId, even if it has the same prefix name. If there is
 * no entry with the interestFilterId, do nothing.
 * @param {number} interestFilterId The ID returned from setInterestFilter.
 */
InterestFilterTable.prototype.unsetInterestFilter = function(interestFilterId)
{
  // Go backwards through the list so we can erase entries.
  // Remove all entries even though interestFilterId should be unique.
  var count = 0;
  for (var i = this.table_.length - 1; i >= 0; --i) {
    if (this.table_[i].getInterestFilterId() == interestFilterId) {
      ++count;
      this.table_.splice(i, 1);
    }
  }

  if (count === 0)
    if (LOG > 0) console.log
      ("unsetInterestFilter: Didn't find interestFilterId " + interestFilterId);
};
