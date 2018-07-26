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
var NdnCommon = require('../util/ndn-common.js').NdnCommon; /** @ignore */
var LOG = require('../log.js').Log.LOG;

/**
 * A PendingInterestTable is an internal class to hold a list of pending
 * interests with their callbacks.
 * @constructor
 */
var PendingInterestTable = function PendingInterestTable()
{
  this.table_ = []; // of Entry
  this.removeRequests_ = []; // of number
};

exports.PendingInterestTable = PendingInterestTable;

/**
 * PendingInterestTable.Entry holds the callbacks and other fields for an entry
 * in the pending interest table.
 * Create a new Entry with the given fields. Note: You should not call this
 * directly but call PendingInterestTable.add.
 * @constructor
 */
PendingInterestTable.Entry = function PendingInterestTableEntry
  (pendingInterestId, interest, onData, onTimeout, onNetworkNack)
{
  this.pendingInterestId_ = pendingInterestId;
  this.interest_ = interest;
  this.onData_ = onData;
  this.onTimeout_ = onTimeout;
  this.onNetworkNack_ = onNetworkNack;
  this.timerId_ = -1;
};

/**
 * Get the pendingInterestId given to the constructor.
 * @return {number} The pendingInterestId.
 */
PendingInterestTable.Entry.prototype.getPendingInterestId = function()
{
  return this.pendingInterestId_;
};

/**
 * Get the interest given to the constructor (from Face.expressInterest).
 * @return {Interest} The interest. NOTE: You must not change the interest
 * object - if you need to change it then make a copy.
 */
PendingInterestTable.Entry.prototype.getInterest = function()
{
  return this.interest_;
};

/**
 * Get the OnData callback given to the constructor.
 * @return {function} The OnData callback.
 */
PendingInterestTable.Entry.prototype.getOnData = function()
{
  return this.onData_;
};

/**
 * Get the OnNetworkNack callback given to the constructor.
 * @return {function} The OnNetworkNack callback.
 */
PendingInterestTable.Entry.prototype.getOnNetworkNack = function()
{
  return this.onNetworkNack_;
};

/**
* Call onTimeout_ (if defined). This ignores exceptions from the call to
* onTimeout_.
*/
PendingInterestTable.Entry.prototype.callTimeout = function()
{
  if (this.onTimeout_) {
    try {
      this.onTimeout_(this.interest_);
    } catch (ex) {
      console.log("Error in onTimeout: " + NdnCommon.getErrorWithStackTrace(ex));
    }
  }
};

/**
 * Call setTimeout(callback, milliseconds) and remember the timer ID. If the
 * timer ID has already been set on a prevous call, do nothing.
 */
PendingInterestTable.Entry.prototype.setTimeout = function(callback, milliseconds)
{
  if (this.timerId_ !== -1)
    // Already set a timeout.
    return;
  this.timerId_ = setTimeout(callback, milliseconds);
};

/**
 * Clear the timeout timer and reset the timer ID.
 */
PendingInterestTable.Entry.prototype.clearTimeout = function()
{
  if (this.timerId_ !== -1) {
    clearTimeout(this.timerId_);
    this.timerId_ = -1;
  }
};

/**
 * Add a new entry to the pending interest table. Also set a timer to call the
 * timeout. However, if removePendingInterest was already called with the
 * pendingInterestId, don't add an entry and return null.
 * @param {number} pendingInterestId
 * @param {Interest} interestCopy
 * @param {function} onData
 * @param {function} onTimeout
 * @param {function} onNetworkNack
 * @return {PendingInterestTable.Entry} The new PendingInterestTable.Entry, or
 * null if removePendingInterest was already called with the pendingInterestId.
 */
PendingInterestTable.prototype.add = function
  (pendingInterestId, interestCopy, onData, onTimeout, onNetworkNack)
{
  var removeRequestIndex = this.removeRequests_.indexOf(pendingInterestId);
  if (removeRequestIndex >= 0) {
    // removePendingInterest was called with the pendingInterestId returned by
    //   expressInterest before we got here, so don't add a PIT entry.
    this.removeRequests_.splice(removeRequestIndex, 1);
    return null;
  }

  var entry = new PendingInterestTable.Entry
    (pendingInterestId, interestCopy, onData, onTimeout, onNetworkNack);
  this.table_.push(entry);

  // Set interest timer.
  var timeoutMilliseconds = (interestCopy.getInterestLifetimeMilliseconds() || 4000);
  var thisTable = this;
  var timeoutCallback = function() {
    if (LOG > 1) console.log("Interest time out: " + interestCopy.getName().toUri());

    // Remove the entry from the table.
    var index = thisTable.table_.indexOf(entry);
    if (index >= 0)
      thisTable.table_.splice(index, 1);

    entry.callTimeout();
  };

  entry.setTimeout(timeoutCallback, timeoutMilliseconds);
  return entry;
};

/**
 * Find all entries from the pending interest table where data conforms to
 * the entry's interest selectors, remove the entries from the table, and add to
 * the entries list.
 * @param {Data} data The incoming Data packet to find the interest for.
 * @param {Array<PendingInterestTable.Entry>} entries Add matching
 * PendingInterestTable.Entry from the pending interest table. The caller should
 * pass in an empty array.
 */
PendingInterestTable.prototype.extractEntriesForExpressedInterest = function
  (data, entries)
{
  // Go backwards through the list so we can erase entries.
  for (var i = this.table_.length - 1; i >= 0; --i) {
    var pendingInterest = this.table_[i];
    if (pendingInterest.getInterest().matchesData(data)) {
      pendingInterest.clearTimeout();
      entries.push(pendingInterest);
      this.table_.splice(i, 1);
    }
  }
};

/**
 * Find all entries from the pending interest table where the OnNetworkNack
 * callback is not null and the entry's interest is the same as the given
 * interest, remove the entries from the table, and add to the entries list.
 * (We don't remove the entry if the OnNetworkNack callback is null so that
 * OnTimeout will be called later.) The interests are the same if their default
 * wire encoding is the same (which has everything including the name, nonce,
 * link object and selectors).
 * @param {Interest} interest The Interest to search for (typically from a Nack
 * packet).
 * @param {Array<PendingInterestTable.Entry>} entries Add matching
 * PendingInterestTable.Entry from the pending interest table. The caller should
 * pass in an empty array.
 */
PendingInterestTable.prototype.extractEntriesForNackInterest = function
  (interest, entries)
{
  var encoding = interest.wireEncode();

  // Go backwards through the list so we can erase entries.
  for (var i = this.table_.length - 1; i >= 0; --i) {
    var pendingInterest = this.table_[i];
    if (pendingInterest.getOnNetworkNack() == null)
      continue;

    // wireEncode returns the encoding cached when the interest was sent (if
    // it was the default wire encoding).
    if (pendingInterest.getInterest().wireEncode().equals(encoding)) {
      pendingInterest.clearTimeout();
      entries.push(pendingInterest);
      this.table_.splice(i, 1);
    }
  }
};

/**
 * Remove the pending interest entry with the pendingInterestId from the pending
 * interest table. This does not affect another pending interest with a
 * different pendingInterestId, even if it has the same interest name.
 * If there is no entry with the pendingInterestId, do nothing.
 * @param {number} pendingInterestId The ID returned from expressInterest.
 */
PendingInterestTable.prototype.removePendingInterest = function
  (pendingInterestId)
{
  if (pendingInterestId == null)
    return;

  // Go backwards through the list so we can erase entries.
  // Remove all entries even though pendingInterestId should be unique.
  var count = 0;
  for (var i = this.table_.length - 1; i >= 0; --i) {
    var entry = this.table_[i];
    if (entry.getPendingInterestId() == pendingInterestId) {
      entry.clearTimeout();
      this.table_.splice(i, 1);
      ++count;
    }
  }

  if (count === 0)
    if (LOG > 0) console.log
      ("removePendingInterest: Didn't find pendingInterestId " + pendingInterestId);

  if (count === 0) {
    // The pendingInterestId was not found. Perhaps this has been called before
    //   the callback in expressInterest can add to the PIT. Add this
    //   removal request which will be checked before adding to the PIT.
    if (this.removeRequests_.indexOf(pendingInterestId) < 0)
      // Not already requested, so add the request.
      this.removeRequests_.push(pendingInterestId);
  }
};
