/**
 * Copyright (C) 2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version, with the additional exemption that
 * compiling, linking, and/or using OpenSSL is allowed.
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
var Interest = require('../../..').Interest; /** @ignore */
var Data = require('../../..').Data; /** @ignore */
var InterestFilter = require('../../..').InterestFilter; /** @ignore */
var InterestFilterTable = require('../../../js/impl/interest-filter-table.js').InterestFilterTable;

/**
 * InMemoryStorageFace extends Face to hold an InMemoryStorageRetaining and
 * use it in expressInterest to instantly reply to an Interest. It also allows
 * calls to registerPrefix to remember an OnInterestCallback.
 *
 * Create an InMemoryStorageFace to use the given storage.
 * @param {InMemoryStorageRetaining} storage The InMemoryStorageRetaining used
 * by expressInterest. If the Data packet for the Interest is found,
 * expressInterest immediately calls onData, otherwise it immediately calls
 * onTimeout.
 * @constructor
 */
var InMemoryStorageFace = function InMemoryStorageFace(storage)
{
  this.storage_ = storage;

  this.sentInterests_ = []; // of Interest
  this.sentData_ = [];      // of Data

  this.interestFilterTable_ = new InterestFilterTable();
};

exports.InMemoryStorageFace = InMemoryStorageFace;

InMemoryStorageFace.prototype.expressInterest = function
  (interest, onData, onTimeout, onNetworkNack)
{
  // Make a copy of the interest.
  this.sentInterests_.push(new Interest(interest));

  var data = this.storage_.find(interest);
  if (data != null) {
    this.sentData_.push(new Data(data));
    onData(interest, data);
  }
  else
    onTimeout(interest);

  return 0;
};

InMemoryStorageFace.prototype.registerPrefix = function
  (prefix, onInterest, onRegisterFailed, onRegisterSuccess, registrationOptions,
   wireFormat)
{
  this.interestFilterTable_.setInterestFilter
    (0, new InterestFilter(prefix), onInterest, this);

  if (onRegisterSuccess != null)
    onRegisterSuccess(prefix, 0);
  return 0;
};

InMemoryStorageFace.prototype.putData = function(data, wireFormat)
{
  this.sentData_.push(new Data(data));
};

/**
 * For each entry from calls to registerPrefix where the Interest matches the
 * prefix, call its OnInterest callback.
 * @param {type} interest
 * @returns {undefined}
 */
InMemoryStorageFace.prototype.receive = function(interest)
{
  var matchedFilters = [];
  this.interestFilterTable_.getMatchedFilters(interest, matchedFilters);
  for (var i = 0; i < matchedFilters.length; ++i) {
    var entry = matchedFilters[i];
    entry.getOnInterest()
     (entry.getFilter().getPrefix(), interest, entry.getFace(),
      entry.getInterestFilterId(), entry.getFilter());
  }
};
