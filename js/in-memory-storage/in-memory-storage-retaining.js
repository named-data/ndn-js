/**
 * Copyright (C) 2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/ims/in-memory-storage-persistent.cpp
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
var Name = require('../name.js').Name; /** @ignore */
var Data = require('../data.js').Data;

/**
 * InMemoryStorageRetaining provides an application cache with in-memory
 * storage, of which no eviction policy will be employed. Entries will only be
 * evicted by explicit application control.
 * Note: In ndn-cxx, this class is called InMemoryStoragePersistent, but
 * "persistent" misleadingly sounds like persistent on-disk storage.
 *
 * Create an InMemoryStorageRetaining.
 * @constructor
 */
var InMemoryStorageRetaining = function InMemoryStorageRetaining()
{
  // The dictionary key is the Data packet Name URI string. The value is a Data.
  this.cache_ = [];
};

exports.InMemoryStorageRetaining = InMemoryStorageRetaining;

/**
 * Insert a Data packet. If a Data packet with the same name, including the
 * implicit digest, already exists, replace it.
 * @param {Data} data The packet to insert, which is copied.
 */
InMemoryStorageRetaining.prototype.insert = function(data)
{
  this.cache_[data.getFullName().toUri()] = new Data(data);
};

/**
 * Find the best match Data for an Interest.
 * @param {Interest} interest The Interest with the Name of the Data packet to
 * find.
 * @returns {Data} The best match if any, otherwise None. You should not modify
 * the returned object. If you need to modify it then you must make a copy.
 */
InMemoryStorageRetaining.prototype.find = function(interest)
{
  for (var nameUri in this.cache_) {
    // Debug: Check selectors, especially CanBePrefix.
    if (interest.getName().isPrefixOf(new Name(nameUri)))
      return this.cache_[nameUri];
  }
};

/**
 * Get the number of packets stored in the in-memory storage.
 * @returns {number} The number of packets.
 */
InMemoryStorageRetaining.prototype.size = function()
{
  return Object.keys(this.cache_).length;
};
