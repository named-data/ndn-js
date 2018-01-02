/**
 * Copyright (C) 2015-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt src/producer-db https://github.com/named-data/ndn-group-encrypt
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
var SyncPromise = require('../util/sync-promise.js').SyncPromise;

/**
 * ProducerDb is a base class for the storage of keys for the producer. It contains
 * one table that maps time slots (to the nearest hour) to the content key
 * created for that time slot. A subclass must implement the methods. For
 * example, see Sqlite3ProducerDb (for Nodejs) or IndexedDbProducerDb (for the
 * browser).
 * @note This class is an experimental feature. The API may change.
 * @constructor
 */
var ProducerDb = function ProducerDb()
{
};

exports.ProducerDb = ProducerDb;

/**
 * Create a new ProducerDb.Error to report an error using ProducerDb
 * methods, wrapping the given error object.
 * Call with: throw new ProducerDb.Error(new Error("message")).
 * @constructor
 * @param {Error} error The exception created with new Error.
 */
ProducerDb.Error = function ProducerDbError(error)
{
  if (error) {
    error.__proto__ = ProducerDb.Error.prototype;
    return error;
  }
};

ProducerDb.Error.prototype = new Error();
ProducerDb.Error.prototype.name = "ProducerDbError";

/**
 * Check if a content key exists for the hour covering timeSlot.
 * @param {number} timeSlot The time slot as milliseconds since Jan 1, 1970 UTC.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that returns true if there is a
 * content key for timeSlot (else false), or that is rejected with
 * ProducerDb.Error for a database error.
 */
ProducerDb.prototype.hasContentKeyPromise = function(timeSlot, useSync)
{
  return SyncPromise.reject(new Error
    ("ProducerDb.hasContentKeyPromise is not implemented"));
};

/**
 * Get the content key for the hour covering timeSlot.
 * @param {number} timeSlot The time slot as milliseconds since Jan 1, 1970 UTC.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that returns a Blob with the encoded
 * key, or that is rejected with ProducerDb.Error if there is no key covering
 * timeSlot, or other database error
 */
ProducerDb.prototype.getContentKeyPromise = function(timeSlot, useSync)
{
  return SyncPromise.reject(new Error
    ("ProducerDb.getContentKeyPromise is not implemented"));
};

/**
 * Add key as the content key for the hour covering timeSlot.
 * @param {number} timeSlot The time slot as milliseconds since Jan 1, 1970 UTC.
 * @param {Blob} key The encoded key.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that fulfills when the key is added,
 * or that is rejected with ProducerDb.Error if a key for the same hour already
 * exists in the database, or other database error.
 */
ProducerDb.prototype.addContentKeyPromise = function
  (timeSlot, key, useSync)
{
  return SyncPromise.reject(new Error
    ("ProducerDb.addContentKeyPromise is not implemented"));
};

/**
 * Delete the content key for the hour covering timeSlot. If there is no key for
 * the time slot, do nothing.
 * @param {number} timeSlot The time slot as milliseconds since Jan 1, 1970 UTC.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that fulfills when the key is deleted
 * (or there is no such key), or that is rejected with ProducerDb.Error for a
 * database error.
 */
ProducerDb.prototype.deleteContentKeyPromise = function(timeSlot, useSync)
{
  return SyncPromise.reject(new Error
    ("ProducerDb.deleteContentKeyPromise is not implemented"));
};

/**
 * Get the hour-based time slot.
 * @param {number} timeSlot The time slot as milliseconds since Jan 1, 1970 UTC.
 * @return {number} The hour-based time slot as hours since Jan 1, 1970 UTC.
 */
ProducerDb.getFixedTimeSlot = function(timeSlot)
{
  return Math.floor(Math.round(timeSlot) / 3600000.0);
};
