/**
 * Copyright (C) 2015-2018 Regents of the University of California.
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

// Don't require modules since this is meant for the browser, not Node.js.

/**
 * IndexedDbProducerDb extends ProducerDb to implement storage of keys for the
 * producer using the browser's IndexedDB service. It contains one table that
 * maps time slots (to the nearest hour) to the content key created for that
 * time slot.
 * Create an IndexedDbProducerDb to use the given IndexedDB database name.
 * @param {string} databaseName IndexedDB database name.
 * @note This class is an experimental feature. The API may change.
 * @constructor
 */
var IndexedDbProducerDb = function IndexedDbProducerDb(databaseName)
{
  ProducerDb.call(this);

  this.database = new Dexie(databaseName);
  this.database.version(1).stores({
    // "timeSlot" is the hour-based time slot as hours since Jan 1, 1970 UTC. // number
    // "key" is the encoded key // Uint8Array
    contentKeys: "timeSlot"
  });
  this.database.open();
};

IndexedDbProducerDb.prototype = new ProducerDb();
IndexedDbProducerDb.prototype.name = "IndexedDbProducerDb";

/**
 * Check if a content key exists for the hour covering timeSlot.
 * @param {number} timeSlot The time slot as milliseconds since Jan 1, 1970 UTC.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise that returns true if there is a content key for
 * timeSlot (else false), or that is rejected with ProducerDb.Error for a
 * database error.
 */
IndexedDbProducerDb.prototype.hasContentKeyPromise = function(timeSlot, useSync)
{
  if (useSync)
    return Promise.reject(new ProducerDb.Error(new Error
      ("IndexedDbProducerDb.hasContentKeyPromise is only supported for async")));

  var fixedTimeSlot = ProducerDb.getFixedTimeSlot(timeSlot);

  return this.database.contentKeys.get(fixedTimeSlot)
  .then(function(contentKeysEntry) {
    return Promise.resolve(contentKeysEntry != undefined);
  })
  .catch(function(ex) {
    return Promise.reject(new ProducerDb.Error(new Error
      ("IndexedDbProducerDb.hasContentKeyPromise: Error: " + ex)));
  });
};

/**
 * Get the content key for the hour covering timeSlot.
 * @param {number} timeSlot The time slot as milliseconds since Jan 1, 1970 UTC.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise that returns a Blob with the encoded key, or that
 * is rejected with ProducerDb.Error if there is no key covering timeSlot, or
 * other database error
 */
IndexedDbProducerDb.prototype.getContentKeyPromise = function(timeSlot, useSync)
{
  if (useSync)
    return Promise.reject(new ProducerDb.Error(new Error
      ("IndexedDbProducerDb.getContentKeyPromise is only supported for async")));

  var fixedTimeSlot = ProducerDb.getFixedTimeSlot(timeSlot);

  return this.database.contentKeys.get(fixedTimeSlot)
  .then(function(contentKeysEntry) {
    if (contentKeysEntry)
      return Promise.resolve(new Blob(contentKeysEntry.key));
    else
      return Promise.reject(new ProducerDb.Error(new Error
        ("IndexedDbProducerDb.getContentKeyPromise: Cannot get the key from the database")));
  }, function(ex) {
    return Promise.reject(new ProducerDb.Error(new Error
      ("IndexedDbProducerDb.getContentKeyPromise: Error: " + ex)));
  });
};

/**
 * Add key as the content key for the hour covering timeSlot.
 * @param {number} timeSlot The time slot as milliseconds since Jan 1, 1970 UTC.
 * @param {Blob} key The encoded key.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise that fulfills when the key is added, or that
 * is rejected with ProducerDb.Error if a key for the same hour already exists
 * in the database, or other database error.
 */
IndexedDbProducerDb.prototype.addContentKeyPromise = function
  (timeSlot, key, useSync)
{
  if (useSync)
    return Promise.reject(new ProducerDb.Error(new Error
      ("IndexedDbProducerDb.addContentKeyPromise is only supported for async")));

  var fixedTimeSlot = ProducerDb.getFixedTimeSlot(timeSlot);

  // Add rejects if the primary key already exists.
  return this.database.contentKeys.add
    ({ timeSlot: fixedTimeSlot, key: key.buf() })
  .catch(function(ex) {
    return Promise.reject(new ProducerDb.Error(new Error
      ("IndexedDbProducerDb.addContentKeyPromise: Error: " + ex)));
  });
};

/**
 * Delete the content key for the hour covering timeSlot. If there is no key for
 * the time slot, do nothing.
 * @param {number} timeSlot The time slot as milliseconds since Jan 1, 1970 UTC.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise that fulfills when the key is deleted (or there
 * is no such key), or that is rejected with ProducerDb.Error for a database
 * error.
 */
IndexedDbProducerDb.prototype.deleteContentKeyPromise = function(timeSlot, useSync)
{
  if (useSync)
    return Promise.reject(new ProducerDb.Error(new Error
      ("IndexedDbProducerDb.deleteContentKeyPromise is only supported for async")));

  var fixedTimeSlot = ProducerDb.getFixedTimeSlot(timeSlot);

  return this.database.contentKeys.delete(fixedTimeSlot)
  .catch(function(ex) {
    return Promise.reject(new ProducerDb.Error(new Error
      ("IndexedDbProducerDb.deleteContentKeyPromise: Error: " + ex)));
  });
};
