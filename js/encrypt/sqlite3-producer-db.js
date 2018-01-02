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
var Blob = require('../util/blob.js').Blob; /** @ignore */
var Sqlite3Promise = require('../util/sqlite3-promise.js').Sqlite3Promise; /** @ignore */
var TlvWireFormat = require('../encoding/tlv-wire-format').TlvWireFormat; /** @ignore */
var SyncPromise = require('../util/sync-promise.js').SyncPromise; /** @ignore */
var ProducerDb = require('./producer-db.js').ProducerDb;

/**
 * Sqlite3ProducerDb extends ProducerDb to implement storage of keys for the
 * producer using SQLite3. It contains one table that maps time slots (to the
 * nearest hour) to the content key created for that time slot.
 * Create a Sqlite3ProducerDb to use the given SQLite3 file.
 * @param {string} databaseFilePath The path of the SQLite file.
 * @throws ProducerDb.Error for a database error.
 * @note This class is an experimental feature. The API may change.
 * @constructor
 */
var Sqlite3ProducerDb = function Sqlite3ProducerDb(databaseFilePath)
{
  // Call the base constructor.
  ProducerDb.call(this);

  this.database_ = new Sqlite3Promise
    (databaseFilePath, Sqlite3ProducerDb.initializeDatabasePromise_);
};

Sqlite3ProducerDb.prototype = new ProducerDb();
Sqlite3ProducerDb.prototype.name = "Sqlite3ProducerDb";

exports.Sqlite3ProducerDb = Sqlite3ProducerDb;

/**
 * Check if a content key exists for the hour covering timeSlot.
 * @param {number} timeSlot The time slot as milliseconds since Jan 1, 1970 UTC.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise that returns true if there is a content key for
 * timeSlot (else false), or that is rejected with ProducerDb.Error for a
 * database error.
 */
Sqlite3ProducerDb.prototype.hasContentKeyPromise = function(timeSlot, useSync)
{
  if (useSync)
    return Promise.reject(new ProducerDb.Error(new Error
      ("Sqlite3ProducerDb.hasContentKeyPromise is only supported for async")));

  var fixedTimeSlot = ProducerDb.getFixedTimeSlot(timeSlot);

  return this.getPromise_
    ("SELECT key FROM contentkeys where timeslot=?", fixedTimeSlot)
  .then(function(row) {
    if (row)
      return Promise.resolve(true);
    else
      return Promise.resolve(false);
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
Sqlite3ProducerDb.prototype.getContentKeyPromise = function(timeSlot, useSync)
{
  if (useSync)
    return Promise.reject(new ProducerDb.Error(new Error
      ("Sqlite3ProducerDb.getContentKeyPromise is only supported for async")));

  var fixedTimeSlot = ProducerDb.getFixedTimeSlot(timeSlot);

  return this.getPromise_
    ("SELECT key FROM contentkeys where timeslot=?", fixedTimeSlot)
  .then(function(row) {
    if (row)
      return Promise.resolve(new Blob(row.key, false));
    else
      return Promise.reject(new ProducerDb.Error(new Error
        ("Sqlite3ProducerDb.getContentKeyPromise: Cannot get the key from the database")));
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
Sqlite3ProducerDb.prototype.addContentKeyPromise = function
  (timeSlot, key, useSync)
{
  if (useSync)
    return Promise.reject(new ProducerDb.Error(new Error
      ("Sqlite3ProducerDb.addContentKeyPromise is only supported for async")));

  var fixedTimeSlot = ProducerDb.getFixedTimeSlot(timeSlot);

  return this.runPromise_
    ("INSERT INTO contentkeys (timeslot, key) values (?, ?)",
     [fixedTimeSlot, key.buf()]);
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
Sqlite3ProducerDb.prototype.deleteContentKeyPromise = function(timeSlot, useSync)
{
  if (useSync)
    return Promise.reject(new ProducerDb.Error(new Error
      ("Sqlite3ProducerDb.deleteContentKeyPromise is only supported for async")));

  var fixedTimeSlot = ProducerDb.getFixedTimeSlot(timeSlot);

  return this.runPromise_
    ("DELETE FROM contentkeys WHERE timeslot=?", fixedTimeSlot);
};

/**
 * Call Sqlite3Promise.runPromise, wrapping an Error in ProducerDb.Error.
 */
Sqlite3ProducerDb.prototype.runPromise_ = function(sql, params)
{
  return this.database_.runPromise(sql, params)
  .catch(function(error) {
    return Promise.reject(new ProducerDb.Error(error));
  });
};

/**
 * Call Sqlite3Promise.getPromise, wrapping an Error in ProducerDb.Error.
 */
Sqlite3ProducerDb.prototype.getPromise_ = function(sql, params)
{
  return this.database_.getPromise(sql, params)
  .catch(function(error) {
    return Promise.reject(new ProducerDb.Error(error));
  });
};

Sqlite3ProducerDb.initializeDatabasePromise_ = function(database)
{
  return database.runPromise(Sqlite3ProducerDb.INITIALIZATION1)
  .then(function() {
    return database.runPromise(Sqlite3ProducerDb.INITIALIZATION2);
  });
};

Sqlite3ProducerDb.INITIALIZATION1 =
  "CREATE TABLE IF NOT EXISTS                         \n" +
  "  contentkeys(                                     \n" +
  "    rowId            INTEGER PRIMARY KEY,          \n" +
  "    timeSlot         INTEGER,                      \n" +
  "    key              BLOB NOT NULL                 \n" +
  "  );                                               \n";
Sqlite3ProducerDb.INITIALIZATION2 =
  "CREATE UNIQUE INDEX IF NOT EXISTS                  \n" +
  "   timeSlotIndex ON contentkeys(timeSlot);         \n";
