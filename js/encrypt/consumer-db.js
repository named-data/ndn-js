/**
 * Copyright (C) 2015-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt src/consumer-db https://github.com/named-data/ndn-group-encrypt
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
 * ConsumerDb is a base class the storage of decryption keys for the consumer. A
 * subclass must implement the methods. For example, see Sqlite3ConsumerDb (for
 * Nodejs) or IndexedDbConsumerDb (for the browser).
 * @note This class is an experimental feature. The API may change.
 * @constructor
 */
var ConsumerDb = function ConsumerDb()
{
};

exports.ConsumerDb = ConsumerDb;

/**
 * Create a new ConsumerDb.Error to report an error using ConsumerDb
 * methods, wrapping the given error object.
 * Call with: throw new ConsumerDb.Error(new Error("message")).
 * @constructor
 * @param {Error} error The exception created with new Error.
 */
ConsumerDb.Error = function ConsumerDbError(error)
{
  if (error) {
    error.__proto__ = ConsumerDb.Error.prototype;
    return error;
  }
};

ConsumerDb.Error.prototype = new Error();
ConsumerDb.Error.prototype.name = "ConsumerDbError";

/**
 * Get the key with keyName from the database.
 * @param {Name} keyName The key name.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that returns a Blob with the encoded
 * key (or an isNull Blob if cannot find the key with keyName), or that is
 * rejected with ConsumerDb.Error for a database error.
 */
ConsumerDb.prototype.getKeyPromise = function(keyName, useSync)
{
  return SyncPromise.reject(new Error
    ("ConsumerDb.getKeyPromise is not implemented"));
};

/**
 * Add the key with keyName and keyBlob to the database.
 * @param {Name} keyName The key name.
 * @param {Blob} keyBlob The encoded key.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that fulfills when the key is added,
 * or that is rejected with ConsumerDb.Error if a key with the same keyName
 * already exists, or other database error.
 */
ConsumerDb.prototype.addKeyPromise = function(keyName, keyBlob, useSync)
{
  return SyncPromise.reject(new Error
    ("ConsumerDb.addKeyPromise is not implemented"));
};

/**
 * Delete the key with keyName from the database. If there is no key with
 * keyName, do nothing.
 * @param {Name} keyName The key name.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that fulfills when the key is deleted
 * (or there is no such key), or that is rejected with ConsumerDb.Error for a
 * database error.
 */
ConsumerDb.prototype.deleteKeyPromise = function(keyName, useSync)
{
  return SyncPromise.reject(new Error
    ("ConsumerDb.addKeyPromise is not implemented"));
};
