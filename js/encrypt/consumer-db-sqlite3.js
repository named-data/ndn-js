/**
 * Copyright (C) 2015 Regents of the University of California.
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

var Blob = require('../util/blob.js').Blob;
var Sqlite3Promise = require('../util/sqlite3-promise.js').Sqlite3Promise;
var TlvWireFormat = require('../encoding/tlv-wire-format').TlvWireFormat;
var SyncPromise = require('../util/sync-promise.js').SyncPromise;
var ConsumerDb = require('./consumer-db.js').ConsumerDb;

/**
 * ConsumerDbSqlite3 extends ConsumerDb to implement the storage of decryption
 * keys for the consumer using SQLite3.
 * Create a ConsumerDbSqlite3 to use the given SQLite3 file.
 * @param {string} databaseFilePath The path of the SQLite file.
 * @throws ConsumerDb.Error for a database error.
 * @note This class is an experimental feature. The API may change.
 * @constructor
 */
var ConsumerDbSqlite3 = function ConsumerDbSqlite3(databaseFilePath)
{
  // Call the base constructor.
  ConsumerDb.call(this);

  this.database_ = new Sqlite3Promise
    (databaseFilePath, ConsumerDbSqlite3.initializeDatabasePromise_);
};

ConsumerDbSqlite3.prototype = new ConsumerDb();
ConsumerDbSqlite3.prototype.name = "ConsumerDbSqlite3";

exports.ConsumerDbSqlite3 = ConsumerDbSqlite3;

/**
 * Get the key with keyName from the database.
 * @param {Name} keyName The key name.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise that returns a Blob with the encoded key (or an
 * isNull Blob if cannot find the key with keyName), or that is
 * rejected with ConsumerDb.Error for a database error.
 */
ConsumerDbSqlite3.prototype.getKeyPromise = function(keyName, useSync)
{
  if (useSync)
    return Promise.reject(new ConsumerDb.Error(new Error
      ("ConsumerDbSqlite3.getKey is only supported for async")));

  return this.getPromise_
    ("SELECT key_buf FROM decryptionkeys WHERE key_name=?",
     keyName.wireEncode(TlvWireFormat.get()).buf())
  .then(function(row) {
    if (row)
      return Promise.resolve(new Blob(row.key_buf, false));
    else
      return Promise.resolve(new Blob());
  });
};

/**
 * Add the key with keyName and keyBlob to the database.
 * @param {Name} keyName The key name.
 * @param {Blob} keyBlob The encoded key.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise that fulfills when the key is added, or that
 * is rejected with ConsumerDb.Error if a key with the same keyName already
 * exists, or other database error.
 */
ConsumerDbSqlite3.prototype.addKeyPromise = function(keyName, keyBlob, useSync)
{
  if (useSync)
    return Promise.reject(new ConsumerDb.Error(new Error
      ("ConsumerDbSqlite3.addKey is only supported for async")));

  return this.runPromise_
    ("INSERT INTO decryptionkeys(key_name, key_buf) values (?, ?)",
     [keyName.wireEncode(TlvWireFormat.get()).buf(), keyBlob.buf()]);
};

/**
 * Delete the key with keyName from the database. If there is no key with
 * keyName, do nothing.
 * @param {Name} keyName The key name.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise that fulfills when the key is deleted (or there
 * is no such key), or that is rejected with ConsumerDb.Error for a database
 * error.
 */
ConsumerDbSqlite3.prototype.deleteKeyPromise = function(keyName, useSync)
{
  if (useSync)
    return Promise.reject(new ConsumerDb.Error(new Error
      ("ConsumerDbSqlite3.deleteKey is only supported for async")));

  return this.runPromise_
    ("DELETE FROM decryptionkeys WHERE key_name=?",
     keyName.wireEncode(TlvWireFormat.get()).buf());
};

/**
 * Call Sqlite3Promise.runPromise, wrapping an Error in ConsumerDb.Error.
 */
ConsumerDbSqlite3.prototype.runPromise_ = function(sql, params)
{
  return this.database_.runPromise(sql, params)
  .catch(function(error) {
    return Promise.reject(new ConsumerDb.Error(error));
  });
};

/**
 * Call Sqlite3Promise.getPromise, wrapping an Error in ConsumerDb.Error.
 */
ConsumerDbSqlite3.prototype.getPromise_ = function(sql, params)
{
  return this.database_.getPromise(sql, params)
  .catch(function(error) {
    return Promise.reject(new ConsumerDb.Error(error));
  });
};

ConsumerDbSqlite3.initializeDatabasePromise_ = function(database)
{
  return database.runPromise(ConsumerDbSqlite3.INITIALIZATION1)
  .then(function() {
    return database.runPromise(ConsumerDbSqlite3.INITIALIZATION2);
  });
};

ConsumerDbSqlite3.INITIALIZATION1 =
  "CREATE TABLE IF NOT EXISTS                         \n" +
  "  decryptionkeys(                                  \n" +
  "    key_id              INTEGER PRIMARY KEY,       \n" +
  "    key_name            BLOB NOT NULL,             \n" +
  "    key_buf             BLOB NOT NULL              \n" +
  "  );                                               \n";
ConsumerDbSqlite3.INITIALIZATION2 =
  "CREATE UNIQUE INDEX IF NOT EXISTS                  \n" +
  "   KeyNameIndex ON decryptionkeys(key_name);       \n";
