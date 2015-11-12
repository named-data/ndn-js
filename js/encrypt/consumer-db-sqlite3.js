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
var TlvWireFormat = require('../encoding/tlv-wire-format').TlvWireFormat;
var SyncPromise = require('../util/sync-promise.js').SyncPromise;
var ConsumerDb = require('./consumer-db.js').ConsumerDb;
var sqlite3 = null;
try {
  // This should be installed with: sudo npm install sqlite3
  sqlite3 = require('sqlite3').verbose();
}
catch (e) {}

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

  if (!sqlite3)
    throw new ConsumerDb.Error(new Error
      ("Need to install sqlite3: sudo npm install sqlite3"));

  this.databaseFilePath_ = databaseFilePath;
  this.database_ = null;
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
 * First call establishDatabasePromise_, then call
 * this.database_.run(sql, params) to execute the SQL command.
 * @param {string} sql The SQL command to execute.
 * @param {object|Array<object>} params (optional) The single parameter or array
 * of parameters for the command.
 * @return {Promise} A promise that fulfills when the SQL command is complete,
 * or that is rejected with ConsumerDb.Error if there is a database error.
 */
ConsumerDbSqlite3.prototype.runPromise_ = function(sql, params)
{
  if (!params)
    params = [];

  var thisManager = this;
  return this.establishDatabasePromise_()
  .then(function() {
    return thisManager.runWithoutEstablishPromise_(sql, params);
  });
};

/**
 * First call establishDatabasePromise_, then call
 * this.database_.get(sql, params) to execute the SQL query and get a single row.
 * @param {string} sql The SQL query to execute.
 * @param {object|Array<object>} params (optional) The single parameter or array
 * of parameters for the query.
 * @return {Promise} A promise that returns the query result, or that is rejected
 * with ConsumerDb.Error if there is a database error. The query result is
 * an object containing the values for the first matching row where the object
 * property names correspond to the column names. If no rows are found, the
 * query result is the undefined value.
 */
ConsumerDbSqlite3.prototype.getPromise_ = function(sql, params)
{
  if (!params)
    params = [];

  var thisManager = this;
  return this.establishDatabasePromise_()
  .then(function() {
    return new Promise(function(resolve, reject) {
      thisManager.database_.get(sql, params, function(err, row) {
        if (err)
          reject(new ConsumerDb.Error(new Error
            ("ConsumerDbSqlite3: SQLite error: " + err)));
        else
          resolve(row);
      });
    });
  });
};

/**
 * Call this.database_.run(sql, params) to execute the SQL command. This should
 * only be called by helper methods which have already called
 * establishDatabasePromise_; normally you would just call runPromise_.
 * @param {string} sql The SQL command to execute.
 * @param {object|Array<object>} params (optional) The single parameter or array
 * of parameters for the command.
 * @return {Promise} A promise that fulfills when the SQL command is complete,
 * or that is rejected with ConsumerDb.Error if there is a database error.
 */
ConsumerDbSqlite3.prototype.runWithoutEstablishPromise_ = function(sql, params)
{
  if (!params)
    params = [];

  var thisManager = this;
  return new Promise(function(resolve, reject) {
    thisManager.database_.run(sql, params, function(err) {
      if (err)
        reject(new ConsumerDb.Error(new Error
          ("ConsumerDbSqlite3: SQLite error: " + err)));
      else
        resolve();
    });
  });
};

/**
 * If this.database_ is still null, set up this.database_ and create the
 * database tables if they don't exist. Each method which uses the database must
 * call this first. We can't do this in the constructor because it is async.
 * @return {Promise} A promise that fulfills when this.database_ is set up.
 */
ConsumerDbSqlite3.prototype.establishDatabasePromise_ = function()
{
  if (this.database_ != null)
    // Already set up.
    return Promise.resolve();

  try {
    this.database_ = new sqlite3.Database(this.databaseFilePath_);
  } catch (ex) {
    return Promise.reject(new ConsumerDb.Error(new Error
      ("ConsumerDbSqlite3: Error creating sqlite3 " + ex.message)));
  }

  var thisManager = this;

  // Enable foreign keys.
  return thisManager.runWithoutEstablishPromise_
    (ConsumerDbSqlite3.INITIALIZATION1)
  .then(function() {
    return thisManager.runWithoutEstablishPromise_
      (ConsumerDbSqlite3.INITIALIZATION2);
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
