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

var sqlite3 = null;
try {
  // This should be installed with: sudo npm install sqlite3
  sqlite3 = require('sqlite3').verbose();
} catch (e) {}

/**
 * Sqlite3Promise provides Promise-based methods to use the Node.js sqlite3
 * module.
 * Create a new Sqlite3Promise to use the given SQLite3 file.
 * @param {string} databaseFilePath The path of the SQLite3 file.
 * @param {function} initializeDatabasePromise (optional) When the database is
 * first opened, this calls initializeDatabasePromise(database) where database
 * is this Sqlite3Promise object, and which should return a Promise that
 * resolves when the database is initialized by creating tables and indexes if
 * needed. If omitted, this does not call it.
 * @constructor
 */
var Sqlite3Promise = function Sqlite3Promise
  (databaseFilePath, initializeDatabasePromise)
{
  if (!initializeDatabasePromise)
    initializeDatabasePromise = function() { return Promise.resolve(); }

  if (!sqlite3)
    throw new Error("Need to install sqlite3: sudo npm install sqlite3");

  this.databaseFilePath_ = databaseFilePath;
  this.initializeDatabasePromise_ = initializeDatabasePromise;
  this.sqlite3Database_ = null;
};

exports.Sqlite3Promise = Sqlite3Promise;

/**
 * First open the database if needed, then call
 * sqlite3.Database.run(sql, params) to execute the SQL command.
 * @param {string} sql The SQL command to execute.
 * @param {object|Array<object>} params (optional) The single parameter or array
 * of parameters for the command.
 * @return {Promise} A promise that fulfills when the SQL command is complete,
 * or that is rejected with Error if there is a database error.
 */
Sqlite3Promise.prototype.runPromise = function(sql, params)
{
  if (!params)
    params = [];

  var thisStorage = this;
  return this.establishDatabasePromise_()
  .then(function() {
    return new Promise(function(resolve, reject) {
      thisStorage.sqlite3Database_.run(sql, params, function(err) {
        if (err)
          reject(new Error("SQLite error: " + err));
        else
          resolve();
      });
    });
  });
};

/**
 * First open the database if needed, then call
 * sqlite3.Database.get(sql, params) to execute the SQL query and get a single row.
 * @param {string} sql The SQL query to execute.
 * @param {object|Array<object>} params (optional) The single parameter or array
 * of parameters for the query.
 * @return {Promise} A promise that returns the query result, or that is rejected
 * with Error if there is a database error. The query result is an object
 * containing the values for the first matching row where the object property
 * names correspond to the column names. If no rows are found, the query result
 * is the undefined value.
 */
Sqlite3Promise.prototype.getPromise = function(sql, params)
{
  if (!params)
    params = [];

  var thisStorage = this;
  return this.establishDatabasePromise_()
  .then(function() {
    return new Promise(function(resolve, reject) {
      thisStorage.sqlite3Database_.get(sql, params, function(err, row) {
        if (err)
          reject(new Error("SQLite error: " + err));
        else
          resolve(row);
      });
    });
  });
};

/**
 * First open the database if needed, then call
 * sqlite3.Database.each(sql, params, onRow) to execute the SQL query.
 * @param {string} sql The SQL command to query.
 * @param {object|Array<object>} params The single parameter or array of
 * parameters for the query. If there are no parameters, pass [].
 * @param {function} onRow For each matched row, this calls onRow(err, row)
 * where row is an object containing the values for the row where the object
 * property names correspond to the column names. If no rows match the query,
 * this is not called.
 * @return {Promise} A promise that fulfills when the SQL query is complete,
 * or that is rejected with Error if there is a database error.
 */
Sqlite3Promise.prototype.eachPromise = function(sql, params, onRow)
{
  if (!params)
    params = [];

  var thisStorage = this;
  return this.establishDatabasePromise_()
  .then(function() {
    return new Promise(function(resolve, reject) {
      thisStorage.sqlite3Database_.each(sql, params, onRow, function(err) {
        if (err)
          reject(new Error("SQLite error: " + err));
        else
          resolve();
      });
    });
  });
};

/**
 * If this.sqlite3Database_ is still null, set up this.sqlite3Database_ and call
 * this.initializeDatabasePromise_() to create the database tables, etc. Each
 * method which uses the database must call this first. We can't do this in the
 * constructor because it is async.
 * @return {Promise} A promise that fulfills when this.sqlite3Database_ is set up.
 */
Sqlite3Promise.prototype.establishDatabasePromise_ = function()
{
  if (this.sqlite3Database_ != null)
    // Already set up.
    return Promise.resolve();

  try {
    this.sqlite3Database_ = new sqlite3.Database(this.databaseFilePath_);
  } catch (ex) {
    return Promise.reject(new Error("Error creating sqlite3 " + ex.message));
  }

  return this.initializeDatabasePromise_(this);
};
