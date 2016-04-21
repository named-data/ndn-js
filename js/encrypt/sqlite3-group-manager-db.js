/**
 * Copyright (C) 2015-2016 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt src/group-manager-db https://github.com/named-data/ndn-group-encrypt
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
var Schedule = require('./schedule.js').Schedule; /** @ignore */
var Blob = require('../util/blob.js').Blob; /** @ignore */
var Sqlite3Promise = require('../util/sqlite3-promise.js').Sqlite3Promise; /** @ignore */
var Name = require('../name.js').Name; /** @ignore */
var TlvWireFormat = require('../encoding/tlv-wire-format').TlvWireFormat; /** @ignore */
var SyncPromise = require('../util/sync-promise.js').SyncPromise; /** @ignore */
var GroupManagerDb = require('./group-manager-db.js').GroupManagerDb;

/**
 * Sqlite3GroupManagerDb extends GroupManagerDb to implement the storage of
 * data used by the GroupManager using the Node.js sqlite3 module.
 * Create a Sqlite3GroupManagerDb to use the given SQLite3 file.
 * @param {string} databaseFilePath The path of the SQLite file.
 * @throws GroupManagerDb.Error for a database error.
 * @note This class is an experimental feature. The API may change.
 * @constructor
 */
var Sqlite3GroupManagerDb = function Sqlite3GroupManagerDb(databaseFilePath)
{
  // Call the base constructor.
  GroupManagerDb.call(this);

  this.database_ = new Sqlite3Promise
    (databaseFilePath, Sqlite3GroupManagerDb.initializeDatabasePromise_);
};

Sqlite3GroupManagerDb.prototype = new GroupManagerDb();
Sqlite3GroupManagerDb.prototype.name = "Sqlite3GroupManagerDb";

exports.Sqlite3GroupManagerDb = Sqlite3GroupManagerDb;

////////////////////////////////////////////////////// Schedule management.

/**
 * Check if there is a schedule with the given name.
 * @param {string} name The name of the schedule.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise that returns true if there is a schedule (else
 * false), or that is rejected with GroupManagerDb.Error for a database error.
 */
Sqlite3GroupManagerDb.prototype.hasSchedulePromise = function(name, useSync)
{
  if (useSync)
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("Sqlite3GroupManagerDb.hasSchedulePromise is only supported for async")));

  return this.getPromise_
    ("SELECT schedule_id FROM schedules where schedule_name=?", name)
  .then(function(row) {
    if (row)
      return Promise.resolve(true);
    else
      return Promise.resolve(false);
  });
};

/**
 * List all the names of the schedules.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise that returns a new array of string with the names
 * of all schedules, or that is rejected with GroupManagerDb.Error for a
 * database error.
 */
Sqlite3GroupManagerDb.prototype.listAllScheduleNamesPromise = function(useSync)
{
  if (useSync)
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("Sqlite3GroupManagerDb.listAllScheduleNamesPromise is only supported for async")));

  var list = [];
  return this.eachPromise_
    ("SELECT schedule_name FROM schedules", [], function(err, row) {
      list.push(row.schedule_name);
    })
  .then(function() {
    return Promise.resolve(list);
  });
};

/**
 * Get a schedule with the given name.
 * @param {string} name The name of the schedule.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise that returns a new Schedule object, or that is
 * rejected with GroupManagerDb.Error if the schedule does not exist or other
 * database error.
 */
Sqlite3GroupManagerDb.prototype.getSchedulePromise = function(name, useSync)
{
  if (useSync)
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("Sqlite3GroupManagerDb.getSchedulePromise is only supported for async")));

  return this.getPromise_
    ("SELECT schedule FROM schedules WHERE schedule_name=?", name)
  .then(function(row) {
    if (row) {
      try {
        var schedule = new Schedule();
        schedule.wireDecode(new Blob(row.schedule, false));
        return Promise.resolve(schedule);
      } catch (ex) {
        // We don't expect this to happen.
        return Promise.reject(new GroupManagerDb.Error(new Error
          ("Sqlite3GroupManagerDb.getSchedulePromise: Error decoding schedule: " + ex)));
      }
    }
    else
      return Promise.reject(new GroupManagerDb.Error(new Error
        ("Sqlite3GroupManagerDb.getSchedulePromise: Cannot get the result from the database")));
  });
};

/**
 * For each member using the given schedule, get the name and public key DER
 * of the member's key.
 * @param {string} name The name of the schedule.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise that returns a new array of object (where
 * "keyName" is the Name of the public key and "publicKey" is the Blob of the
 * public key DER), or that is rejected with GroupManagerDb.Error for a database
 * error. Note that the member's identity name is keyName.getPrefix(-1). If the
 * schedule name is not found, the list is empty.
 */
Sqlite3GroupManagerDb.prototype.getScheduleMembersPromise = function
  (name, useSync)
{
  if (useSync)
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("Sqlite3GroupManagerDb.getScheduleMembersPromise is only supported for async")));

  var list = [];
  var onRowError = null;
  return this.eachPromise_
    ("SELECT key_name, pubkey " +
     "FROM members JOIN schedules " +
     "ON members.schedule_id=schedules.schedule_id " +
     "WHERE schedule_name=?", name, function(err, row) {
      try {
        var keyName = new Name();
        keyName.wireDecode(new Blob(row.key_name, false), TlvWireFormat.get());

        list.push({ keyName: keyName, publicKey: new Blob(row.pubkey, false) });
      } catch (ex) {
        // We don't expect this to happen.
        onRowError = new GroupManagerDb.Error(new Error
          ("Sqlite3GroupManagerDb.getScheduleMembersPromise: Error decoding name: " + ex));
      }
    })
  .then(function() {
    if (onRowError)
      return Promise.reject(onRowError);
    else
      return Promise.resolve(list);
  });
};

/**
 * Add a schedule with the given name.
 * @param {string} name The name of the schedule. The name cannot be empty.
 * @param {Schedule} schedule The Schedule to add.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise that fulfills when the schedule is added, or that
 * is rejected with GroupManagerDb.Error if a schedule with the same name
 * already exists, if the name is empty, or other database error.
 */
Sqlite3GroupManagerDb.prototype.addSchedulePromise = function
  (name, schedule, useSync)
{
  if (useSync)
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("Sqlite3GroupManagerDb.addSchedulePromise is only supported for async")));

  if (name.length == 0)
    return Promise.reject(new GroupManagerDb.Error
      ("Sqlite3GroupManagerDb.addSchedulePromise: The schedule name cannot be empty"));

  return this.runPromise_
    ("INSERT INTO schedules (schedule_name, schedule) values (?, ?)",
     [name, schedule.wireEncode().buf()]);
};

/**
 * Delete the schedule with the given name. Also delete members which use this
 * schedule. If there is no schedule with the name, then do nothing.
 * @param {string} name The name of the schedule.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise that fulfills when the schedule is deleted (or
 * there is no such schedule), or that is rejected with GroupManagerDb.Error for
 * a database error.
 */
Sqlite3GroupManagerDb.prototype.deleteSchedulePromise = function
  (name, useSync)
{
  if (useSync)
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("Sqlite3GroupManagerDb.deleteSchedulePromise is only supported for async")));

  return this.runPromise_
    ("DELETE FROM schedules WHERE schedule_name=?", name);
};

/**
 * Rename a schedule with oldName to newName.
 * @param {string} oldName The name of the schedule to be renamed.
 * @param {string} newName The new name of the schedule. The name cannot be empty.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise that fulfills when the schedule is renamed, or
 * that is rejected with GroupManagerDb.Error if a schedule with newName already
 * exists, if the schedule with oldName does not exist, if newName is empty, or
 * other database error.
 */
Sqlite3GroupManagerDb.prototype.renameSchedulePromise = function
  (oldName, newName, useSync)
{
  if (useSync)
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("Sqlite3GroupManagerDb.renameSchedulePromise is only supported for async")));

  if (newName.length == 0)
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("Sqlite3GroupManagerDb.renameSchedule: The schedule newName cannot be empty")));

  return this.runPromise_
    ("UPDATE schedules SET schedule_name=? WHERE schedule_name=?",
     [newName, oldName]);
};

/**
 * Update the schedule with name and replace the old object with the given
 * schedule. Otherwise, if no schedule with name exists, a new schedule
 * with name and the given schedule will be added to database.
 * @param {string} name The name of the schedule. The name cannot be empty.
 * @param {Schedule} schedule The Schedule to update or add.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise that fulfills when the schedule is updated, or
 * that is rejected with GroupManagerDb.Error if the name is empty, or other
 * database error.
 */
Sqlite3GroupManagerDb.prototype.updateSchedulePromise = function
  (name, schedule, useSync)
{
  if (useSync)
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("Sqlite3GroupManagerDb.updateSchedulePromise is only supported for async")));

  var thisManager = this;
  return this.hasSchedulePromise(name)
  .then(function(hasSchedule) {
    if (!hasSchedule)
      return thisManager.addSchedulePromise(name, schedule);

    return thisManager.runPromise_
      ("UPDATE schedules SET schedule=? WHERE schedule_name=?",
       [schedule.wireEncode().buf(), name]);
  });
};

////////////////////////////////////////////////////// Member management.

/**
 * Check if there is a member with the given identity name.
 * @param {Name} identity The member's identity name.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise that returns true if there is a member (else
 * false), or that is rejected with GroupManagerDb.Error for a database error.
 */
Sqlite3GroupManagerDb.prototype.hasMemberPromise = function(identity, useSync)
{
  if (useSync)
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("Sqlite3GroupManagerDb.hasMemberPromise is only supported for async")));

  return this.getPromise_
    ("SELECT member_id FROM members WHERE member_name=?",
     identity.wireEncode(TlvWireFormat.get()).buf())
  .then(function(row) {
    if (row)
      return Promise.resolve(true);
    else
      return Promise.resolve(false);
  });
};

/**
 * List all the members.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise that returns a new array of Name with the names
 * of all members, or that is rejected with GroupManagerDb.Error for a
 * database error.
 */
Sqlite3GroupManagerDb.prototype.listAllMembersPromise = function(useSync)
{
  if (useSync)
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("Sqlite3GroupManagerDb.listAllMembersPromise is only supported for async")));

  var list = [];
  var onRowError = null;
  return this.eachPromise_
    ("SELECT member_name FROM members", [], function(err, row) {
      try {
        var identity = new Name();
        identity.wireDecode(new Blob(row.member_name, false), TlvWireFormat.get());
        list.push(identity);
      } catch (ex) {
        // We don't expect this to happen.
        onRowError = new GroupManagerDb.Error(new Error
          ("Sqlite3GroupManagerDb.listAllMembersPromise: Error decoding name: " + ex));
      }
    })
  .then(function() {
    if (onRowError)
      return Promise.reject(onRowError);
    else
      return Promise.resolve(list);
  });
};

/**
 * Get the name of the schedule for the given member's identity name.
 * @param {Name} identity The member's identity name.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise that returns the string schedule name, or that is
 * rejected with GroupManagerDb.Error if there's no member with the given
 * identity name in the database, or other database error.
 */
Sqlite3GroupManagerDb.prototype.getMemberSchedulePromise = function
  (identity, useSync)
{
  if (useSync)
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("Sqlite3GroupManagerDb.getMemberSchedulePromise is only supported for async")));

  return this.getPromise_
    ("SELECT schedule_name " +
     "FROM schedules JOIN members " +
     "ON schedules.schedule_id = members.schedule_id " +
     "WHERE member_name=?",
     identity.wireEncode(TlvWireFormat.get()).buf())
  .then(function(row) {
    if (row)
      return Promise.resolve(row.schedule_name);
    else
      return Promise.reject(new GroupManagerDb.Error(new Error
        ("Sqlite3GroupManagerDb.getMemberSchedulePromise: Cannot get the result from the database")));
  });
};

/**
 * Add a new member with the given key named keyName into a schedule named
 * scheduleName. The member's identity name is keyName.getPrefix(-1).
 * @param {string} scheduleName The schedule name.
 * @param {Name} keyName The name of the key.
 * @param {Blob} key A Blob of the public key DER.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise that fulfills when the member is added, or that
 * is rejected with GroupManagerDb.Error if there's no schedule named
 * scheduleName, if the member's identity name already exists, or other database
 * error.
 */
Sqlite3GroupManagerDb.prototype.addMemberPromise = function
  (scheduleName, keyName, key, useSync)
{
  if (useSync)
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("Sqlite3GroupManagerDb.addMemberPromise is only supported for async")));

  var thisManager = this;
  return this.getScheduleIdPromise_(scheduleName)
  .then(function(scheduleId) {
    if (scheduleId == -1)
      return Promise.reject(new GroupManagerDb.Error(new Error
        ("Sqlite3GroupManagerDb.addMemberPromise: The schedule does not exist")));

    // Needs to be changed in the future.
    var memberName = keyName.getPrefix(-1);

    return thisManager.runPromise_
        ("INSERT INTO members(schedule_id, member_name, key_name, pubkey) " +
         "values (?, ?, ?, ?)",
         [scheduleId, memberName.wireEncode(TlvWireFormat.get()).buf(),
          keyName.wireEncode(TlvWireFormat.get()).buf(), key.buf()]);
  });
};

/**
 * Change the name of the schedule for the given member's identity name.
 * @param {Name} identity The member's identity name.
 * @param {string} scheduleName The new schedule name.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise that fulfills when the member is updated, or that
 * is rejected with GroupManagerDb.Error if there's no member with the given
 * identity name in the database, or there's no schedule named scheduleName, or
 * other database error.
 */
Sqlite3GroupManagerDb.prototype.updateMemberSchedulePromise = function
  (identity, scheduleName, useSync)
{
  if (useSync)
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("Sqlite3GroupManagerDb.updateMemberSchedulePromise is only supported for async")));

  var thisManager = this;
  return this.getScheduleIdPromise_(scheduleName)
  .then(function(scheduleId) {
    if (scheduleId == -1)
      return Promise.reject(new GroupManagerDb.Error(new Error
        ("Sqlite3GroupManagerDb.updateMemberSchedulePromise: The schedule does not exist")));

    return thisManager.runPromise_
        ("UPDATE members SET schedule_id=? WHERE member_name=?",
         [scheduleId, identity.wireEncode(TlvWireFormat.get()).buf()]);
  });
};

/**
 * Delete a member with the given identity name. If there is no member with
 * the identity name, then do nothing.
 * @param {Name} identity The member's identity name.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise that fulfills when the member is deleted (or
 * there is no such member), or that is rejected with GroupManagerDb.Error for a
 * database error.
 */
Sqlite3GroupManagerDb.prototype.deleteMemberPromise = function
  (identity, useSync)
{
  if (useSync)
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("Sqlite3GroupManagerDb.deleteMemberPromise is only supported for async")));

  return this.runPromise_
    ("DELETE FROM members WHERE member_name=?",
     identity.wireEncode(TlvWireFormat.get()).buf());
};

/**
 * Get the ID for the schedule.
 * @param {string} name The schedule name.
 * @return {Promise} A promise that returns the ID (or -1 if not found), or that
 * is rejected with GroupManagerDb.Error for a database error.
 */
Sqlite3GroupManagerDb.prototype.getScheduleIdPromise_ = function(name)
{
  return this.getPromise_
    ("SELECT schedule_id FROM schedules WHERE schedule_name=?", name)
  .then(function(row) {
    if (row)
      return Promise.resolve(row.schedule_id);
    else
      return Promise.resolve(-1);
  });
};

/**
 * Call Sqlite3Promise.runPromise, wrapping an Error in GroupManagerDb.Error.
 */
Sqlite3GroupManagerDb.prototype.runPromise_ = function(sql, params)
{
  return this.database_.runPromise(sql, params)
  .catch(function(error) {
    return Promise.reject(new GroupManagerDb.Error(error));
  });
};

/**
 * Call Sqlite3Promise.getPromise, wrapping an Error in GroupManagerDb.Error.
 */
Sqlite3GroupManagerDb.prototype.getPromise_ = function(sql, params)
{
  return this.database_.getPromise(sql, params)
  .catch(function(error) {
    return Promise.reject(new GroupManagerDb.Error(error));
  });
};

/**
 * Call Sqlite3Promise.eachPromise, wrapping an Error in GroupManagerDb.Error.
 */
Sqlite3GroupManagerDb.prototype.eachPromise_ = function(sql, params, onRow)
{
  return this.database_.eachPromise(sql, params, onRow)
  .catch(function(error) {
    return Promise.reject(new GroupManagerDb.Error(error));
  });
};

Sqlite3GroupManagerDb.initializeDatabasePromise_ = function(database)
{
  // Enable foreign keys.
  return database.runPromise("PRAGMA foreign_keys = ON")
  .then(function() {
    return database.runPromise(Sqlite3GroupManagerDb.INITIALIZATION1);
  })
  .then(function() {
    return database.runPromise(Sqlite3GroupManagerDb.INITIALIZATION2);
  })
  .then(function() {
    return database.runPromise(Sqlite3GroupManagerDb.INITIALIZATION3);
  })
  .then(function() {
    return database.runPromise(Sqlite3GroupManagerDb.INITIALIZATION4);
  });
};

Sqlite3GroupManagerDb.INITIALIZATION1 =
  "CREATE TABLE IF NOT EXISTS                         \n" +
  "  schedules(                                       \n" +
  "    schedule_id         INTEGER PRIMARY KEY,       \n" +
  "    schedule_name       TEXT NOT NULL,             \n" +
  "    schedule            BLOB NOT NULL              \n" +
  "  );                                               \n";
Sqlite3GroupManagerDb.INITIALIZATION2 =
  "CREATE UNIQUE INDEX IF NOT EXISTS                  \n" +
  "   scheduleNameIndex ON schedules(schedule_name);  \n";
Sqlite3GroupManagerDb.INITIALIZATION3 =
  "CREATE TABLE IF NOT EXISTS                         \n" +
  "  members(                                         \n" +
  "    member_id           INTEGER PRIMARY KEY,       \n" +
  "    schedule_id         INTEGER NOT NULL,          \n" +
  "    member_name         BLOB NOT NULL,             \n" +
  "    key_name            BLOB NOT NULL,             \n" +
  "    pubkey              BLOB NOT NULL,             \n" +
  "    FOREIGN KEY(schedule_id)                       \n" +
  "      REFERENCES schedules(schedule_id)            \n" +
  "      ON DELETE CASCADE                            \n" +
  "      ON UPDATE CASCADE                            \n" +
  "  );                                               \n";
Sqlite3GroupManagerDb.INITIALIZATION4 =
  "CREATE UNIQUE INDEX IF NOT EXISTS                  \n" +
  "   memNameIndex ON members(member_name);           \n";
