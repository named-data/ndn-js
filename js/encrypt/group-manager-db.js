/**
 * Copyright (C) 2015-2018 Regents of the University of California.
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
var SyncPromise = require('../util/sync-promise.js').SyncPromise;

/**
 * GroupManagerDb is a base class for the storage of data used by the
 * GroupManager. It contains two tables to store Schedules and Members.
 * This is an abstract base class. A subclass must implement the methods.
 * For example, see Sqlite3GroupManagerDb (for Nodejs) or IndexedDbGroupManagerDb
 * (for the browser).
 * @note This class is an experimental feature. The API may change.
 * @constructor
 */
var GroupManagerDb = function GroupManagerDb()
{
};

exports.GroupManagerDb = GroupManagerDb;

/**
 * Create a new GroupManagerDb.Error to report an error using GroupManagerDb
 * methods, wrapping the given error object.
 * Call with: throw new GroupManagerDb.Error(new Error("message")).
 * @constructor
 * @param {Error} error The exception created with new Error.
 */
GroupManagerDb.Error = function GroupManagerDbError(error)
{
  if (error) {
    error.__proto__ = GroupManagerDb.Error.prototype;
    return error;
  }
};

GroupManagerDb.Error.prototype = new Error();
GroupManagerDb.Error.prototype.name = "GroupManagerDbError";

////////////////////////////////////////////////////// Schedule management.

/**
 * Check if there is a schedule with the given name.
 * @param {string} name The name of the schedule.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that returns true if there is a
 * schedule (else false), or that is rejected with GroupManagerDb.Error for a
 * database error.
 */
GroupManagerDb.prototype.hasSchedulePromise = function(name, useSync)
{
  return SyncPromise.reject(new Error
    ("GroupManagerDb.hasSchedulePromise is not implemented"));
};

/**
 * List all the names of the schedules.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that returns a new array of string
 * with the names of all schedules, or that is rejected with
 * GroupManagerDb.Error for a database error.
 */
GroupManagerDb.prototype.listAllScheduleNamesPromise = function(useSync)
{
  return SyncPromise.reject(new Error
    ("GroupManagerDb.listAllScheduleNamesPromise is not implemented"));
};

/**
 * Get a schedule with the given name.
 * @param {string} name The name of the schedule.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that returns a new Schedule object,
 * or that is rejected with GroupManagerDb.Error if the schedule does not exist
 * or other database error.
 */
GroupManagerDb.prototype.getSchedulePromise = function(name, useSync)
{
  return SyncPromise.reject(new Error
    ("GroupManagerDb.getSchedulePromise is not implemented"));
};

/**
 * For each member using the given schedule, get the name and public key DER
 * of the member's key.
 * @param {string} name The name of the schedule.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that returns a new array of object
 * (where "keyName" is the Name of the public key and "publicKey" is the Blob of
 * the public key DER), or that is rejected with GroupManagerDb.Error for a
 * database error. Note that the member's identity name is keyName.getPrefix(-1).
 * If the schedule name is not found, the list is empty.
 */
GroupManagerDb.prototype.getScheduleMembersPromise = function
  (name, useSync)
{
  return SyncPromise.reject(new Error
    ("GroupManagerDb.getScheduleMembersPromise is not implemented"));
};

/**
 * Add a schedule with the given name.
 * @param {string} name The name of the schedule. The name cannot be empty.
 * @param {Schedule} schedule The Schedule to add.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that fulfills when the schedule is
 * added, or that is rejected with GroupManagerDb.Error if a schedule with the
 * same name already exists, if the name is empty, or other database error.
 */
GroupManagerDb.prototype.addSchedulePromise = function(name, schedule, useSync)
{
  return SyncPromise.reject(new Error
    ("GroupManagerDb.addSchedulePromise is not implemented"));
};

/**
 * Delete the schedule with the given name. Also delete members which use this
 * schedule. If there is no schedule with the name, then do nothing.
 * @param {string} name The name of the schedule.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that fulfills when the schedule is
 * deleted (or there is no such schedule), or that is rejected with
 * GroupManagerDb.Error for a database error.
 */
GroupManagerDb.prototype.deleteSchedulePromise = function(name, useSync)
{
  return SyncPromise.reject(new Error
    ("GroupManagerDb.deleteSchedulePromise is not implemented"));
};

/**
 * Rename a schedule with oldName to newName.
 * @param {string} oldName The name of the schedule to be renamed.
 * @param {string} newName The new name of the schedule. The name cannot be empty.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that fulfills when the schedule is
 * renamed, or that is rejected with GroupManagerDb.Error if a schedule with
 * newName already exists, if the schedule with oldName does not exist, if
 * newName is empty, or other database error.
 */
GroupManagerDb.prototype.renameSchedulePromise = function
  (oldName, newName, useSync)
{
  return SyncPromise.reject(new Error
    ("GroupManagerDb.renameSchedulePromise is not implemented"));
};

/**
 * Update the schedule with name and replace the old object with the given
 * schedule. Otherwise, if no schedule with name exists, a new schedule
 * with name and the given schedule will be added to database.
 * @param {string} name The name of the schedule. The name cannot be empty.
 * @param {Schedule} schedule The Schedule to update or add.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that fulfills when the schedule is
 * updated, or that is rejected with GroupManagerDb.Error if the name is empty,
 * or other database error.
 */
GroupManagerDb.prototype.updateSchedulePromise = function
  (name, schedule, useSync)
{
  return SyncPromise.reject(new Error
    ("GroupManagerDb.updateSchedulePromise is not implemented"));
};

////////////////////////////////////////////////////// Member management.

/**
 * Check if there is a member with the given identity name.
 * @param {Name} identity The member's identity name.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that returns true if there is a
 * member (else false), or that is rejected with GroupManagerDb.Error for a
 * database error.
 */
GroupManagerDb.prototype.hasMemberPromise = function(identity, useSync)
{
  return SyncPromise.reject(new Error
    ("GroupManagerDb.hasMemberPromise is not implemented"));
};

/**
 * List all the members.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that returns a new array of Name with
 * the names of all members, or that is rejected with GroupManagerDb.Error for a
 * database error.
 */
GroupManagerDb.prototype.listAllMembersPromise = function(useSync)
{
  return SyncPromise.reject(new Error
    ("GroupManagerDb.listAllMembersPromise is not implemented"));
};

/**
 * Get the name of the schedule for the given member's identity name.
 * @param {Name} identity The member's identity name.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that returns the string schedule name,
 * or that is rejected with GroupManagerDb.Error if there's no member with the
 * given identity name in the database, or other database error.
 */
GroupManagerDb.prototype.getMemberSchedulePromise = function(identity, useSync)
{
  return SyncPromise.reject(new Error
    ("GroupManagerDb.getMemberSchedulePromise is not implemented"));
};

/**
 * Add a new member with the given key named keyName into a schedule named
 * scheduleName. The member's identity name is keyName.getPrefix(-1).
 * @param {string} scheduleName The schedule name.
 * @param {Name} keyName The name of the key.
 * @param {Blob} key A Blob of the public key DER.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that fulfills when the member is
 * added, or that is rejected with GroupManagerDb.Error if there's no schedule
 * named scheduleName, if the member's identity name already exists, or other
 * database error.
 */
GroupManagerDb.prototype.addMemberPromise = function
  (scheduleName, keyName, key, useSync)
{
  return SyncPromise.reject(new Error
    ("GroupManagerDb.addMemberPromise is not implemented"));
};

/**
 * Change the name of the schedule for the given member's identity name.
 * @param {Name} identity The member's identity name.
 * @param {string} scheduleName The new schedule name.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that fulfills when the member is
 * updated, or that is rejected with GroupManagerDb.Error if there's no member
 * with the given identity name in the database, or there's no schedule named
 * scheduleName, or other database error.
 */
GroupManagerDb.prototype.updateMemberSchedulePromise = function
  (identity, scheduleName, useSync)
{
  return SyncPromise.reject(new Error
    ("GroupManagerDb.updateMemberSchedulePromise is not implemented"));
};

/**
 * Delete a member with the given identity name. If there is no member with
 * the identity name, then do nothing.
 * @param {Name} identity The member's identity name.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that fulfills when the member is
 * deleted (or there is no such member), or that is rejected with
 * GroupManagerDb.Error for a database error.
 */
GroupManagerDb.prototype.deleteMemberPromise = function(identity, useSync)
{
  return SyncPromise.reject(new Error
    ("GroupManagerDb.deleteMemberPromise is not implemented"));
};

/**
 * Check if there is an EKey with the name eKeyName in the database.
 * @param {Name} eKeyName The name of the EKey.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that returns true if the EKey exists
 * (else false), or that is rejected with GroupManagerDb.Error for a database
 * error.
 */
GroupManagerDb.prototype.hasEKeyPromise = function(eKeyName, useSync)
{
  return SyncPromise.reject(new Error
    ("GroupManagerDb.hasEKeyPromise is not implemented"));
};

/**
 * Add the EKey with name eKeyName to the database.
 * @param {Name} eKeyName The name of the EKey. This copies the Name.
 * @param {Blob} publicKey The encoded public Key of the group key pair.
 * @param {Blob} privateKey The encoded private Key of the group key pair.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that fulfills when the EKey is added,
 * or that is rejected with GroupManagerDb.Error if a key with name eKeyName
 * already exists in the database, or other database error.
 */
GroupManagerDb.prototype.addEKeyPromise = function
  (eKeyName, publicKey, privateKey, useSync)
{
  return SyncPromise.reject(new Error
    ("GroupManagerDb.addEKeyPromise is not implemented"));
};

/**
 * Get the group key pair with the name eKeyName from the database.
 * @param {Name} eKeyName The name of the EKey.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that returns an object (where
 * "publicKey" is the public key Blob and "privateKey" is the private key Blob),
 * or that is rejected with GroupManagerDb.Error for a database error.
 */
GroupManagerDb.prototype.getEKeyPromise = function(eKeyName, useSync)
{
  return SyncPromise.reject(new Error
    ("GroupManagerDb.getEKeyPromise is not implemented"));
};

/**
 * Delete all the EKeys in the database. The database will keep growing because
 * EKeys will keep being added, so this method should be called periodically.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that fulfills when the EKeys are
 * deleted, or that is rejected with GroupManagerDb.Error for a database error.
 */
GroupManagerDb.prototype.cleanEKeysPromise = function(useSync)
{
  return SyncPromise.reject(new Error
    ("GroupManagerDb.cleanEKeysPromise is not implemented"));
};

/**
 * Delete the EKey with name eKeyName from the database. If no key with the
 * name exists in the database, do nothing.
 * @param {Name} eKeyName The name of the EKey.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that fulfills when the EKey is
 * deleted (or there is no such key), or that is rejected with
 * GroupManagerDb.Error for a database error.
 */
GroupManagerDb.prototype.deleteEKeyPromise = function(eKeyName, useSync)
{
  return SyncPromise.reject(new Error
    ("GroupManagerDb.deleteEKeyPromise is not implemented"));
};
