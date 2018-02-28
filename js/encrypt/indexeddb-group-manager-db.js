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
 * IndexedDbGroupManagerDb extends GroupManagerDb to implement the storage of
 * data used by the GroupManager using the browser's IndexedDB service.
 * Create an IndexedDbGroupManagerDb to use the given IndexedDB database name.
 * @param {string} databaseName IndexedDB database name.
 * @note This class is an experimental feature. The API may change.
 * @constructor
 */
var IndexedDbGroupManagerDb = function IndexedDbGroupManagerDb(databaseName)
{
  GroupManagerDb.call(this);

  // The map key is the E-KEY name URI string. The value is the private key Blob.
  // (Use a string because we can't use the Name object as the key in JavaScript.)
  this.privateKeyBase_ = {};

  this.database = new Dexie(databaseName);
  this.database.version(1).stores({
    // "scheduleId" is the schedule ID, auto incremented // number
    // "scheduleName" is the schedule name, unique // string
    // "schedule" is the TLV-encoded schedule // Uint8Array
    schedules: "++scheduleId, &scheduleName",

    // "memberNameUri" is the member name URI // string
    //   (Note: In SQLite3, the member name index is the TLV encoded bytes, but
    //   we can't index on a byte array in IndexedDb.)
    //   (Note: The SQLite3 table also has an auto-incremented member ID primary
    //   key, but is not used so we omit it to simplify.)
    // "memberName" is the TLV-encoded member name (same as memberNameUri // Uint8Array
    // "scheduleId" is the schedule ID, linked to the schedules table // number
    //   (Note: The SQLite3 table has a foreign key to the schedules table with
    //   cascade update and delete, but we have to handle it manually.)
    // "keyName" is the TLV-encoded key name // Uint8Array
    // "publicKey" is the encoded key bytes // Uint8Array
    members: "memberNameUri, scheduleId",

    // "eKeyNameUri" is the ekey name URI // string
    //   (Note: In SQLite3, the member name index is the TLV encoded bytes, but
    //   we can't index on a byte array in IndexedDb.)
    //   (Note: The SQLite3 table also has an auto-incremented member ID primary
    //   key, but is not used so we omit it to simplify.)
    // "publicKey" is the encoded key bytes // Uint8Array
    ekeys: "eKeyNameUri"
  });
  this.database.open();
};

IndexedDbGroupManagerDb.prototype = new GroupManagerDb();
IndexedDbGroupManagerDb.prototype.name = "IndexedDbGroupManagerDb";

////////////////////////////////////////////////////// Schedule management.

/**
 * Check if there is a schedule with the given name.
 * @param {string} name The name of the schedule.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise} A promise that returns true if there is a schedule (else
 * false), or that is rejected with GroupManagerDb.Error for a database error.
 */
IndexedDbGroupManagerDb.prototype.hasSchedulePromise = function(name, useSync)
{
  if (useSync)
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("IndexedDbGroupManagerDb.hasSchedulePromise is only supported for async")));

  return this.getScheduleIdPromise_(name)
  .then(function(scheduleId) {
    return Promise.resolve(scheduleId != -1);
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
IndexedDbGroupManagerDb.prototype.listAllScheduleNamesPromise = function(useSync)
{
  if (useSync)
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("IndexedDbGroupManagerDb.listAllScheduleNamesPromise is only supported for async")));

  var list = [];
  return this.database.schedules.each(function(entry) {
    list.push(entry.scheduleName);
  })
  .then(function() {
    return Promise.resolve(list);
  })
  .catch(function(ex) {
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("IndexedDbGroupManagerDb.listAllScheduleNamesPromise: Error: " + ex)));
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
IndexedDbGroupManagerDb.prototype.getSchedulePromise = function(name, useSync)
{
  if (useSync)
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("IndexedDbGroupManagerDb.getSchedulePromise is only supported for async")));

  var thisManager = this;
  // Use getScheduleIdPromise_ to handle the search on the non-primary key.
  return this.getScheduleIdPromise_(name)
  .then(function(scheduleId) {
    if (scheduleId != -1) {
      return thisManager.database.schedules.get(scheduleId)
      .then(function(entry) {
        // We expect entry to be found, and don't expect an error decoding.
        var schedule = new Schedule();
        schedule.wireDecode(new Blob(entry.schedule, false));
        return Promise.resolve(schedule);
      })
      .catch(function(ex) {
        return Promise.reject(new GroupManagerDb.Error(new Error
          ("IndexedDbGroupManagerDb.getSchedulePromise: Error: " + ex)));
      });
    }
    else
      return Promise.reject(new GroupManagerDb.Error(new Error
        ("IndexedDbGroupManagerDb.getSchedulePromise: Cannot get the result from the database")));
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
IndexedDbGroupManagerDb.prototype.getScheduleMembersPromise = function
  (name, useSync)
{
  if (useSync)
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("IndexedDbGroupManagerDb.getScheduleMembersPromise is only supported for async")));

  var list = [];
  var thisManager = this;
  // There is only one matching schedule ID, so we can just look it up instead
  // of doing a more complicated join.
  return this.getScheduleIdPromise_(name)
  .then(function(scheduleId) {
    if (scheduleId == -1)
      // Return the empty list.
      return Promise.resolve(list);

    var onEntryError = null;
    return thisManager.database.members.where("scheduleId").equals(scheduleId)
    .each(function(entry) {
      try {
        var keyName = new Name();
        keyName.wireDecode(new Blob(entry.keyName, false), TlvWireFormat.get());

        list.push({ keyName: keyName, publicKey: new Blob(entry.publicKey, false) });
      } catch (ex) {
        // We don't expect this to happen.
        onEntryError = new GroupManagerDb.Error(new Error
          ("IndexedDbGroupManagerDb.getScheduleMembersPromise: Error decoding name: " + ex));
      }
    })
    .then(function() {
      if (onEntryError)
        // We got an error decoding.
        return Promise.reject(onEntryError);
      else
        return Promise.resolve(list);
    }, function(ex) {
      return Promise.reject(new GroupManagerDb.Error(new Error
        ("IndexedDbGroupManagerDb.getScheduleMembersPromise: Error: " + ex)));
    });
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
IndexedDbGroupManagerDb.prototype.addSchedulePromise = function
  (name, schedule, useSync)
{
  if (useSync)
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("IndexedDbGroupManagerDb.addSchedulePromise is only supported for async")));

  if (name.length == 0)
    return Promise.reject(new GroupManagerDb.Error
      ("IndexedDbGroupManagerDb.addSchedulePromise: The schedule name cannot be empty"));

  // Add rejects if the primary key already exists.
  return this.database.schedules.add
    ({ scheduleName: name, schedule: schedule.wireEncode().buf() })
  .catch(function(ex) {
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("IndexedDbGroupManagerDb.addSchedulePromise: Error: " + ex)));
  });
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
IndexedDbGroupManagerDb.prototype.deleteSchedulePromise = function
  (name, useSync)
{
  if (useSync)
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("IndexedDbGroupManagerDb.deleteSchedulePromise is only supported for async")));

  var scheduleId;
  var thisManager = this;
  return this.getScheduleIdPromise_(name)
  .then(function(localScheduleId) {
    scheduleId = localScheduleId;

    // Get the members which use this schedule.
    return thisManager.database.members.where("scheduleId").equals(scheduleId).toArray();
  })
  .then(function(membersEntries) {
    // Delete the members.
    var promises = membersEntries.map(function(entry) {
      return thisManager.database.members.delete(entry.memberNameUri);
    });
    return Promise.all(promises);
  })
  .then(function() {
    // Now delete the schedule.
    return thisManager.database.schedules.delete(scheduleId);
  })
  .catch(function(ex) {
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("IndexedDbGroupManagerDb.deleteSchedulePromise: Error: " + ex)));
  });
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
IndexedDbGroupManagerDb.prototype.renameSchedulePromise = function
  (oldName, newName, useSync)
{
  if (useSync)
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("IndexedDbGroupManagerDb.renameSchedulePromise is only supported for async")));

  if (newName.length == 0)
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("IndexedDbGroupManagerDb.renameSchedule: The schedule newName cannot be empty")));

  var thisManager = this;
  return this.getScheduleIdPromise_(oldName)
  .then(function(scheduleId) {
    if (scheduleId == -1)
      return Promise.reject(new GroupManagerDb.Error(new Error
        ("IndexedDbGroupManagerDb.renameSchedule: The schedule oldName does not exist")));

    return thisManager.database.schedules.update
      (scheduleId, { scheduleName: newName })
    .catch(function(ex) {
      return Promise.reject(new GroupManagerDb.Error(new Error
        ("IndexedDbGroupManagerDb.renameSchedulePromise: Error: " + ex)));
    });
  });
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
IndexedDbGroupManagerDb.prototype.updateSchedulePromise = function
  (name, schedule, useSync)
{
  if (useSync)
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("IndexedDbGroupManagerDb.updateSchedulePromise is only supported for async")));

  var thisManager = this;
  return this.getScheduleIdPromise_(name)
  .then(function(scheduleId) {
    if (scheduleId == -1)
      return thisManager.addSchedulePromise(name, schedule);

    return thisManager.database.schedules.update
      (scheduleId, { schedule: schedule.wireEncode().buf() })
    .catch(function(ex) {
      return Promise.reject(new GroupManagerDb.Error(new Error
        ("IndexedDbGroupManagerDb.updateSchedulePromise: Error: " + ex)));
    });
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
IndexedDbGroupManagerDb.prototype.hasMemberPromise = function(identity, useSync)
{
  if (useSync)
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("IndexedDbGroupManagerDb.hasMemberPromise is only supported for async")));

  return this.database.members.get(identity.toUri())
  .then(function(entry) {
    return Promise.resolve(entry != undefined);
  })
  .catch(function(ex) {
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("IndexedDbGroupManagerDb.hasMemberPromise: Error: " + ex)));
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
IndexedDbGroupManagerDb.prototype.listAllMembersPromise = function(useSync)
{
  if (useSync)
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("IndexedDbGroupManagerDb.listAllMembersPromise is only supported for async")));

  var list = [];
  var onEntryError = null;
  return this.database.members.each(function(entry) {
    try {
      var identity = new Name();
      identity.wireDecode(new Blob(entry.memberName, false), TlvWireFormat.get());
      list.push(identity);
    } catch (ex) {
      // We don't expect this to happen.
      onEntryError = new GroupManagerDb.Error(new Error
        ("IndexedDbGroupManagerDb.listAllMembersPromise: Error decoding name: " + ex));
    }
  })
  .then(function() {
    if (onEntryError)
      // We got an error decoding.
      return Promise.reject(onEntryError);
    else
      return Promise.resolve(list);
  }, function(ex) {
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("IndexedDbGroupManagerDb.listAllMembersPromise: Error: " + ex)));
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
IndexedDbGroupManagerDb.prototype.getMemberSchedulePromise = function
  (identity, useSync)
{
  if (useSync)
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("IndexedDbGroupManagerDb.getMemberSchedulePromise is only supported for async")));

  var thisManager = this;
  return this.database.members.get(identity.toUri())
  .then(function(membersEntry) {
    if (!membersEntry)
      throw new Error("The member identity name does not exist in the database");

    return thisManager.database.schedules.get(membersEntry.scheduleId);
  })
  .then(function(schedulesEntry) {
    if (!schedulesEntry)
      throw new Error
        ("The schedule ID for the member identity name does not exist in the database");

    return Promise.resolve(schedulesEntry.scheduleName);
  })
  .catch(function(ex) {
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("IndexedDbGroupManagerDb.getMemberSchedulePromise: Error: " + ex)));
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
IndexedDbGroupManagerDb.prototype.addMemberPromise = function
  (scheduleName, keyName, key, useSync)
{
  if (useSync)
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("IndexedDbGroupManagerDb.addMemberPromise is only supported for async")));

  var thisManager = this;
  return this.getScheduleIdPromise_(scheduleName)
  .then(function(scheduleId) {
    if (scheduleId == -1)
      return Promise.reject(new GroupManagerDb.Error(new Error
        ("IndexedDbGroupManagerDb.addMemberPromise: The schedule does not exist")));

    // Needs to be changed in the future.
    var memberName = keyName.getPrefix(-1);

    // Add rejects if the primary key already exists.
    return thisManager.database.members.add
      ({ memberNameUri: memberName.toUri(),
         memberName: memberName.wireEncode(TlvWireFormat.get()).buf(),
         scheduleId: scheduleId,
         keyName: keyName.wireEncode(TlvWireFormat.get()).buf(),
         publicKey: key.buf() })
    .catch(function(ex) {
      return Promise.reject(new GroupManagerDb.Error(new Error
        ("IndexedDbGroupManagerDb.addMemberPromise: Error: " + ex)));
    });
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
IndexedDbGroupManagerDb.prototype.updateMemberSchedulePromise = function
  (identity, scheduleName, useSync)
{
  if (useSync)
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("IndexedDbGroupManagerDb.updateMemberSchedulePromise is only supported for async")));

  var thisManager = this;
  return this.getScheduleIdPromise_(scheduleName)
  .then(function(scheduleId) {
    if (scheduleId == -1)
      return Promise.reject(new GroupManagerDb.Error(new Error
        ("IndexedDbGroupManagerDb.updateMemberSchedulePromise: The schedule does not exist")));

    return thisManager.database.members.update
      (identity.toUri(), { scheduleId: scheduleId })
    .catch(function(ex) {
      return Promise.reject(new GroupManagerDb.Error(new Error
        ("IndexedDbGroupManagerDb.updateMemberSchedulePromise: Error: " + ex)));
    });
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
IndexedDbGroupManagerDb.prototype.deleteMemberPromise = function
  (identity, useSync)
{
  if (useSync)
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("IndexedDbGroupManagerDb.deleteMemberPromise is only supported for async")));

  return this.database.members.delete(identity.toUri())
  .catch(function(ex) {
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("IndexedDbGroupManagerDb.deleteMemberPromise: Error: " + ex)));
  });
};

/**
 * Check if there is an EKey with the name eKeyName in the database.
 * @param {Name} eKeyName The name of the EKey.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise|SyncPromise} A promise that returns true if the EKey exists
 * (else false), or that is rejected with GroupManagerDb.Error for a database
 * error.
 */
IndexedDbGroupManagerDb.prototype.hasEKeyPromise = function(eKeyName, useSync)
{
  if (useSync)
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("IndexedDbGroupManagerDb.hasEKeyPromise is only supported for async")));

  return this.database.ekeys.get(eKeyName.toUri())
  .then(function(entry) {
    return Promise.resolve(entry != undefined);
  })
  .catch(function(ex) {
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("IndexedDbGroupManagerDb.hasEKeyPromise: Error: " + ex)));
  });
};

/**
 * Add the EKey with name eKeyName to the database.
 * Add the EKey with name eKeyName to the database.
 * @param {Name} eKeyName The name of the EKey. This copies the Name.
 * @param {Blob} publicKey The encoded public Key of the group key pair.
 * @param {Blob} privateKey The encoded private Key of the group key pair.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise|SyncPromise} A promise that fulfills when the EKey is added,
 * or that is rejected with GroupManagerDb.Error if a key with name eKeyName
 * already exists in the database, or other database error.
 */
IndexedDbGroupManagerDb.prototype.addEKeyPromise = function
  (eKeyName, publicKey, privateKey, useSync)
{
  if (useSync)
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("IndexedDbGroupManagerDb.addEKeyPromise is only supported for async")));

  var eKeyNameUri = eKeyName.toUri();
  var thisManager = this;
  // Add rejects if the primary key already exists.
  return thisManager.database.ekeys.add
    ({ eKeyNameUri: eKeyNameUri,
       publicKey: publicKey.buf() })
  .then(function() {
    thisManager.privateKeyBase_[eKeyNameUri] = privateKey;

    return Promise.resolve();
  })
  .catch(function(ex) {
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("IndexedDbGroupManagerDb.addEKeyPromise: Error: " + ex)));
  });
};

/**
 * Get the group key pair with the name eKeyName from the database.
 * @param {Name} eKeyName The name of the EKey.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise|SyncPromise} A promise that returns an object (where
 * "publicKey" is the public key Blob and "privateKey" is the private key Blob),
 * or that is rejected with GroupManagerDb.Error for a database error.
 */
IndexedDbGroupManagerDb.prototype.getEKeyPromise = function(eKeyName, useSync)
{
  if (useSync)
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("IndexedDbGroupManagerDb.getEKeyPromise is only supported for async")));

  var eKeyNameUri = eKeyName.toUri();
  var thisManager = this;
  return this.database.ekeys.get(eKeyNameUri)
  .then(function(entry) {
    if (entry)
      return Promise.resolve({
        publicKey: new Blob(entry.publicKey, true),
        privateKey: thisManager.privateKeyBase_[eKeyNameUri]  });
    else
      throw new Error("The eKeyName does not exist in the database");
  })
  .catch(function(ex) {
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("IndexedDbGroupManagerDb.getEKeyPromise: Error: " + ex)));
  });
};

/**
 * Delete all the EKeys in the database. The database will keep growing because
 * EKeys will keep being added, so this method should be called periodically.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise|SyncPromise} A promise that fulfills when the EKeys are
 * deleted, or that is rejected with GroupManagerDb.Error for a database error.
 */
IndexedDbGroupManagerDb.prototype.cleanEKeysPromise = function(useSync)
{
  return Promise.reject(new Error
    ("IndexedDbGroupManagerDb.cleanEKeysPromise is not implemented"));

  var thisManager = this;
  return this.database.ekeys.clear()
  .then(function() {
    thisManager.privateKeyBase_ = {};

    return Promise.resolve();
  })
  .catch(function(ex) {
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("IndexedDbGroupManagerDb.cleanEKeysPromise: Error: " + ex)));
  });
};

/**
 * Delete the EKey with name eKeyName from the database. If no key with the
 * name exists in the database, do nothing.
 * @param {Name} eKeyName The name of the EKey.
 * @param {boolean} useSync (optional) If true then return a rejected promise
 * since this only supports async code.
 * @return {Promise|SyncPromise} A promise that fulfills when the EKey is
 * deleted (or there is no such key), or that is rejected with
 * GroupManagerDb.Error for a database error.
 */
IndexedDbGroupManagerDb.prototype.deleteEKeyPromise = function(eKeyName, useSync)
{
  if (useSync)
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("IndexedDbGroupManagerDb.deleteEKeyPromise is only supported for async")));

  var thisManager = this;
  return this.database.ekeys.delete(eKeyName.toUri())
  .then(function() {
    delete thisManager.privateKeyBase_[eKeyName.toUri()];

    return Promise.resolve();
  })
  .catch(function(ex) {
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("IndexedDbGroupManagerDb.deleteEKeyPromise: Error: " + ex)));
  });
};

/**
 * Get the ID for the schedule.
 * @param {string} name The schedule name.
 * @return {Promise} A promise that returns the ID (or -1 if not found), or that
 * is rejected with GroupManagerDb.Error for a database error.
 */
IndexedDbGroupManagerDb.prototype.getScheduleIdPromise_ = function(name)
{
  // The scheduleName is not the primary key, so use 'where' instead of 'get'.
  var id = -1;
  return this.database.schedules.where("scheduleName").equals(name)
  .each(function(entry) {
    id = entry.scheduleId;
  })
  .then(function() {
    return Promise.resolve(id);
  })
  .catch(function(ex) {
    return Promise.reject(new GroupManagerDb.Error(new Error
      ("IndexedDbGroupManagerDb.getScheduleIdPromise_: Error: " + ex)));
  });
};
