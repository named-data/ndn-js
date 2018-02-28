/**
 * Copyright (C) 2015-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt src/group-manager https://github.com/named-data/ndn-group-encrypt
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
var Name = require('../name.js').Name; /** @ignore */
var Data = require('../data.js').Data; /** @ignore */
var SyncPromise = require('../util/sync-promise.js').SyncPromise; /** @ignore */
var IdentityCertificate = require('../security/certificate/identity-certificate.js').IdentityCertificate; /** @ignore */
var SecurityException = require('../security/security-exception.js').SecurityException; /** @ignore */
var RsaKeyParams = require('../security/key-params.js').RsaKeyParams; /** @ignore */
var EncryptParams = require('./algo/encrypt-params.js').EncryptParams; /** @ignore */
var EncryptAlgorithmType = require('./algo/encrypt-params.js').EncryptAlgorithmType; /** @ignore */
var Encryptor = require('./algo/encryptor.js').Encryptor; /** @ignore */
var RsaAlgorithm = require('./algo/rsa-algorithm.js').RsaAlgorithm; /** @ignore */
var Interval = require('./interval.js').Interval; /** @ignore */
var Schedule = require('./schedule.js').Schedule;

/**
 * A GroupManager manages keys and schedules for group members in a particular
 * namespace.
 * Create a group manager with the given values. The group manager namespace
 * is <prefix>/read/<dataType> .
 * @param {Name} prefix The prefix for the group manager namespace.
 * @param {Name} dataType The data type for the group manager namespace.
 * @param {GroupManagerDb} database The GroupManagerDb for storing the group
 * management information (including user public keys and schedules).
 * @param {number} keySize The group key will be an RSA key with keySize bits.
 * @param {number} freshnessHours The number of hours of the freshness period of
 *   data packets carrying the keys.
 * @param {KeyChain} keyChain The KeyChain to use for signing data packets. This
 * signs with the default identity.
 * @note This class is an experimental feature. The API may change.
 * @constructor
 */
var GroupManager = function GroupManager
  (prefix, dataType, database, keySize, freshnessHours, keyChain)
{
  this.namespace_ = new Name(prefix).append(Encryptor.NAME_COMPONENT_READ)
    .append(dataType);
  this.database_ = database;
  this.keySize_ = keySize;
  this.freshnessHours_ = freshnessHours;

  this.keyChain_ = keyChain;
};

exports.GroupManager = GroupManager;

/**
 * Create a group key for the interval into which timeSlot falls. This creates
 * a group key if it doesn't exist, and encrypts the key using the public key of
 * each eligible member.
 * @param {number} timeSlot The time slot to cover as milliseconds since
 * Jan 1, 1970 UTC.
 * @param {boolean} needRegenerate (optional) needRegenerate should be true if
 * this is the first time this method is called, or a member was removed.
 * needRegenerate can be false if this is not the first time this method is
 * called, or a member was added. If omitted, use true. If useSync is specified,
 * then needRegenerate must also be specified (since this can't disambiguate
 * two optional boolean parameters).
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise. If useSync is specified, then needRegenerate must also be
 * specified (since this can't disambiguate two optional boolean parameters).
 * @return {Promise|SyncPromise} A promise that returns a List of Data packets
 * (where the first is the E-KEY data packet with the group's public key and the
 * rest are the D-KEY data packets with the group's private key encrypted with
 * the public key of each eligible member), or that is rejected with
 * GroupManagerDb.Error for a database error or SecurityException for an error
 * using the security KeyChain.
 */
GroupManager.prototype.getGroupKeyPromise = function
  (timeSlot, needRegenerate, useSync)
{
  if (needRegenerate == undefined)
    needRegenerate = true;

  var memberKeys = [];
  var result = [];
  var thisManager = this;
  var privateKeyBlob;
  var publicKeyBlob;
  var startTimeStamp;
  var endTimeStamp;

  // Get the time interval.
  return this.calculateIntervalPromise_(timeSlot, memberKeys, useSync)
  .then(function(finalInterval) {
    if (finalInterval.isValid() == false)
      return SyncPromise.resolve(result);

    startTimeStamp = Schedule.toIsoString(finalInterval.getStartTime());
    endTimeStamp = Schedule.toIsoString(finalInterval.getEndTime());

    // Generate the private and public keys.
    var eKeyName = new Name(thisManager.namespace_);
    eKeyName.append(Encryptor.NAME_COMPONENT_E_KEY).append(startTimeStamp)
      .append(endTimeStamp);

    return SyncPromise.resolve()
    .then(function() {
      // Only call hasEKeyPromise if needRegenerate is false.
      if (!needRegenerate)
        return thisManager.database_.hasEKeyPromise(eKeyName, useSync);
      else
        return SyncPromise.resolve(false);
    })
    .then(function(hasEKey) {
      if (!needRegenerate && hasEKey) {
        return thisManager.getEKeyPromise_(eKeyName, useSync)
        .then(function(keyPair) {
          privateKeyBlob = keyPair.privateKey;
          publicKeyBlob = keyPair.publicKey;
          return SyncPromise.resolve();
        });
      }
      else {
        return thisManager.generateKeyPairPromise_(useSync)
        .then(function(keyPair) {
          privateKeyBlob = keyPair.privateKeyBlob;
          publicKeyBlob = keyPair.publicKeyBlob;

          // deleteEKeyPromise_ does nothing if eKeyName does not exist.
          return thisManager.deleteEKeyPromise_(eKeyName, useSync);
        })
        .then(function() {
          return thisManager.addEKeyPromise_
            (eKeyName, publicKeyBlob, privateKeyBlob, useSync);
        });
      }
    })
    .then(function() {
      // Add the first element to the result.
      // The E-KEY (public key) data packet name convention is:
      // /<data_type>/E-KEY/[start-ts]/[end-ts]
      return thisManager.createEKeyDataPromise_
        (startTimeStamp, endTimeStamp, publicKeyBlob, useSync);
    })
    .then(function(data) {
      result.push(data);

      // Encrypt the private key with the public key from each member's certificate.

      // Process the memberKeys entry at i, and recursively call to process the
      // next entry. Return a promise which is resolved when all are processed.
      // (We have to make a recursive function to use Promises.)
      function processMemberKey(i) {
        if (i >= memberKeys.length)
          // Finished.
          return SyncPromise.resolve();

        var keyName = memberKeys[i].keyName;
        var certificateKey = memberKeys[i].publicKey;

        return thisManager.createDKeyDataPromise_
          (startTimeStamp, endTimeStamp, keyName, privateKeyBlob, certificateKey,
           useSync)
        .then(function(data) {
          result.push(data);

          return processMemberKey(i + 1);
        });
      }

      return processMemberKey(0);
    })
    .then(function() {
      return SyncPromise.resolve(result);
    });
  });
};

/**
 * Add a schedule with the given scheduleName.
 * @param {string} scheduleName The name of the schedule. The name cannot be
 * empty.
 * @param {Schedule} schedule The Schedule to add.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that fulfills when the schedule is
 * added, or that is rejected with GroupManagerDb.Error if a schedule with the
 * same name already exists, if the name is empty, or other database error.
 */
GroupManager.prototype.addSchedulePromise = function
  (scheduleName, schedule, useSync)
{
  return this.database_.addSchedulePromise(scheduleName, schedule, useSync);
};

/**
 * Delete the schedule with the given scheduleName. Also delete members which
 * use this schedule. If there is no schedule with the name, then do nothing.
 * @param {string} scheduleName The name of the schedule.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that fulfills when the schedule is
 * deleted (or there is no such schedule), or that is rejected with
 * GroupManagerDb.Error for a database error.
 */
GroupManager.prototype.deleteSchedulePromise = function(scheduleName, useSync)
{
  return this.database_.deleteSchedulePromise(scheduleName, useSync);
};

/**
 * Update the schedule with scheduleName and replace the old object with the
 * given schedule. Otherwise, if no schedule with name exists, a new schedule
 * with name and the given schedule will be added to database.
 * @param {string} scheduleName The name of the schedule. The name cannot be
 * empty.
 * @param {Schedule} schedule The Schedule to update or add.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that fulfills when the schedule is
 * updated, or that is rejected with GroupManagerDb.Error if the name is empty,
 * or other database error.
 */
GroupManager.prototype.updateSchedulePromise = function
  (scheduleName, schedule, useSync)
{
  return this.database_.updateSchedulePromise(scheduleName, schedule, useSync);
};

/**
 * Add a new member with the given memberCertificate into a schedule named
 * scheduleName. If cert is an IdentityCertificate made from memberCertificate,
 * then the member's identity name is cert.getPublicKeyName().getPrefix(-1).
 * @param {string} scheduleName The schedule name.
 * @param {Data} memberCertificate The member's certificate.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that fulfills when the member is
 * added, or that is rejected with GroupManagerDb.Error if there's no schedule
 * named scheduleName, if the member's identity name already exists, or other
 * database error. Or a promise that is rejected with DerDecodingException for
 * an error decoding memberCertificate as a certificate.
 */
GroupManager.prototype.addMemberPromise = function
  (scheduleName, memberCertificate, useSync)
{
  var cert = new IdentityCertificate(memberCertificate);
  return this.database_.addMemberPromise
    (scheduleName, cert.getPublicKeyName(), cert.getPublicKeyInfo().getKeyDer(),
     useSync);
};

/**
 * Remove a member with the given identity name. If there is no member with
 * the identity name, then do nothing.
 * @param {Name} identity The member's identity name.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that fulfills when the member is
 * removed (or there is no such member), or that is rejected with
 * GroupManagerDb.Error for a database error.
 */
GroupManager.prototype.removeMemberPromise = function(identity, useSync)
{
  return this.database_.deleteMemberPromise(identity, useSync);
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
 * scheduleName.
 */
GroupManager.prototype.updateMemberSchedulePromise = function
  (identity, scheduleName, useSync)
{
  return this.database_.updateMemberSchedulePromise
    (identity, scheduleName, useSync);
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
GroupManager.prototype.cleanEKeysPromise = function(useSync)
{
  return this.database_.cleanEKeysPromise(useSync);
};

/**
 * Calculate an Interval that covers the timeSlot.
 * @param {number} timeSlot The time slot to cover as milliseconds since
 * Jan 1, 1970 UTC.
 * @param {Array<object>} memberKeys First clear memberKeys then fill it with
 * the info of members who are allowed to access the interval. memberKeys is an
 * array of object where "keyName" is the Name of the public key and "publicKey"
 * is the Blob of the public key DER. The memberKeys entries are sorted by
 * the entry keyName.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that returns a new nterval covering
 * the time slot, or that is rejected with GroupManagerDb.Error for a database
 * error.
 */
GroupManager.prototype.calculateIntervalPromise_ = function
  (timeSlot, memberKeys, useSync)
{
  // Prepare.
  var positiveResult = new Interval();
  var negativeResult = new Interval();
  // Clear memberKeys.
  memberKeys.splice(0, memberKeys.length);
  var thisManager = this;

  // Get the all intervals from the schedules.
  return this.database_.listAllScheduleNamesPromise(useSync)
  .then(function(scheduleNames) {
    // Process the scheduleNames entry at i, and recursively call to process the
    // next entry. Return a promise which is resolved when all are processed.
    // (We have to make a recursive function to use Promises.)
    function processSchedule(i) {
      if (i >= scheduleNames.length)
        // Finished.
        return SyncPromise.resolve();

      var scheduleName = scheduleNames[i];

      return thisManager.database_.getSchedulePromise(scheduleName, useSync)
      .then(function(schedule) {
        var result = schedule.getCoveringInterval(timeSlot);
        var tempInterval = result.interval;

        if (result.isPositive) {
          if (!positiveResult.isValid())
            positiveResult = tempInterval;
          positiveResult.intersectWith(tempInterval);

          return thisManager.database_.getScheduleMembersPromise
            (scheduleName, useSync)
          .then(function(map) {
            // Add each entry in map to memberKeys.
            for (var iMap = 0; iMap < map.length; ++iMap)
              GroupManager.memberKeysAdd_(memberKeys, map[iMap]);

            return processSchedule(i + 1);
          });
        }
        else {
          if (!negativeResult.isValid())
            negativeResult = tempInterval;
          negativeResult.intersectWith(tempInterval);

          return processSchedule(i + 1);
        }
      });
    }

    return processSchedule(0);
  })
  .then(function() {
    if (!positiveResult.isValid())
      // Return an invalid interval when there is no member which has an
      // interval covering the time slot.
      return SyncPromise.resolve(new Interval(false));

    // Get the final interval result.
    var finalInterval;
    if (negativeResult.isValid())
      finalInterval = positiveResult.intersectWith(negativeResult);
    else
      finalInterval = positiveResult;

    return SyncPromise.resolve(finalInterval);
  });
};

/**
 * Add entry to memberKeys, sorted by entry.keyName. If there is already an
 * entry with keyName, then don't add.
 */
GroupManager.memberKeysAdd_ = function(memberKeys, entry)
{
  // Find the index of the first node where the keyName is not less than
  // entry.keyName.
  var i = 0;
  while (i < memberKeys.length) {
    var comparison = memberKeys[i].keyName.compare(entry.keyName);
    if (comparison == 0)
      // A duplicate, so don't add.
      return;

    if (comparison > 0)
      break;
    i += 1;
  }

  memberKeys.splice(i, 0, entry);
};

/**
 * Generate an RSA key pair according to keySize_.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that returns an object where
 * "privateKeyBlob" is the encoding Blob of the private key and "publicKeyBlob"
 * is the encoding Blob of the public key.
 */
GroupManager.prototype.generateKeyPairPromise_ = function(useSync)
{
  var params = new RsaKeyParams(this.keySize_);

  return RsaAlgorithm.generateKeyPromise(params)
  .then(function(privateKey) {
    var privateKeyBlob = privateKey.getKeyBits();
    var publicKey = RsaAlgorithm.deriveEncryptKey(privateKeyBlob);
    var publicKeyBlob = publicKey.getKeyBits();

    return SyncPromise.resolve
      ({ privateKeyBlob: privateKeyBlob, publicKeyBlob: publicKeyBlob });
  });
};

/**
 * Create an E-KEY Data packet for the given public key.
 * @param {string} startTimeStamp The start time stamp string to put in the name.
 * @param {string} endTimeStamp The end time stamp string to put in the name.
 * @param {Blob} publicKeyBlob A Blob of the public key DER.
 * @return The Data packet.
 * @throws SecurityException for an error using the security KeyChain.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that returns the Data packet, or that
 * is rejected with SecurityException for an error using the security KeyChain.
 */
GroupManager.prototype.createEKeyDataPromise_ = function
  (startTimeStamp, endTimeStamp, publicKeyBlob, useSync)
{
  var name = new Name(this.namespace_);
  name.append(Encryptor.NAME_COMPONENT_E_KEY).append(startTimeStamp)
    .append(endTimeStamp);

  var data = new Data(name);
  data.getMetaInfo().setFreshnessPeriod
    (this.freshnessHours_ * GroupManager.MILLISECONDS_IN_HOUR);
  data.setContent(publicKeyBlob);

  return this.keyChain_.signPromise(data);
};

/**
 * Create a D-KEY Data packet with an EncryptedContent for the given private
 * key, encrypted with the certificate key.
 * @param {string} startTimeStamp The start time stamp string to put in the name.
 * @param {string} endTimeStamp The end time stamp string to put in the name.
 * @param {Name} keyName The key name to put in the data packet name and the
 * EncryptedContent key locator.
 * @param {Blob} privateKeyBlob A Blob of the encoded private key.
 * @param {Blob} certificateKey The certificate key encoding, used to encrypt
 * the private key.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that returns the Data packet, or that
 * is rejected with SecurityException for an error using the security KeyChain.
 */
GroupManager.prototype.createDKeyDataPromise_ = function
  (startTimeStamp, endTimeStamp, keyName, privateKeyBlob, certificateKey,
   useSync)
{
  var name = new Name(this.namespace_);
  name.append(Encryptor.NAME_COMPONENT_D_KEY);
  name.append(startTimeStamp).append(endTimeStamp);
  var data = new Data(name);
  data.getMetaInfo().setFreshnessPeriod
    (this.freshnessHours_ * GroupManager.MILLISECONDS_IN_HOUR);
  var encryptParams = new EncryptParams(EncryptAlgorithmType.RsaOaep);
  var thisManager = this;

  return Encryptor.encryptDataPromise
    (data, privateKeyBlob, keyName, certificateKey, encryptParams, useSync)
  .catch(function(ex) {
    // Consolidate errors such as InvalidKeyException.
    return SyncPromise.reject(SecurityException(new Error
      ("createDKeyData: Error in encryptData: " + ex)));
  })
  .then(function() {
    return thisManager.keyChain_.signPromise(data);
  });
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
GroupManager.prototype.addEKeyPromise_ = function
  (eKeyName, publicKey, privateKey, useSync)
{
  return this.database_.addEKeyPromise(eKeyName, publicKey, privateKey, useSync);
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
GroupManager.prototype.getEKeyPromise_ = function(eKeyName, useSync)
{
  return this.database_.getEKeyPromise(eKeyName, useSync);
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
GroupManager.prototype.deleteEKeyPromise_ = function(eKeyName, useSync)
{
  return this.database_.deleteEKeyPromise(eKeyName, useSync);
};

GroupManager.MILLISECONDS_IN_HOUR = 3600 * 1000;
