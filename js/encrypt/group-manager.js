/**
 * Copyright (C) 2015 Regents of the University of California.
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

var Name = require('../name.js').Name;
var Data = require('../data.js').Data;
var SyncPromise = require('../util/sync-promise.js').SyncPromise;
var SecurityException = require('../security/security-exception.js').SecurityException;
var EncryptParams = require('./algo/encrypt-params.js').EncryptParams;
var EncryptAlgorithmType = require('./algo/encrypt-params.js').EncryptAlgorithmType;
var Encryptor = require('./algo/encryptor.js').Encryptor;

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
 * @param {number} freshnessHours The FreshnessPeriod of data packets carrying
 * the keys
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
  (startTimeStamp, endTimeStamp, keyName, privateKeyBlob, certificateKey, useSync)
{
  var name = new Name(this.namespace_);
  name.append(Encryptor.NAME_COMPONENT_D_KEY);
  name.append(startTimeStamp).append(endTimeStamp)
    .append(Encryptor.NAME_COMPONENT_FOR).append(keyName);
  var data = new Data(name);
  data.getMetaInfo().setFreshnessPeriod
    (this.freshnessHours_ * GroupManager.MILLISECONDS_IN_HOUR);
  var encryptParams = new EncryptParams(EncryptAlgorithmType.RsaPkcs);
  var identityManger = this.keyChain_.getIdentityManager();
  
  return Encryptor.encryptDataPromise
    (data, privateKeyBlob, keyName, certificateKey, encryptParams, useSync)
  .catch(function(ex) {
    // Consolidate errors such as InvalidKeyException.
    return SyncPromise.reject(SecurityException(new Error
      ("createDKeyData: Error in encryptData: " + ex)));
  })
  .then(function() {
    // TODO: When implemented, use KeyChain.sign(data) which does the same thing.
    return identityManger.identityStorage.getDefaultIdentityPromise(useSync)
    .then(function(identityName) {
      return identityManger.identityStorage.getDefaultCertificateNameForIdentityPromise
        (identityName, useSync)     ;
    })
    .then(function(defaultCertificateName) {
      return identityManger.identityStorage.getCertificatePromise
        (defaultCertificateName, true, useSync);
    })
    .then(function(certificate) {
      var certificateName = certificate.getName().getPrefix(-1);
      return identityManger.signByCertificatePromise
        (data, certificateName, useSync);
    });
  })
  .then(function() {
    return SyncPromise.resolve(data);
  });
};

GroupManager.MILLISECONDS_IN_HOUR = 3600 * 1000;
