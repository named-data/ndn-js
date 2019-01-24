/**
 * Copyright (C) 2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From the NAC library https://github.com/named-data/name-based-access-control/blob/new/src/encryptor.cpp
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
var Crypto = require('../crypto.js'); /** @ignore */
var Blob = require('../util/blob.js').Blob; /** @ignore */
var Name = require('../name.js').Name; /** @ignore */
var Data = require('../data.js').Data; /** @ignore */
var Interest = require('../interest.js').Interest; /** @ignore */
var SigningInfo = require('../security/signing-info.js').SigningInfo; /** @ignore */
var InMemoryStorageRetaining = require('../in-memory-storage/in-memory-storage-retaining.js').InMemoryStorageRetaining; /** @ignore */
var PublicKey = require('../security/certificate/public-key.js').PublicKey; /** @ignore */
var EncryptedContent = require('./encrypted-content.js').EncryptedContent; /** @ignore */
var EncryptParams = require('./algo/encrypt-params.js').EncryptParams; /** @ignore */
var EncryptAlgorithmType = require('./algo/encrypt-params.js').EncryptAlgorithmType; /** @ignore */
var AesAlgorithm = require('./algo/aes-algorithm.js').AesAlgorithm; /** @ignore */
var NdnCommon = require('../util/ndn-common.js').NdnCommon; /** @ignore */
var EncryptError = require('./encrypt-error.js').EncryptError; /** @ignore */
var LOG = require('../log.js').Log.LOG;

/**
 * EncryptorV2 encrypts the requested content for name-based access control (NAC)
 * using security v2. For the meaning of "KEK", etc. see:
 * https://github.com/named-data/name-based-access-control/blob/new/docs/spec.rst
 * 
 * Create an EncryptorV2 with the given parameters. This uses the face to
 * register to receive Interests for the prefix {ckPrefix}/CK.
 * @param {Name} accessPrefix The NAC prefix to fetch the Key Encryption Key
 * (KEK) (e.g., /access/prefix/NAC/data/subset). This copies the Name.
 * @param {Name} ckPrefix The prefix under which Content Keys (CK) will be
 * generated. (Each will have a unique version appended.) This copies the Name.
 * @param {SigningInfo} ckDataSigningInfo The SigningInfo parameters to sign the
 * Content Key (CK) Data packet. This copies the SigningInfo.
 * @param {function} onError On failure to create the CK data (failed to fetch
 * the KEK, failed to encrypt with the KEK, etc.), this calls
 * onError(errorCode, message) where errorCode is from
 * EncryptError.ErrorCode, and message is an error string. The encrypt
 * method will continue trying to retrieve the KEK until success (with each
 * attempt separated by RETRY_DELAY_KEK_RETRIEVAL_MS) and onError may be
 * called multiple times.
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {Validator} validator The validation policy to ensure correctness of
 * the KEK.
 * @param {KeyChain} keyChain The KeyChain used to sign Data packets.
 * @param {Face} face The Face that will be used to fetch the KEK and publish CK data.
 * @constructor
 */
var EncryptorV2 = function EncryptorV2
  (accessPrefix, ckPrefix, ckDataSigningInfo, onError, validator, keyChain, face)
{
  // Copy the Name.
  this.accessPrefix_ = new Name(accessPrefix);
  this.ckPrefix_ = new Name(ckPrefix);
  // ckBits_ will be set by regenerateCk().
  this.ckBits_ = null;
  this.ckDataSigningInfo_ = new SigningInfo(ckDataSigningInfo);
  this.isKekRetrievalInProgress_ = false;
  this.onError_ = onError;
  this.keyChain_ = keyChain;
  this.face_ = face;

  this.kekData_ = null;
  // Storage for encrypted CKs.
  this.storage_ = new InMemoryStorageRetaining();
  this.kekPendingInterestId_ = 0;

  this.regenerateCk();

  var thisEncryptor = this;
  var onInterest = function(prefix, interest, face, interestFilterId, filter) {
    var data = thisEncryptor.storage_.find(interest);
    if (data != null) {
      if (LOG > 3) console.log
        ("Serving " + data.getName().toUri() + " from InMemoryStorage");
      try {
        face.putData(data);
      } catch (ex) {
        console.log("Error in Face.putData: " + NdnCommon.getErrorWithStackTrace(ex));
      }
    }
    else {
      if (LOG > 3) console.log
        ("Didn't find CK data for " + interest.getName().toUri());
      // TODO: Send NACK?
    }
  };

  var onRegisterFailed = function(prefix) {
    if (LOG > 0) console.log("Failed to register prefix " + prefix.toUri());
  };

  this.ckRegisteredPrefixId_ = this.face_.registerPrefix
    (new Name(ckPrefix).append(EncryptorV2.NAME_COMPONENT_CK),
     onInterest, onRegisterFailed);
};

exports.EncryptorV2 = EncryptorV2;

EncryptorV2.prototype.shutdown = function()
{
  this.face_.unsetInterestFilter(this.ckRegisteredPrefixId_);
  if (this.kekPendingInterestId_ > 0)
    this.face_.removePendingInterest(this.kekPendingInterestId_);
};

/**
 * Encrypt the plainData using the existing Content Key (CK) and return a new
 * EncryptedContent.
 * @param {Buffer|Blob} plainData The data to encrypt.
 * @return {EncryptedContent} The new EncryptedContent.
 */
EncryptorV2.prototype.encrypt = function(plainData)
{
  // Generate the initial vector.
  var initialVector = Crypto.randomBytes(EncryptorV2.AES_IV_SIZE);

  var params = new EncryptParams(EncryptAlgorithmType.AesCbc);
  params.setInitialVector(new Blob(initialVector, false));
  if (!(plainData instanceof Blob))
    plainData = new Blob(plainData);
  // Debug: Use a Promise.
  var encryptedData = AesAlgorithm.encrypt
    (new Blob(this.ckBits_, false), plainData, params);

  var content = new EncryptedContent();
  content.setInitialVector(new Blob(initialVector, false));
  content.setPayload(encryptedData);
  content.setKeyLocatorName(this.ckName_);

  return content;
};

/**
 * Create a new Content Key (CK) and publish the corresponding CK Data packet.
 * This uses the onError given to the constructor to report errors.
 */
EncryptorV2.prototype.regenerateCk = function()
{
  // TODO: Ensure that the CK Data packet for the old CK is published when the
  // CK is updated before the KEK is fetched.

  this.ckName_ = new Name(this.ckPrefix_);
  this.ckName_.append(EncryptorV2.NAME_COMPONENT_CK);
  // The version is the ID of the CK.
  this.ckName_.appendVersion(new Date().getTime());

  if (LOG > 3) console.log("Generating new CK: " + this.ckName_.toUri());
  this.ckBits_ = Crypto.randomBytes(EncryptorV2.AES_KEY_SIZE);

  // One implication: If the CK is updated before the KEK is fetched, then
  // the KDK for the old CK will not be published.
  if (this.kekData_ == null)
    this.retryFetchingKek_();
  else
    this.makeAndPublishCkData_(this.onError_);
};

/**
 * Get the number of packets stored in in-memory storage.
 * @return {number} The number of packets.
 */
EncryptorV2.prototype.size = function()
{
  return this.storage_.size();
};

EncryptorV2.prototype.retryFetchingKek_ = function()
{
  if (this.isKekRetrievalInProgress_)
    return;

  if (LOG > 3) console.log("Retrying fetching of the KEK");
  this.isKekRetrievalInProgress_ = true;

  var thisEncryptor = this;
  this.fetchKekAndPublishCkData_
    (function() {
       if (LOG > 3) console.log("The KEK was retrieved and published");
       thisEncryptor.isKekRetrievalInProgress_ = false;
     },
     function(errorCode, message) {
       if (LOG > 3) console.log("Failed to retrieve KEK: " + message);
       thisEncryptor.isKekRetrievalInProgress_ = false;
       thisEncryptor.onError_(errorCode, message);
     },
     EncryptorV2.N_RETRIES);
};

/**
 * Create an Interest for <access-prefix>/KEK to retrieve the
 * <access-prefix>/KEK/<key-id> KEK Data packet, and set kekData_.
 * @param {function} onReady When the KEK is retrieved and published, this calls
 * onReady().
 * @param {function} onError On failure, this calls onError(errorCode, message)
 * where errorCode is from EncryptError.ErrorCode, and message is an error
 * string.
 * @param {number} nTriesLeft The number of retries for expressInterest timeouts.
 */
EncryptorV2.prototype.fetchKekAndPublishCkData_ = function
  (onReady, onError, nTriesLeft)
{
  if (LOG > 3) console.log("Fetching KEK: " +
    new Name(this.accessPrefix_).append(EncryptorV2.NAME_COMPONENT_KEK).toUri());

  if (this.kekPendingInterestId_ > 0) {
    onError(EncryptError.ErrorCode.General,
      "fetchKekAndPublishCkData: There is already a kekPendingInterestId_");
    return;
  }

  var thisEncryptor = this;
  var onData = function(interest, kekData) {
    thisEncryptor.kekPendingInterestId_ = 0;
    // TODO: Verify if the key is legitimate.
    thisEncryptor.kekData_ = kekData;
    if (thisEncryptor.makeAndPublishCkData_(onError))
      onReady();
    // Otherwise, failure has already been reported.
  };

  var onTimeout = function(interest) {
    thisEncryptor.kekPendingInterestId_ = 0;
    if (nTriesLeft > 1)
      thisEncryptor.fetchKekAndPublishCkData_(onReady, onError, nTriesLeft - 1);
    else {
      onError(EncryptError.ErrorCode.KekRetrievalTimeout,
        "Retrieval of KEK [" + interest.getName().toUri() + "] timed out");
      if (LOG > 3) console.log("Scheduling retry after all timeouts");
      setTimeout
        (function() { thisEncryptor.retryFetchingKek_(); },
         EncryptorV2.RETRY_DELAY_KEK_RETRIEVAL_MS);
    }
  };

  var onNetworkNack = function(interest, networkNack) {
    thisEncryptor.kekPendingInterestId_ = 0;
    if (nTriesLeft > 1) {
      setTimeout
        (function() {
           thisEncryptor.fetchKekAndPublishCkData_(onReady, onError, nTriesLeft - 1);
         },
         EncryptorV2.RETRY_DELAY_AFTER_NACK_MS);
    }
    else {
      onError(EncryptError.ErrorCode.KekRetrievalFailure,
        "Retrieval of KEK [" + interest.getName().toUri() +
        "] failed. Got NACK (" + networkNack.getReason() + ")");
      if (LOG > 3) console.log("Scheduling retry from NACK");
      setTimeout
        (function() { thisEncryptor.retryFetchingKek_(); },
         EncryptorV2.RETRY_DELAY_KEK_RETRIEVAL_MS);
    }
  };

  try {
    this.kekPendingInterestId_ = this.face_.expressInterest
      (new Interest(new Name(this.accessPrefix_).append(EncryptorV2.NAME_COMPONENT_KEK))
         .setMustBeFresh(true)
         .setCanBePrefix(true),
       onData, onTimeout, onNetworkNack);
  } catch (ex) {
    onError(EncryptError.ErrorCode.General, "expressInterest error: " + ex);
  }
};

/**
 * Make a CK Data packet for ckName_ encrypted by the KEK in kekData_ and
 * insert it in the storage_.
 * @param {function} onError On failure, this calls onError(errorCode, message)
 * where errorCode is from EncryptError.ErrorCode, and message is an error
 * string.
 * @returns {boolean} True on success, else false.
 */
EncryptorV2.prototype.makeAndPublishCkData_ = function(onError)
{
  try {
    var kek = new PublicKey(this.kekData_.getContent());

    var content = new EncryptedContent();
    // Debug: Use a Promise.
    var payload = kek.encrypt(this.ckBits_, EncryptAlgorithmType.RsaOaep);
    content.setPayload(payload);

    var ckData = new Data
      (new Name(this.ckName_).append(EncryptorV2.NAME_COMPONENT_ENCRYPTED_BY)
       .append(this.kekData_.getName()));
    ckData.setContent(content.wireEncodeV2());
    // FreshnessPeriod can serve as a soft access control for revoking access.
    ckData.getMetaInfo().setFreshnessPeriod
      (EncryptorV2.DEFAULT_CK_FRESHNESS_PERIOD_MS);
    // Debug: Use a Promise.
    this.keyChain_.sign(ckData, this.ckDataSigningInfo_);
    this.storage_.insert(ckData);

    if (LOG > 3) console.log("Publishing CK data: " + ckData.getName().toUri());
    return true;
  } catch (ex) {
    onError(EncryptError.ErrorCode.EncryptionFailure,
      "Failed to encrypt generated CK with KEK " + this.kekData_.getName().toUri());
    return false;
  }
};

EncryptorV2.NAME_COMPONENT_ENCRYPTED_BY = new Name.Component("ENCRYPTED-BY");
EncryptorV2.NAME_COMPONENT_NAC = new Name.Component("NAC");
EncryptorV2.NAME_COMPONENT_KEK = new Name.Component("KEK");
EncryptorV2.NAME_COMPONENT_KDK = new Name.Component("KDK");
EncryptorV2.NAME_COMPONENT_CK = new Name.Component("CK");

EncryptorV2.RETRY_DELAY_AFTER_NACK_MS = 1000.0;
EncryptorV2.RETRY_DELAY_KEK_RETRIEVAL_MS = 60 * 1000.0;

EncryptorV2.AES_KEY_SIZE = 32;
EncryptorV2.AES_IV_SIZE = 16;
EncryptorV2.N_RETRIES = 3;

EncryptorV2.DEFAULT_CK_FRESHNESS_PERIOD_MS = 3600 * 1000.0;
