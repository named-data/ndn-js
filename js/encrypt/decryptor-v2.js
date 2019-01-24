/**
 * Copyright (C) 2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From the NAC library https://github.com/named-data/name-based-access-control/blob/new/src/decryptor.cpp
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
var Name = require('../name.js').Name;
var Interest = require('../interest.js').Interest;
var EncryptError = require('./encrypt-error.js').EncryptError; /** @ignore */
var KeyChain = require('../security/key-chain.js').KeyChain; /** @ignore */
var SafeBag = require('../security/safe-bag.js').SafeBag; /** @ignore */
var EncryptorV2 = require('./encryptor-v2.js').EncryptorV2; /** @ignore */
var EncryptError = require('./encrypt-error.js').EncryptError; /** @ignore */
var EncryptedContent = require('./encrypted-content.js').EncryptedContent; /** @ignore */
var EncryptParams = require('./algo/encrypt-params.js').EncryptParams; /** @ignore */
var EncryptAlgorithmType = require('./algo/encrypt-params.js').EncryptAlgorithmType; /** @ignore */
var AesAlgorithm = require('./algo/aes-algorithm.js').AesAlgorithm; /** @ignore */
var NdnCommon = require('../util/ndn-common.js').NdnCommon; /** @ignore */
var Pib = require('../security/pib/pib.js').Pib; /** @ignore */
var SyncPromise = require('../util/sync-promise.js').SyncPromise; /** @ignore */
var KeyLocatorType = require('../key-locator.js').KeyLocatorType; /** @ignore */
var LOG = require('../log.js').Log.LOG;

/**
 * DecryptorV2 decrypts the supplied EncryptedContent element, using
 * asynchronous operations, contingent on the retrieval of the CK Data packet,
 * the KDK, and the successful decryption of both of these. For the meaning of
 * "KDK", etc. see:
 * https://github.com/named-data/name-based-access-control/blob/new/docs/spec.rst
 * 
 * Create a DecryptorV2 with the given parameters.
 * @param {PibKey} credentialsKey The credentials key to be used to retrieve and
 * decrypt the KDK.
 * @param {Validator} validator The validation policy to ensure the validity of
 * the KDK and CK.
 * @param {KeyChain} keyChain The KeyChain that will be used to decrypt the KDK.
 * @param {Face} face The Face that will be used to fetch the CK and KDK.
 * @constructor
 */
var DecryptorV2 = function DecryptorV2(credentialsKey, validator, keyChain, face)
{
  // The dictionary key is the CK Name URI string. The value is a DecryptorV2.ContentKey.
  // TODO: add some expiration, so they are not stored forever.
  this.contentKeys_ = {};

  this.credentialsKey_ = credentialsKey;
  // this.validator_ = validator;
  this.face_ = face;
  // The external keychain with access credentials.
  this.keyChain_ = keyChain;

  // The internal in-memory keychain for temporarily storing KDKs.
  this.internalKeyChain_ = new KeyChain("pib-memory:", "tpm-memory:");
};

exports.DecryptorV2 = DecryptorV2;

DecryptorV2.prototype.shutdown = function()
{
  for (var nameUri in this.contentKeys_) {
    var contentKey = this.contentKeys_[nameUri];

    if (contentKey.pendingInterest > 0) {
      this.face_.removePendingInterest(contentKey.pendingInterest);
      contentKey.pendingInterest = 0;

      for (var i in contentKey.pendingDecrypts)
        contentKey.pendingDecrypts[i].onError
          (EncryptError.ErrorCode.CkRetrievalFailure,
           "Canceling pending decrypt as ContentKey is being destroyed");

      // Clear is not really necessary, but just in case.
      contentKey.pendingDecrypts = [];
    }
  }
};

/**
 * Asynchronously decrypt the encryptedContent.
 * @param {EncryptedContent} encryptedContent The EncryptedContent to decrypt,
 * which must have a KeyLocator with a KEYNAME and and initial vector. This does
 * not copy the EncryptedContent object. If you may change it later, then pass
 * in a copy of the object.
 * @param {function} onSuccess On successful decryption, this calls
 * onSuccess(plainData) where plainData is the decrypted Blob.
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onError On failure, this calls onError(errorCode, message)
 * where errorCode is from EncryptError.ErrorCode, and message is an error
 * string.
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 */
DecryptorV2.prototype.decrypt = function(encryptedContent, onSuccess, onError)
{
  if (encryptedContent.getKeyLocator().getType() != KeyLocatorType.KEYNAME) {
    if (LOG > 3) console.log
      ("Missing required KeyLocator in the supplied EncryptedContent block");
    onError(EncryptError.ErrorCode.MissingRequiredKeyLocator,
      "Missing required KeyLocator in the supplied EncryptedContent block");
    return;
  }

  if (!encryptedContent.hasInitialVector()) {
    if (LOG > 3) console.log
      ("Missing required initial vector in the supplied EncryptedContent block");
    onError(EncryptError.ErrorCode.MissingRequiredInitialVector,
      "Missing required initial vector in the supplied EncryptedContent block");
    return;
  }

  var ckName = encryptedContent.getKeyLocatorName();
  var ckNameUri = ckName.toUri();
  var contentKey = this.contentKeys_[ckNameUri];
  var isNew = (contentKey === undefined);
  if (isNew) {
    contentKey = new DecryptorV2.ContentKey();
    this.contentKeys_[ckNameUri] = contentKey;
  }

  if (contentKey.isRetrieved)
    DecryptorV2.doDecrypt_(encryptedContent, contentKey.bits, onSuccess, onError);
  else {
    if (LOG > 3) console.log("CK " + ckName.toUri() +
      " not yet available, so adding to the pending decrypt queue");
    contentKey.pendingDecrypts.push(new DecryptorV2.ContentKey.PendingDecrypt
      (encryptedContent, onSuccess, onError));
  }

  if (isNew)
    this.fetchCk_(ckName, contentKey, onError, EncryptorV2.N_RETRIES);
};

DecryptorV2.ContentKey = function DecryptorV2ContentKey()
{
  this.isRetrieved = false;
  // Blob
  this.bits = null;
  this.pendingInterest = 0;
  // Array of DecryptorV2.ContentKey.PendingDecrypt
  this.pendingDecrypts = [];
};

DecryptorV2.ContentKey.PendingDecrypt = function DecryptorV2ContentKeyPendingDecrypt
  (encryptedContent, onSuccess, onError)
{
  // EncryptedContent
  this.encryptedContent = encryptedContent;
  // This calls onSuccess(plainData) where plainData is a Blob.
  this.onSuccess = onSuccess;
  // This calls onError(errorCode, message)
  this.onError = onError;
};

DecryptorV2.prototype.fetchCk_ = function
  (ckName, contentKey, onError, nTriesLeft)
{
  // The full name of the CK is
  //
  // <whatever-prefix>/CK/<ck-id>  /ENCRYPTED-BY /<kek-prefix>/KEK/<key-id>
  // \                          /                \                        /
  //  -----------  -------------                  -----------  -----------
  //             \/                                          \/
  //   from the encrypted data          unknown (name in retrieved CK is used to determine KDK)

  if (LOG > 3) console.log("Fetching CK " + ckName.toUri());

  var thisDecryptor = this;
  var onData = function(ckInterest, ckData) {
    try {
      contentKey.pendingInterest = 0;
      // TODO: Verify that the key is legitimate.
      var kdkPrefix = [null];
      var kdkIdentityName = [null];
      var kdkKeyName = [null];
      if (!DecryptorV2.extractKdkInfoFromCkName_
          (ckData.getName(), ckInterest.getName(), onError, kdkPrefix,
           kdkIdentityName, kdkKeyName))
        // The error has already been reported.
        return;

      // Check if the KDK already exists.
      var kdkIdentity = null;
      try {
        // Debug: Use a Promise.
        kdkIdentity = thisDecryptor.internalKeyChain_.getPib().getIdentity
          (kdkIdentityName[0]);
      } catch (ex) {
        if (!(ex instanceof Pib.Error))
          throw ex;
      }
      if (kdkIdentity != null) {
        var kdkKey = null;
        try {
          // Debug: Use a Promise.
          kdkKey = kdkIdentity.getKey(kdkKeyName[0]);
        } catch (ex) {
          if (!(ex instanceof Pib.Error))
            throw ex;
        }
        if (kdkKey != null) {
          // The KDK was already fetched and imported.
          if (LOG > 3) console.log("KDK " + kdkKeyName.toUri() +
            " already exists, so directly using it to decrypt the CK");
          thisDecryptor.decryptCkAndProcessPendingDecrypts_
            (contentKey, ckData, kdkKeyName[0], onError);
          return;
        }
      }

      thisDecryptor.fetchKdk_
        (contentKey, kdkPrefix[0], ckData, onError, EncryptorV2.N_RETRIES);
    } catch (ex) {
      onError(EncryptError.ErrorCode.General, "Error in fetchCk onData: " + ex);
    }
  };

  var onTimeout = function(interest) {
    contentKey.pendingInterest = 0;
    if (nTriesLeft > 1)
      thisDecryptor.fetchCk_(ckName, contentKey, onError, nTriesLeft - 1);
    else
      onError(EncryptError.ErrorCode.CkRetrievalTimeout,
        "Retrieval of CK [" + interest.getName().toUri() + "] timed out");
  };

  var onNetworkNack = function(interest, networkNack) {
    contentKey.pendingInterest = 0;
    onError(EncryptError.ErrorCode.CkRetrievalFailure,
      "Retrieval of CK [" + interest.getName().toUri() +
      "] failed. Got NACK (" + networkNack.getReason() + ")");
  };

  try {
    contentKey.pendingInterest = this.face_.expressInterest
      (new Interest(ckName).setMustBeFresh(false).setCanBePrefix(true),
       onData, onTimeout, onNetworkNack);
  } catch (ex) {
    onError(EncryptError.ErrorCode.General, "expressInterest error: " + ex);
  }
};

/**
 *
 * @param {DecryptorV2.ContentKey} contentKey
 * @param {Name} kdkPrefix
 * @param {Data} ckData
 * @param {function} onError On error, this calls onError(errorCode, message).
 * @param {number} nTriesLeft
 */
DecryptorV2.prototype.fetchKdk_ = function
  (contentKey, kdkPrefix, ckData, onError, nTriesLeft)
{
  // <kdk-prefix>/KDK/<kdk-id>    /ENCRYPTED-BY  /<credential-identity>/KEY/<key-id>
  // \                          /                \                                /
  //  -----------  -------------                  ---------------  ---------------
  //             \/                                              \/
  //     from the CK data                                from configuration

  var kdkName = new Name(kdkPrefix);
  kdkName
    .append(EncryptorV2.NAME_COMPONENT_ENCRYPTED_BY)
    .append(this.credentialsKey_.getName());

  if (LOG > 3) console.log("Fetching KDK " + kdkName.toUri());

  var thisDecryptor = this;
  var onData = function(kdkInterest, kdkData) {
    contentKey.pendingInterest = 0;
    // TODO: Verify that the key is legitimate.

    var isOk = thisDecryptor.decryptAndImportKdk_(kdkData, onError);
    if (!isOk)
      return;
    // This way of getting the kdkKeyName is a bit hacky.
    var kdkKeyName = kdkPrefix.getPrefix(-2)
      .append("KEY").append(kdkPrefix.get(-1));
    thisDecryptor.decryptCkAndProcessPendingDecrypts_
      (contentKey, ckData, kdkKeyName, onError);
  };

  var onTimeout = function(interest) {
    contentKey.pendingInterest = 0;
    if (nTriesLeft > 1)
      thisDecryptor.fetchKdk_
        (contentKey, kdkPrefix, ckData, onError, nTriesLeft - 1);
    else
      onError(EncryptError.ErrorCode.KdkRetrievalTimeout,
        "Retrieval of KDK [" + interest.getName().toUri() + "] timed out");
  };

  var onNetworkNack = function(interest, networkNack) {
    contentKey.pendingInterest = 0;
    onError(EncryptError.ErrorCode.KdkRetrievalFailure,
      "Retrieval of KDK [" + interest.getName().toUri() +
      "] failed. Got NACK (" + networkNack.getReason() + ")");
  };

  try {
    contentKey.pendingInterest = this.face_.expressInterest
      (new Interest(kdkName).setMustBeFresh(true).setCanBePrefix(false),
       onData, onTimeout, onNetworkNack);
  } catch (ex) {
    onError(EncryptError.ErrorCode.General, "expressInterest error: " + ex);
  }
};

/**
 * @param {Data} kdkData
 * @param {function} onError On error, this calls onError(errorCode, message).
 * @returns {boolean} True for success, false for error (where this has called 
 * onError).
 */
DecryptorV2.prototype.decryptAndImportKdk_ = function(kdkData, onError)
{
  try {
    if (LOG > 3) console.log("Decrypting and importing KDK " +
      kdkData.getName().toUri());
    var encryptedContent = new EncryptedContent();
    encryptedContent.wireDecodeV2(kdkData.getContent());

    var safeBag = new SafeBag(encryptedContent.getPayload());
    // Debug: Use a Promise.
    var secret = SyncPromise.getValue(this.keyChain_.getTpm().decryptPromise
      (encryptedContent.getPayloadKey().buf(), this.credentialsKey_.getName(), true));
    if (secret.isNull()) {
      onError(EncryptError.ErrorCode.TpmKeyNotFound,
         "Could not decrypt secret, " + this.credentialsKey_.getName().toUri() +
         " not found in TPM");
      return false;
    }

    this.internalKeyChain_.importSafeBag(safeBag, secret.buf());
    return true;
  } catch (ex) {
    // This can be EncodingException, Pib.Error, Tpm.Error, or a bunch of
    // other runtime-derived errors.
    onError(EncryptError.ErrorCode.DecryptionFailure,
       "Failed to decrypt KDK [" + kdkData.getName().toUri() + "]: " + ex);
    return false;
  }
};

/**
 * @param {DecryptorV2.ContentKey} contentKey
 * @param {Data} ckData
 * @param {Name} kdkKeyName
 * @param {function} onError On error, this calls onError(errorCode, message).
 */
DecryptorV2.prototype.decryptCkAndProcessPendingDecrypts_ = function
  (contentKey, ckData, kdkKeyName, onError)
{
  if (LOG > 3) console.log("Decrypting CK data " + ckData.getName().toUri());

  var content = new EncryptedContent();
  try {
    content.wireDecodeV2(ckData.getContent());
  } catch (ex) {
    onError(EncryptError.ErrorCode.InvalidEncryptedFormat,
      "Error decrypting EncryptedContent: " + ex);
    return;
  }

  var ckBits;
  try {
    // Debug: Use a Promise.
    ckBits = SyncPromise.getValue(this.internalKeyChain_.getTpm().decryptPromise
      (content.getPayload().buf(), kdkKeyName, true));
  } catch (ex) {
    // We don't expect this from the in-memory KeyChain.
    onError(EncryptError.ErrorCode.DecryptionFailure,
      "Error decrypting the CK EncryptedContent " + ex);
    return;
  }

  if (ckBits.isNull()) {
    onError(EncryptError.ErrorCode.TpmKeyNotFound,
      "Could not decrypt secret, " + kdkKeyName.toUri() + " not found in TPM");
    return;
  }

  contentKey.bits = ckBits;
  contentKey.isRetrieved = true;

  for (var i in contentKey.pendingDecrypts) {
    var pendingDecrypt = contentKey.pendingDecrypts[i];
    // TODO: If this calls onError, should we quit?
    DecryptorV2.doDecrypt_
      (pendingDecrypt.encryptedContent, contentKey.bits,
       pendingDecrypt.onSuccess, pendingDecrypt.onError);
  }

  contentKey.pendingDecrypts = [];
};

/**
 * @param {EncryptedContent} content
 * @param {Blob} ckBits
 * @param {function} onSuccess On success, this calls onSuccess(plainData)
 * where plainData is a Blob.
 * @param {function} onError On error, this calls onError(errorCode, message).
 */
DecryptorV2.doDecrypt_ = function(content, ckBits, onSuccess, onError)
{
  if (!content.hasInitialVector()) {
    onError(EncryptError.ErrorCode.MissingRequiredInitialVector,
      "Expecting Initial Vector in the encrypted content, but it is not present");
    return;
  }

  var plainData;
  try {
    var params = new EncryptParams(EncryptAlgorithmType.AesCbc);
    params.setInitialVector(content.getInitialVector());
    // Debug: Use a Promise.
    plainData = AesAlgorithm.decrypt(ckBits, content.getPayload(), params);
  } catch (ex) {
    onError(EncryptError.ErrorCode.DecryptionFailure,
      "Decryption error in doDecrypt: " + ex);
    return;
  }

  try {
    onSuccess(plainData);
  } catch (ex) {
    console.log("Error in onSuccess: " + NdnCommon.getErrorWithStackTrace(ex));
  }
};

/**
 * Convert the KEK name to the KDK prefix:
 * <access-namespace>/KEK/<key-id> ==> <access-namespace>/KDK/<key-id>.
 * @param {Name} kekName The KEK name.
 * @param {function} onError This calls onError.onError(errorCode, message) for
 * an error.
 * @return {Name} The KDK prefix, or null if an error was reported to onError.
 */
DecryptorV2.convertKekNameToKdkPrefix_ = function(kekName, onError)
{
  if (kekName.size() < 2 ||
      !kekName.get(-2).equals(EncryptorV2.NAME_COMPONENT_KEK)) {
    onError(EncryptError.ErrorCode.KekInvalidName,
      "Invalid KEK name [" + kekName.toUri() + "]");
    return null;
  }

  return kekName.getPrefix(-2)
    .append(EncryptorV2.NAME_COMPONENT_KDK).append(kekName.get(-1));
};

/**
 * Extract the KDK information from the CK Data packet name. The KDK identity
 * name plus the KDK key ID together identify the KDK private key in the KeyChain.
 * @param {Name} ckDataName The name of the CK Data packet.
 * @param {Name} ckName The CK name from the Interest used to fetch the CK Data
 * packet.
 * @param {function} onError This calls onError.onError(errorCode, message) for
 * an error.
 * @param {Array<Name>} kdkPrefix This sets kdkPrefix[0] to the KDK prefix.
 * @param {Array<Name>} kdkIdentityName This sets kdkIdentityName[0] to the KDK
 * identity name.
 * @param {Array<Name>} kdkKeyId This sets kdkKeyId[0] to the KDK key ID.
 * @return {boolean} True for success or false if an error was reported to
 * onError.
 */
DecryptorV2.extractKdkInfoFromCkName_ = function
  (ckDataName, ckName, onError, kdkPrefix, kdkIdentityName, kdkKeyId)
{
  // <full-ck-name-with-id> | /ENCRYPTED-BY/<kek-prefix>/NAC/KEK/<key-id>

  if (ckDataName.size() < ckName.size() + 1 ||
      !ckDataName.getPrefix(ckName.size()).equals(ckName) ||
      !ckDataName.get(ckName.size()).equals(EncryptorV2.NAME_COMPONENT_ENCRYPTED_BY)) {
    onError(EncryptError.ErrorCode.CkInvalidName,
      "Invalid CK name [" + ckDataName.toUri() + "]");
    return false;
  }

  var kekName = ckDataName.getSubName(ckName.size() + 1);
  kdkPrefix[0] = DecryptorV2.convertKekNameToKdkPrefix_(kekName, onError);
  if (kdkPrefix[0] == null)
    // The error has already been reported.
    return false;

  kdkIdentityName[0] = kekName.getPrefix(-2);
  kdkKeyId[0] = kekName.getPrefix(-2).append("KEY").append(kekName.get(-1));
  return true;
};
