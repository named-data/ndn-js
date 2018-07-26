/**
 * Copyright (C) 2014-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * From ndn-cxx security by Yingdi Yu <yingdi@cs.ucla.edu>.
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

// Use capitalized Crypto to not clash with the browser's crypto.subtle.
/** @ignore */
var Crypto = require('../../crypto.js'); /** @ignore */
var Name = require('../../name.js').Name; /** @ignore */
var Data = require('../../data.js').Data; /** @ignore */
var Blob = require('../../util/blob.js').Blob; /** @ignore */
var ConfigFile = require('../../util/config-file.js').ConfigFile; /** @ignore */
var DigestSha256Signature = require('../../digest-sha256-signature.js').DigestSha256Signature; /** @ignore */
var Sha256WithRsaSignature = require('../../sha256-with-rsa-signature.js').Sha256WithRsaSignature; /** @ignore */
var Sha256WithEcdsaSignature = require('../../sha256-with-ecdsa-signature.js').Sha256WithEcdsaSignature; /** @ignore */
var KeyLocatorType = require('../../key-locator.js').KeyLocatorType; /** @ignore */
var WireFormat = require('../../encoding/wire-format.js').WireFormat; /** @ignore */
var SecurityException = require('../security-exception.js').SecurityException; /** @ignore */
var DigestAlgorithm = require('../security-types.js').DigestAlgorithm; /** @ignore */
var KeyType = require('../security-types.js').KeyType; /** @ignore */
var RsaKeyParams = require('../key-params.js').RsaKeyParams; /** @ignore */
var IdentityCertificate = require('../certificate/identity-certificate.js').IdentityCertificate; /** @ignore */
var PublicKey = require('../certificate/public-key.js').PublicKey; /** @ignore */
var CertificateSubjectDescription = require('../certificate/certificate-subject-description.js').CertificateSubjectDescription; /** @ignore */
var SyncPromise = require('../../util/sync-promise.js').SyncPromise; /** @ignore */
var BasicIdentityStorage = require('./basic-identity-storage.js').BasicIdentityStorage; /** @ignore */
var FilePrivateKeyStorage = require('./file-private-key-storage.js').FilePrivateKeyStorage;

/**
 * An IdentityManager is the interface of operations related to identity, keys,
 * and certificates.
 *
 * Create a new IdentityManager to use the IdentityStorage and
 * PrivateKeyStorage.
 * @param {IdentityStorage} identityStorage An object of a subclass of
 * IdentityStorage. In Node.js, if this is omitted then use BasicIdentityStorage.
 * @param {PrivateKeyStorage} privateKeyStorage An object of a subclass of
 * PrivateKeyStorage. In Node.js, if this is omitted then use the default
 * PrivateKeyStorage for your system, which is FilePrivateKeyStorage for any
 * system other than OS X. (OS X key chain storage is not yet implemented, so
 * you must supply a different PrivateKeyStorage.)
 * @throws SecurityException if this is not in Node.js and identityStorage or
 * privateKeyStorage is omitted.
 * @constructor
 */
var IdentityManager = function IdentityManager
  (identityStorage, privateKeyStorage)
{
  if (privateKeyStorage) {
    // Don't call checkTpm() when using a custom PrivateKeyStorage.
    if (!identityStorage)
        // We don't expect this to happen.
        throw new Error
          ("IdentityManager: A custom privateKeyStorage is supplied with a null identityStorage")

    this.identityStorage = identityStorage;
    this.privateKeyStorage = privateKeyStorage;
  }
  else {
    if (!ConfigFile)
      // Assume we are in the browser.
      throw new SecurityException(new Error
        ("IdentityManager: If not in Node.js then you must supply identityStorage and privateKeyStorage."));
    var config = new ConfigFile();

    var canonicalTpmLocator = [null];
    var thisStorage = this;
    // Make the function that BasicIdentityStorage will call the first time it
    // is used. It has to be an async promise becuase getTpmLocatorPromise is async.
    function initialCheckPromise()
    {
      return thisStorage.checkTpmPromise_(canonicalTpmLocator[0]);
    }

    this.identityStorage = identityStorage ? identityStorage
      : IdentityManager.getDefaultIdentityStorage_(config, initialCheckPromise);
    this.privateKeyStorage = IdentityManager.getDefaultPrivateKeyStorage_
      (config, canonicalTpmLocator);
  }
};

exports.IdentityManager = IdentityManager;

/**
 * Create an identity by creating a pair of Key-Signing-Key (KSK) for this
 * identity and a self-signed certificate of the KSK. If a key pair or
 * certificate for the identity already exists, use it.
 * @param {Name} identityName The name of the identity.
 * @params {KeyParams} params The key parameters if a key needs to be generated
 * for the identity.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the name of the default
 * certificate of the identity.
 */
IdentityManager.prototype.createIdentityAndCertificatePromise = function
  (identityName, params, useSync)
{
  var thisManager = this;
  var generateKey = true;
  var keyName = null;

  return this.identityStorage.addIdentityPromise(identityName, useSync)
  .then(function() {
    return thisManager.identityStorage.getDefaultKeyNameForIdentityPromise
      (identityName, useSync)
    .then(function(localKeyName) {
      keyName = localKeyName;

      // Set generateKey.
      return thisManager.identityStorage.getKeyPromise(keyName, useSync)
      .then(function(publicKeyDer) {
        var key = new PublicKey(publicKeyDer);
        if (key.getKeyType() == params.getKeyType())
          // The key exists and has the same type, so don't need to generate one.
          generateKey = false;
        return SyncPromise.resolve();
      });
    }, function(err) {
      if (!(err instanceof SecurityException))
        throw err;

      // The key doesn't exist, so leave generateKey true.
      return SyncPromise.resolve();
    });
  })
  .then(function() {
    if (generateKey)
      return thisManager.generateKeyPairPromise(identityName, true, params, useSync)
      .then(function(localKeyName) {
        keyName = localKeyName;
        return thisManager.identityStorage.setDefaultKeyNameForIdentityPromise
          (keyName, useSync);
      });
    else
      // Don't generate a key pair. Use the existing keyName.
      return SyncPromise.resolve();
  })
  .then(function() {
    return thisManager.identityStorage.getDefaultCertificateNameForKeyPromise
      (keyName, useSync)
    .then(function(certName) {
      // The cert exists, so don't need to make it.
      return SyncPromise.resolve(certName);
    }, function(err) {
      if (!(err instanceof SecurityException))
        throw err;

      // The cert doesn't exist, so make one.
      var certName;
      return thisManager.selfSignPromise(keyName, useSync)
      .then(function(selfCert) {
        certName = selfCert.getName();
        return thisManager.addCertificateAsIdentityDefaultPromise(selfCert, useSync);
      })
      .then(function() {
        return SyncPromise.resolve(certName);
      });
    });
  });
};

/**
 * Create an identity by creating a pair of Key-Signing-Key (KSK) for this
 * identity and a self-signed certificate of the KSK. If a key pair or
 * certificate for the identity already exists, use it.
 * @param {Name} identityName The name of the identity.
 * @params {KeyParams} params The key parameters if a key needs to be generated
 * for the identity.
 * @param {function} onComplete (optional) This calls onComplete(certificateName)
 * with the name of the default certificate of the identity. If omitted, the
 * return value is described below. (Some crypto libraries only use a callback,
 * so onComplete is required to use these.)
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some crypto libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * @return {Name} If onComplete is omitted, return the name of the default
 * certificate of the identity. Otherwise, if onComplete is supplied then return
 * undefined and use onComplete as described above.
 */
IdentityManager.prototype.createIdentityAndCertificate = function
  (identityName, params, onComplete, onError)
{
  return SyncPromise.complete(onComplete, onError,
    this.createIdentityAndCertificatePromise(identityName, params, !onComplete));
};

/**
 * Create an identity by creating a pair of Key-Signing-Key (KSK) for this
 * identity and a self-signed certificate of the KSK. If a key pair or
 * certificate for the identity already exists, use it.
 * @deprecated Use createIdentityAndCertificate which returns the
 * certificate name instead of the key name. You can use
 * IdentityCertificate.certificateNameToPublicKeyName to convert the
 * certificate name to the key name.
 * @param {Name} identityName The name of the identity.
 * @params {KeyParams} params The key parameters if a key needs to be generated
 * for the identity.
 * @return {Name} The key name of the auto-generated KSK of the identity.
 */
IdentityManager.prototype.createIdentity = function(identityName, params)
{
  return IdentityCertificate.certificateNameToPublicKeyName
    (this.createIdentityAndCertificate(identityName, params));
};

/**
 * Delete the identity from the public and private key storage. If the
 * identity to be deleted is the current default system default, this will not
 * delete the identity and will return immediately.
 * @param {Name} identityName The name of the identity.
 * @param {function} onComplete (optional) This calls onComplete() when the
 * operation is complete. If omitted, do not use it. (Some database libraries
 * only use a callback, so onComplete is required to use these.)
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 */
IdentityManager.prototype.deleteIdentity = function
  (identityName, onComplete, onError)
{
  var useSync = !onComplete;
  var thisManager = this;

  var doDelete = true;

  var mainPromise = this.identityStorage.getDefaultIdentityPromise(useSync)
  .then(function(defaultIdentityName) {
    if (defaultIdentityName.equals(identityName))
      // Don't delete the default identity!
      doDelete = false;

    return SyncPromise.resolve();
  }, function(err) {
    // There is no default identity to check.
    return SyncPromise.resolve();
  })
  .then(function() {
    if (!doDelete)
      return SyncPromise.resolve();

    var keysToDelete = [];
    return thisManager.identityStorage.getAllKeyNamesOfIdentityPromise
      (identityName, keysToDelete, true)
    .then(function() {
      return thisManager.identityStorage.getAllKeyNamesOfIdentityPromise
        (identityName, keysToDelete, false);
    })
    .then(function() {
      return thisManager.identityStorage.deleteIdentityInfoPromise(identityName);
    })
    .then(function() {
      // Recursively loop through keysToDelete, calling deleteKeyPairPromise.
      function deleteKeyLoop(i) {
        if (i >= keysToDelete.length)
          return SyncPromise.resolve();

        return thisManager.privateKeyStorage.deleteKeyPairPromise(keysToDelete[i])
        .then(function() {
          return deleteKeyLoop(i + 1);
        });
      }

      return deleteKeyLoop(0);
    });
  });

  return SyncPromise.complete(onComplete, onError, mainPromise);
};

/**
 * Set the default identity.  If the identityName does not exist, then clear the
 * default identity so that getDefaultIdentity() throws an exception.
 * @param {Name} identityName The default identity name.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when the default
 * identity is set.
 */
IdentityManager.prototype.setDefaultIdentityPromise = function
  (identityName, useSync)
{
  return this.identityStorage.setDefaultIdentityPromise(identityName, useSync);
};

/**
 * Set the default identity.  If the identityName does not exist, then clear the
 * default identity so that getDefaultIdentity() throws an exception.
 * @param {Name} identityName The default identity name.
 * @param {function} onComplete (optional) This calls onComplete() when complete.
 * (Some database libraries only use a callback, so onComplete is required to
 * use these.)
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 */
IdentityManager.prototype.setDefaultIdentity = function
  (identityName, onComplete, onError)
{
  return SyncPromise.complete(onComplete, onError,
    this.identityStorage.setDefaultIdentityPromise(identityName, !onComplete));
};

/**
 * Get the default identity.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the Name of default
 * identity, or a promise rejected with SecurityException if the default
 * identity is not set.
 */
IdentityManager.prototype.getDefaultIdentityPromise = function(useSync)
{
  return this.identityStorage.getDefaultIdentityPromise(useSync);
};

/**
 * Get the default identity.
 * @param {function} onComplete (optional) This calls onComplete(identityName)
 * with name of the default identity. If omitted, the return value is described
 * below. (Some database libraries only use a callback, so onComplete is required
 * to use these.)
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * @return {Name} If onComplete is omitted, return the name of the default
 * identity. Otherwise, if onComplete is supplied then return undefined and use
 * onComplete as described above.
 * @throws SecurityException if the default identity is not set. However, if
 * onComplete and onError are defined, then if there is an exception return
 * undefined and call onError(exception).
 */
IdentityManager.prototype.getDefaultIdentity = function(onComplete, onError)
{
  return SyncPromise.complete(onComplete, onError,
    this.identityStorage.getDefaultIdentityPromise(!onComplete));
};

/**
 * Get the certificate of the default identity.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the requested
 * IdentityCertificate or null if not found.
 */
IdentityManager.prototype.getDefaultCertificatePromise = function(useSync)
{
  return this.identityStorage.getDefaultCertificatePromise(useSync);
};

/**
 * Generate a pair of RSA keys for the specified identity.
 * @param {Name} identityName The name of the identity.
 * @param {boolean} isKsk True for generating a Key-Signing-Key (KSK), false for
 * a Data-Signing-Key (DSK).
 * @param {number} keySize The size of the key.
 * @return {Name} The generated key name.
 */
IdentityManager.prototype.generateRSAKeyPair = function
  (identityName, isKsk, keySize)
{
  // For now, require sync. This method may be removed from the API.
  return SyncPromise.getValue
    (this.generateKeyPairPromise
     (identityName, isKsk, new RsaKeyParams(keySize), true));
};

/**
 * Set a key as the default key of an identity. The identity name is inferred
 * from keyName.
 * @param {Name} keyName The name of the key.
 * @param {Name} identityNameCheck (optional) The identity name to check that the
 * keyName contains the same identity name. If an empty name, it is ignored.
 * @param {function} onComplete (optional) This calls onComplete() when complete.
 * (Some database libraries only use a callback, so onComplete is required to
 * use these.)
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 */
IdentityManager.prototype.setDefaultKeyForIdentity = function
  (keyName, identityNameCheck, onComplete, onError)
{
  onError = (typeof identityNameCheck === "function") ? onComplete : onError;
  onComplete = (typeof identityNameCheck === "function") ?
    identityNameCheck : onComplete;
  identityNameCheck = (typeof identityNameCheck === "function" || !identityNameCheck) ?
    new Name() : identityNameCheck;

  return SyncPromise.complete(onComplete, onError,
    this.identityStorage.setDefaultKeyNameForIdentityPromise
      (keyName, identityNameCheck, !onComplete));
};

/**
 * Get the default key for an identity.
 * @param {Name} identityName The name of the identity.
 * @param {function} onComplete (optional) This calls onComplete(keyName)
 * with name of the default key. If omitted, the return value is described
 * below. (Some database libraries only use a callback, so onComplete is required
 * to use these.)
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * @return {Name} If onComplete is omitted, return the default key name.
 * Otherwise, if onComplete is supplied then return undefined and use onComplete
 * as described above.
 * @throws SecurityException if the default key name for the identity is not set.
 * However, if onComplete and onError are defined, then if there is an exception
 * return undefined and call onError(exception).
 */
IdentityManager.prototype.getDefaultKeyNameForIdentity = function
  (identityName, onComplete, onError)
{
  return SyncPromise.complete(onComplete, onError,
    this.identityStorage.getDefaultKeyNameForIdentityPromise
      (identityName, !onComplete));
};

/**
 * Generate a pair of RSA keys for the specified identity and set it as default
 * key for the identity.
 * @param {Name} identityName The name of the identity.
 * @param {boolean} isKsk True for generating a Key-Signing-Key (KSK), false for
 * a Data-Signing-Key (DSK).
 * @param {number} keySize The size of the key.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If false, this may return a SyncPromise or an async
 * Promise.
 * @return {Promise|SyncPromise} A promise which returns the generated key name.
 */
IdentityManager.prototype.generateRSAKeyPairAsDefaultPromise = function
  (identityName, isKsk, keySize, useSync)
{
  var newKeyName;
  var thisManager = this;
  return this.generateKeyPairPromise(identityName, isKsk, new RsaKeyParams(keySize))
  .then(function(localKeyName) {
    newKeyName = localKeyName;

    return thisManager.identityStorage.setDefaultKeyNameForIdentityPromise
      (newKeyName);
  })
  .then(function() {
    return SyncPromise.resolve(newKeyName);
  });
};

/**
 * Generate a pair of RSA keys for the specified identity and set it as default
 * key for the identity.
 * @param {Name} identityName The name of the identity.
 * @param {boolean} isKsk True for generating a Key-Signing-Key (KSK), false for
 * a Data-Signing-Key (DSK).
 * @param {number} keySize The size of the key.
 * @return {Name} The generated key name.
 */
IdentityManager.prototype.generateRSAKeyPairAsDefault = function
  (identityName, isKsk, keySize)
{
  return SyncPromise.getValue
    (this.generateRSAKeyPairAsDefaultPromise(identityName, isKsk, keySize, true));
};

/**
 * Get the public key with the specified name.
 * @param {Name} keyName The name of the key.
 * @param {function} onComplete (optional) This calls onComplete(publicKey)
 * with PublicKey. If omitted, the return value is described below. (Some database
 * libraries only use a callback, so onComplete is required to use these.)
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * @return {PublicKey} If onComplete is omitted, return the public key.
 * Otherwise, if onComplete is supplied then return undefined and use onComplete
 * as described above.
 */
IdentityManager.prototype.getPublicKey = function(keyName, onComplete, onError)
{
  return SyncPromise.complete(onComplete, onError,
    this.identityStorage.getKeyPromise(keyName, !onComplete)
    .then(function(keyDer) {
      return SyncPromise.resolve(new PublicKey(keyDer));
    }));
};

// TODO: Add two versions of createIdentityCertificate.

/**
 * Prepare an unsigned identity certificate.
 * @param {Name} keyName The key name, e.g., `/{identity_name}/ksk-123456`.
 * @param {PublicKey} publicKey (optional) The public key to sign. If ommited,
 * use the keyName to get the public key from the identity storage.
 * @param {Name} signingIdentity The signing identity.
 * @param {number} notBefore See IdentityCertificate.
 * @param {number} notAfter See IdentityCertificate.
 * @param {Array<CertificateSubjectDescription>} subjectDescription A list of
 * CertificateSubjectDescription. See IdentityCertificate. If null or empty,
 * this adds a an ATTRIBUTE_NAME based on the keyName.
 * @param {Name} certPrefix (optional) The prefix before the `KEY` component. If
 * null or omitted, this infers the certificate name according to the relation
 * between the signingIdentity and the subject identity. If the signingIdentity
 * is a prefix of the subject identity, `KEY` will be inserted after the
 * signingIdentity, otherwise `KEY` is inserted after subject identity (i.e.,
 * before `ksk-...`).
 * @param {function} onComplete (optional) This calls onComplete(certificate)
 * with the unsigned IdentityCertificate, or null if the inputs are invalid. If
 * omitted, the return value is described below. (Some database libraries only
 * use a callback, so onComplete is required to use these.)
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * @return {IdentityCertificate} If onComplete is omitted, return the the
 * unsigned IdentityCertificate, or null if the inputs are invalid. Otherwise,
 * if onComplete is supplied then return undefined and use onComplete as
 * described above.
 */
IdentityManager.prototype.prepareUnsignedIdentityCertificate = function
  (keyName, publicKey, signingIdentity, notBefore, notAfter, subjectDescription,
   certPrefix, onComplete, onError)
{
  if (!(publicKey instanceof PublicKey)) {
    // The publicKey was omitted. Shift arguments.
    onError = onComplete;
    onComplete = certPrefix;
    certPrefix = subjectDescription;
    subjectDescription = notAfter;
    notAfter = notBefore;
    notBefore = signingIdentity;
    signingIdentity = publicKey;
    publicKey = null;
  }

  // certPrefix may be omitted or null, so check for it and the following args.
  var arg7 = certPrefix;
  var arg8 = onComplete;
  var arg9 = onError;
  if (arg7 instanceof Name)
    certPrefix = arg7;
  else
    certPrefix = null;

  if (typeof arg7 === 'function') {
    onComplete = arg7;
    onError = arg8;
  }
  else if (typeof arg8 === 'function') {
    onComplete = arg8;
    onError = arg9;
  }
  else {
    onComplete = null;
    onError = null;
  }

  var promise;
  if (publicKey == null)
    promise =  this.prepareUnsignedIdentityCertificatePromise
      (keyName, signingIdentity, notBefore, notAfter, subjectDescription,
       certPrefix, !onComplete);
  else
    promise =  this.prepareUnsignedIdentityCertificatePromise
      (keyName, publicKey, signingIdentity, notBefore, notAfter,
       subjectDescription, certPrefix, !onComplete);
  return SyncPromise.complete(onComplete, onError, promise);
};

/**
 * Prepare an unsigned identity certificate.
 * @param {Name} keyName The key name, e.g., `/{identity_name}/ksk-123456`.
 * @param {PublicKey} publicKey (optional) The public key to sign. If ommited,
 * use the keyName to get the public key from the identity storage.
 * @param {Name} signingIdentity The signing identity.
 * @param {number} notBefore See IdentityCertificate.
 * @param {number} notAfter See IdentityCertificate.
 * @param {Array<CertificateSubjectDescription>} subjectDescription A list of
 * CertificateSubjectDescription. See IdentityCertificate. If null or empty,
 * this adds a an ATTRIBUTE_NAME based on the keyName.
 * @param {Name} certPrefix (optional) The prefix before the `KEY` component. If
 * null or omitted, this infers the certificate name according to the relation
 * between the signingIdentity and the subject identity. If the signingIdentity
 * is a prefix of the subject identity, `KEY` will be inserted after the
 * signingIdentity, otherwise `KEY` is inserted after subject identity (i.e.,
 * before `ksk-...`).
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that returns the unsigned
 * IdentityCertificate, or that returns null if the inputs are invalid.
 */
IdentityManager.prototype.prepareUnsignedIdentityCertificatePromise = function
  (keyName, publicKey, signingIdentity, notBefore, notAfter, subjectDescription,
   certPrefix, useSync)
{
  if (!(publicKey instanceof PublicKey)) {
    // The publicKey was omitted. Shift arguments.
    useSync = certPrefix;
    certPrefix = subjectDescription;
    subjectDescription = notAfter;
    notAfter = notBefore;
    notBefore = signingIdentity;
    signingIdentity = publicKey;
    publicKey = null;
  }

  // certPrefix may be omitted or null, so check for it and the following arg.
  var arg7 = certPrefix;
  var arg8 = useSync;
  if (arg7 instanceof Name)
    certPrefix = arg7;
  else
    certPrefix = null;

  if (typeof arg7 === 'boolean')
    useSync = arg7;
  else if (typeof arg8 === 'boolean')
    useSync = arg8;
  else
    useSync = false;

  var promise;
  if (publicKey == null) {
    promise = this.identityStorage.getKeyPromise(keyName, useSync)
    .then(function(keyDer) {
      publicKey = new PublicKey(keyDer);
      return SyncPromise.resolve();
    });
  }
  else
    promise = SyncPromise.resolve();

  return promise
  .then(function() {
    return SyncPromise.resolve
      (IdentityManager.prepareUnsignedIdentityCertificateHelper_
       (keyName, publicKey, signingIdentity, notBefore, notAfter,
        subjectDescription, certPrefix));
  });
};

/**
 * A helper for prepareUnsignedIdentityCertificatePromise where the publicKey
 * is known.
 */
IdentityManager.prepareUnsignedIdentityCertificateHelper_ = function
  (keyName, publicKey, signingIdentity, notBefore, notAfter, subjectDescription,
   certPrefix)
{
  if (keyName.size() < 1)
    return null;

  var tempKeyIdPrefix = keyName.get(-1).toEscapedString();
  if (tempKeyIdPrefix.length < 4)
    return null;
  keyIdPrefix = tempKeyIdPrefix.substr(0, 4);
  if (keyIdPrefix != "ksk-" && keyIdPrefix != "dsk-")
    return null;

  var certificate = new IdentityCertificate();
  var certName = new Name();

  if (certPrefix == null) {
    // No certificate prefix hint, so infer the prefix.
    if (signingIdentity.match(keyName))
      certName.append(signingIdentity)
        .append("KEY")
        .append(keyName.getSubName(signingIdentity.size()))
        .append("ID-CERT")
        .appendVersion(new Date().getTime());
    else
      certName.append(keyName.getPrefix(-1))
        .append("KEY")
        .append(keyName.get(-1))
        .append("ID-CERT")
        .appendVersion(new Date().getTime());
  }
  else {
    // A cert prefix hint is supplied, so determine the cert name.
    if (certPrefix.match(keyName) && !certPrefix.equals(keyName))
      certName.append(certPrefix)
        .append("KEY")
        .append(keyName.getSubName(certPrefix.size()))
        .append("ID-CERT")
        .appendVersion(new Date().getTime());
    else
      return null;
  }

  certificate.setName(certName);
  certificate.setNotBefore(notBefore);
  certificate.setNotAfter(notAfter);
  certificate.setPublicKeyInfo(publicKey);

  if (subjectDescription == null || subjectDescription.length === 0)
    certificate.addSubjectDescription(new CertificateSubjectDescription
      ("2.5.4.41", keyName.getPrefix(-1).toUri()));
  else {
    for (var i = 0; i < subjectDescription.length; ++i)
      certificate.addSubjectDescription(subjectDescription[i]);
  }

  try {
    certificate.encode();
  } catch (ex) {
    throw SecurityException(new Error("DerEncodingException: " + ex));
  }

  return certificate;
};

/**
 * Add a certificate into the public key identity storage.
 * @param {IdentityCertificate} certificate The certificate to to added. This
 * makes a copy of the certificate.
 * @param {function} onComplete (optional) This calls onComplete() when complete.
 * (Some database libraries only use a callback, so onComplete is required to
 * use these.)
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 */
IdentityManager.prototype.addCertificate = function
  (certificate, onComplete, onError)
{
  return SyncPromise.complete(onComplete, onError,
    this.identityStorage.addCertificatePromise(certificate, !onComplete));
};

/**
 * Set the certificate as the default for its corresponding key.
 * @param {IdentityCertificate} certificate The certificate.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If false, this may return a SyncPromise or an async
 * Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when the default
 * certificate is set.
 */
IdentityManager.prototype.setDefaultCertificateForKeyPromise = function
  (certificate, useSync)
{
  var thisManager = this;

  var keyName = certificate.getPublicKeyName();
  return this.identityStorage.doesKeyExistPromise(keyName, useSync)
  .then(function(exists) {
    if (!exists)
      throw new SecurityException(new Error
        ("No corresponding Key record for certificate!"));

    return thisManager.identityStorage.setDefaultCertificateNameForKeyPromise
      (keyName, certificate.getName(), useSync);
  });
};

/**
 * Set the certificate as the default for its corresponding key.
 * @param {IdentityCertificate} certificate The certificate.
 * @param {function} onComplete (optional) This calls onComplete() when complete.
 * (Some database libraries only use a callback, so onComplete is required to
 * use these.)
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 */
IdentityManager.prototype.setDefaultCertificateForKey = function
  (certificate, onComplete, onError)
{
  return SyncPromise.complete(onComplete, onError,
    this.setDefaultCertificateForKeyPromise(certificate, !onComplete));
};

/**
 * Add a certificate into the public key identity storage and set the
 * certificate as the default for its corresponding identity.
 * @param {IdentityCertificate} certificate The certificate to be added. This
 * makes a copy of the certificate.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If false, this may return a SyncPromise or an async
 * Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when the certificate
 * is added.
 */
IdentityManager.prototype.addCertificateAsIdentityDefaultPromise = function
  (certificate, useSync)
{
  var thisManager = this;
  return this.identityStorage.addCertificatePromise(certificate, useSync)
  .then(function() {
    var keyName = certificate.getPublicKeyName();
    return thisManager.identityStorage.setDefaultKeyNameForIdentityPromise
      (keyName, useSync);
  })
  .then(function() {
    return thisManager.setDefaultCertificateForKeyPromise(certificate, useSync);
  });
};

/**
 * Add a certificate into the public key identity storage and set the
 * certificate as the default of its corresponding key.
 * @param {IdentityCertificate} certificate The certificate to be added. This
 * makes a copy of the certificate.
 * @param {function} onComplete (optional) This calls onComplete() when complete.
 * (Some database libraries only use a callback, so onComplete is required to use
 * these.)
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 */
IdentityManager.prototype.addCertificateAsDefault = function
  (certificate, onComplete, onError)
{
  var useSync = !onComplete;
  var thisManager = this;

  return SyncPromise.complete(onComplete, onError,
    this.identityStorage.addCertificatePromise(certificate, useSync)
    .then(function() {
      return thisManager.setDefaultCertificateForKeyPromise(certificate, useSync);
    }));
};

/**
 * Get a certificate which is still valid with the specified name.
 * @param {Name} certificateName The name of the requested certificate.
 * @param {function} onComplete (optional) This calls onComplete(certificate)
 * with the requested IdentityCertificate. If omitted, the return value is
 * described below. (Some database libraries only use a callback, so onComplete
 * is required to use these.)
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * @return {IdentityCertificate} If onComplete is omitted, return the requested
 * certificate. Otherwise, if onComplete is supplied then return undefined and
 * use onComplete as described above.
 */
IdentityManager.prototype.getCertificate = function
  (certificateName, onComplete, onError)
{
  return SyncPromise.complete(onComplete, onError,
    this.identityStorage.getCertificatePromise
      (certificateName, false, !onComplete));
};

/**
 * Get the default certificate name for the specified identity.
 * @param {Name} identityName The identity name.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the default certificate
 * Name, or a promise rejected with SecurityException if the default key name
 * for the identity is not set or the default certificate name for the key name
 * is not set.
 */
IdentityManager.prototype.getDefaultCertificateNameForIdentityPromise = function
  (identityName, useSync)
{
  return this.identityStorage.getDefaultCertificateNameForIdentityPromise
    (identityName, useSync);
}

/**
 * Get the default certificate name for the specified identity, which will be
 * used when signing is performed based on identity.
 * @param {Name} identityName The name of the specified identity.
 * @param {function} onComplete (optional) This calls onComplete(certificateName)
 * with name of the default certificate. If omitted, the return value is described
 * below. (Some database libraries only use a callback, so onComplete is required
 * to use these.)
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * @return {Name} If onComplete is omitted, return the default certificate name.
 * Otherwise, if onComplete is supplied then return undefined and use
 * onComplete as described above.
 * @throws SecurityException if the default key name for the identity is not
 * set or the default certificate name for the key name is not set. However, if
 * onComplete and onError are defined, then if there is an exception return
 * undefined and call onError(exception).
 */
IdentityManager.prototype.getDefaultCertificateNameForIdentity = function
  (identityName, onComplete, onError)
{
  return SyncPromise.complete(onComplete, onError,
    this.identityStorage.getDefaultCertificateNameForIdentityPromise
      (identityName, !onComplete));
};

/**
 * Get the default certificate name of the default identity, which will be used
 * when signing is based on identity and the identity is not specified.
 * @param {function} onComplete (optional) This calls onComplete(certificateName)
 * with name of the default certificate. If omitted, the return value is described
 * below. (Some database libraries only use a callback, so onComplete is required
 * to use these.)
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * @return {Name} If onComplete is omitted, return the default certificate name.
 * Otherwise, if onComplete is supplied then return undefined and use
 * onComplete as described above.
 * @throws SecurityException if the default identity is not set or the default
 * key name for the identity is not set or the default certificate name for
 * the key name is not set. However, if onComplete and onError are defined, then
 * if there is an exception return undefined and call onError(exception).
 */
IdentityManager.prototype.getDefaultCertificateName = function
  (onComplete, onError)
{
  var useSync = !onComplete;
  var thisManager = this;

  return SyncPromise.complete(onComplete, onError,
    this.identityStorage.getDefaultIdentityPromise(useSync)
    .then(function(identityName) {
      return thisManager.identityStorage.getDefaultCertificateNameForIdentityPromise
        (identityName, useSync);
    }));
};

/**
 * Append all the identity names to the nameList.
 * @param {Array<Name>} nameList Append result names to nameList.
 * @param {boolean} isDefault If true, add only the default identity name. If
 * false, add only the non-default identity names.
 * @param {function} onComplete (optional) This calls onComplete() when finished
 * adding to nameList. If omitted, this returns when complete. (Some database
 * libraries only use a callback, so onComplete is required to use these.)
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * @return {void} If onComplete is omitted, return when complete. Otherwise, if
 * onComplete is supplied then return undefined and use onComplete as described
 * above.
 */
IdentityManager.prototype.getAllIdentities = function
  (nameList, isDefault, onComplete, onError)
{
  return SyncPromise.complete(onComplete, onError,
    this.identityStorage.getAllIdentitiesPromise
      (nameList, isDefault, !onComplete));
};

/**
 * Append all the key names of a particular identity to the nameList.
 * @param {Name} identityName The identity name to search for.
 * @param {Array<Name>} nameList Append result names to nameList.
 * @param {boolean} isDefault If true, add only the default key name. If false,
 * add only the non-default key names.
 * @param {function} onComplete (optional) This calls onComplete() when finished
 * adding to nameList. If omitted, this returns when complete. (Some database
 * libraries only use a callback, so onComplete is required to use these.)
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * @return {void} If onComplete is omitted, return when complete. Otherwise, if
 * onComplete is supplied then return undefined and use onComplete as described
 * above.
 */
IdentityManager.prototype.getAllKeyNamesOfIdentity = function
  (identityName, nameList, isDefault, onComplete, onError)
{
  return SyncPromise.complete(onComplete, onError,
    this.identityStorage.getAllKeyNamesOfIdentityPromise
      (identityName, nameList, isDefault, !onComplete));
};

/**
 * Append all the certificate names of a particular key name to the nameList.
 * @param {Name} keyName The key name to search for.
 * @param {Array<Name>} nameList Append result names to nameList.
 * @param {boolean} isDefault If true, add only the default certificate name. If
 * false, add only the non-default certificate names.
 * @param {function} onComplete (optional) This calls onComplete() when finished
 * adding to nameList. If omitted, this returns when complete. (Some database
 * libraries only use a callback, so onComplete is required to use these.)
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * @return {void} If onComplete is omitted, return when complete. Otherwise, if
 * onComplete is supplied then return undefined and use onComplete as described
 * above.
 */
IdentityManager.prototype.getAllCertificateNamesOfKey = function
  (keyName, nameList, isDefault, onComplete, onError)
{
  return SyncPromise.complete(onComplete, onError,
    this.identityStorage.getAllCertificateNamesOfKeyPromise
      (keyName, nameList, isDefault, !onComplete));
};

/**
 * Sign the Data packet or byte array data based on the certificate name.
 * @param {Data|Buffer} target If this is a Data object, wire encode for signing,
 * update its signature and key locator field and wireEncoding. If it is a
 * Buffer, sign it to produce a Signature object.
 * @param {Name} certificateName The Name identifying the certificate which
 * identifies the signing key.
 * @param {WireFormat} (optional) The WireFormat for calling encodeData, or
 * WireFormat.getDefaultWireFormat() if omitted.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that returns the generated Signature
 * object (if target is a Buffer) or the target (if target is Data).
 */
IdentityManager.prototype.signByCertificatePromise = function
  (target, certificateName, wireFormat, useSync)
{
  useSync = (typeof wireFormat === "boolean") ? wireFormat : useSync;
  wireFormat = (typeof wireFormat === "boolean" || !wireFormat) ? WireFormat.getDefaultWireFormat() : wireFormat;

  var keyName = IdentityManager.certificateNameToPublicKeyName(certificateName);

  var thisManager = this;
  if (target instanceof Data) {
    var data = target;
    var digestAlgorithm = [0];

    return this.makeSignatureByCertificatePromise
      (certificateName, digestAlgorithm, useSync)
    .then(function(signature) {
      data.setSignature(signature);
      // Encode once to get the signed portion.
      var encoding = data.wireEncode(wireFormat);

      return thisManager.privateKeyStorage.signPromise
        (encoding.signedBuf(), keyName, digestAlgorithm[0], useSync);
    })
    .then(function(signatureValue) {
      data.getSignature().setSignature(signatureValue);
      // Encode again to include the signature.
      data.wireEncode(wireFormat);

      return SyncPromise.resolve(data);
    });
  }
  else {
    var digestAlgorithm = [0];
    return this.makeSignatureByCertificatePromise
      (certificateName, digestAlgorithm, useSync)
    .then(function(signature) {
      return thisManager.privateKeyStorage.signPromise
        (target, keyName, digestAlgorithm[0], useSync);
    })
    .then(function (signatureValue) {
      signature.setSignature(signatureValue);
      return SyncPromise.resolve(signature);
    });
  }
};

/**
 * Sign the Data packet or byte array data based on the certificate name.
 * @param {Data|Buffer} target If this is a Data object, wire encode for signing,
 * update its signature and key locator field and wireEncoding. If it is a
 * Buffer, sign it to produce a Signature object.
 * @param {Name} certificateName The Name identifying the certificate which
 * identifies the signing key.
 * @param {WireFormat} (optional) The WireFormat for calling encodeData, or
 * WireFormat.getDefaultWireFormat() if omitted.
 * @param {function} onComplete (optional) If target is a Data object, this calls
 * onComplete(data) with the supplied Data object which has been modified to set
 * its signature. If target is a Buffer, this calls onComplete(signature) where
 * signature is the produced Signature object. If omitted, the return value is
 * described below. (Some crypto libraries only use a callback, so onComplete is
 * required to use these.)
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some crypto libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * @return {Signature} If onComplete is omitted, return the generated Signature
 * object (if target is a Buffer) or the target (if target is Data). Otherwise,
 * if onComplete is supplied then return undefined and use onComplete as described
 * above.
 */
IdentityManager.prototype.signByCertificate = function
  (target, certificateName, wireFormat, onComplete, onError)
{
  onError = (typeof wireFormat === "function") ? onComplete : onError;
  onComplete = (typeof wireFormat === "function") ? wireFormat : onComplete;
  wireFormat = (typeof wireFormat === "function" || !wireFormat) ? WireFormat.getDefaultWireFormat() : wireFormat;

  return SyncPromise.complete(onComplete, onError,
    this.signByCertificatePromise
      (target, certificateName, wireFormat, !onComplete));
};

/**
 * Append a SignatureInfo to the Interest name, sign the name components and
 * append a final name component with the signature bits.
 * @param {Interest} interest The Interest object to be signed. This appends
 * name components of SignatureInfo and the signature bits.
 * @param {Name} certificateName The certificate name of the key to use for
 * signing.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * the input. If omitted, use WireFormat getDefaultWireFormat().
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that returns the supplied Interest.
 */
IdentityManager.prototype.signInterestByCertificatePromise = function
  (interest, certificateName, wireFormat, useSync)
{
  useSync = (typeof wireFormat === "boolean") ? wireFormat : useSync;
  wireFormat = (typeof wireFormat === "boolean" || !wireFormat) ? WireFormat.getDefaultWireFormat() : wireFormat;

  var thisManager = this;
  var signature;
  var digestAlgorithm = [0];
  return this.makeSignatureByCertificatePromise
      (certificateName, digestAlgorithm, useSync)
  .then(function(localSignature) {
    signature = localSignature;
    // Append the encoded SignatureInfo.
    interest.getName().append(wireFormat.encodeSignatureInfo(signature));

    // Append an empty signature so that the "signedPortion" is correct.
    interest.getName().append(new Name.Component());
    // Encode once to get the signed portion.
    var encoding = interest.wireEncode(wireFormat);
    var keyName = IdentityManager.certificateNameToPublicKeyName
      (certificateName);

    return thisManager.privateKeyStorage.signPromise
      (encoding.signedBuf(), keyName, digestAlgorithm[0], useSync);
  })
  .then(function(signatureValue) {
    signature.setSignature(signatureValue);

    // Remove the empty signature and append the real one.
    interest.setName(interest.getName().getPrefix(-1).append
      (wireFormat.encodeSignatureValue(signature)));
    return SyncPromise.resolve(interest);
  });
};

/**
 * Append a SignatureInfo to the Interest name, sign the name components and
 * append a final name component with the signature bits.
 * @param {Interest} interest The Interest object to be signed. This appends
 * name components of SignatureInfo and the signature bits.
 * @param {Name} certificateName The certificate name of the key to use for
 * signing.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * the input. If omitted, use WireFormat getDefaultWireFormat().
 * @param {function} onComplete (optional) This calls onComplete(interest) with
 * the supplied Interest object which has been modified to set its signature. If
 * omitted, then return when the interest has been signed. (Some crypto
 * libraries only use a callback, so onComplete is required to use these.)
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some crypto libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * @return {Signature} If onComplete is omitted, return the interest. Otherwise,
 * if onComplete is supplied then return undefined and use onComplete as
 * described above.
 */
IdentityManager.prototype.signInterestByCertificate = function
  (interest, certificateName, wireFormat, onComplete, onError)
{
  onError = (typeof wireFormat === "function") ? onComplete : onError;
  onComplete = (typeof wireFormat === "function") ? wireFormat : onComplete;
  wireFormat = (typeof wireFormat === "function" || !wireFormat) ? WireFormat.getDefaultWireFormat() : wireFormat;

  return SyncPromise.complete(onComplete, onError,
    this.signInterestByCertificatePromise
      (interest, certificateName, wireFormat, !onComplete));
};

/**
 * Wire encode the Data object, digest it and set its SignatureInfo to a
 * DigestSha256.
 * @param {Data} data The Data object to be signed. This updates its signature
 * and wireEncoding.
 * @param {WireFormat} (optional) The WireFormat for calling encodeData, or
 * WireFormat.getDefaultWireFormat() if omitted.
 */
IdentityManager.prototype.signWithSha256 = function(data, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());

  data.setSignature(new DigestSha256Signature());
  // Encode once to get the signed portion.
  var encoding = data.wireEncode(wireFormat);

  // Digest and set the signature.
  var hash = Crypto.createHash('sha256');
  hash.update(encoding.signedBuf());
  data.getSignature().setSignature(new Blob(hash.digest(), false));

  // Encode again to include the signature.
  data.wireEncode(wireFormat);
};

/**
 * Append a SignatureInfo for DigestSha256 to the Interest name, digest the
   * name components and append a final name component with the signature bits
   * (which is the digest).
 * @param {Interest} interest The Interest object to be signed. This appends
 * name components of SignatureInfo and the signature bits.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * the input. If omitted, use WireFormat getDefaultWireFormat().
 */
IdentityManager.prototype.signInterestWithSha256 = function(interest, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());

  var signature = new DigestSha256Signature();

  // Append the encoded SignatureInfo.
  interest.getName().append(wireFormat.encodeSignatureInfo(signature));

  // Append an empty signature so that the "signedPortion" is correct.
  interest.getName().append(new Name.Component());
  // Encode once to get the signed portion.
  var encoding = interest.wireEncode(wireFormat);

  // Digest and set the signature.
  var hash = Crypto.createHash('sha256');
  hash.update(encoding.signedBuf());
  signature.setSignature(new Blob(hash.digest(), false));

  // Remove the empty signature and append the real one.
  interest.setName(interest.getName().getPrefix(-1).append
    (wireFormat.encodeSignatureValue(signature)));
};

/**
 * Generate a self-signed certificate for a public key.
 * @param {Name} keyName The name of the public key.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If false, this may return a SyncPromise or an async
 * Promise.
 * @return {Promise|SyncPromise} A promise which returns the generated
 * IdentityCertificate.
 */
IdentityManager.prototype.selfSignPromise = function(keyName, useSync)
{
  var certificate = new IdentityCertificate();

  var thisManager = this;
  return this.identityStorage.getKeyPromise(keyName, useSync)
  .then(function(keyBlob) {
    var publicKey = new PublicKey(keyBlob);

    var notBefore = new Date().getTime();
    var notAfter = notBefore + 2 * 365 * 24 * 3600 * 1000; // about 2 years

    certificate.setNotBefore(notBefore);
    certificate.setNotAfter(notAfter);

    var certificateName = keyName.getPrefix(-1).append("KEY").append
      (keyName.get(-1)).append("ID-CERT").appendVersion(certificate.getNotBefore());
    certificate.setName(certificateName);

    certificate.setPublicKeyInfo(publicKey);
    certificate.addSubjectDescription(new CertificateSubjectDescription
      ("2.5.4.41", keyName.toUri()));
    certificate.encode();

    return thisManager.signByCertificatePromise
      (certificate, certificate.getName(), useSync);
  })
};

/**
 * Generate a self-signed certificate for a public key.
 * @param {Name} keyName The name of the public key.
 * @param {function} onComplete (optional) This calls onComplete(certificate)
 * with the the generated IdentityCertificate. If omitted, the return value is
 * described below. (Some crypto libraries only use a callback, so onComplete is
 * required to use these.)
 * @return {IdentityCertificate} If onComplete is omitted, return the
 * generated certificate. Otherwise, if onComplete is supplied then return
 * undefined and use onComplete as described above.
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some crypto libraries only use a
 * callback, so onError is required to be notified of an exception.)
 */
IdentityManager.prototype.selfSign = function(keyName, onComplete, onError)
{
  return SyncPromise.complete(onComplete, onError,
    this.selfSignPromise(keyName, !onComplete));
};

/**
 * Get the public key name from the full certificate name.
 *
 * @param {Name} certificateName The full certificate name.
 * @return {Name} The related public key name.
 * TODO: Move this to IdentityCertificate
 */
IdentityManager.certificateNameToPublicKeyName = function(certificateName)
{
  var i = certificateName.size() - 1;
  var idString = "ID-CERT";
  while (i >= 0) {
    if (certificateName.get(i).toEscapedString() == idString)
      break;
    --i;
  }

  var tmpName = certificateName.getSubName(0, i);
  var keyString = "KEY";
  i = 0;
  while (i < tmpName.size()) {
    if (tmpName.get(i).toEscapedString() == keyString)
      break;
    ++i;
  }

  return tmpName.getSubName(0, i).append(tmpName.getSubName
    (i + 1, tmpName.size() - i - 1));
};

/**
 * Return a new Signature object based on the signature algorithm of the public
 * key with keyName (derived from certificateName).
 * @param {Name} certificateName The certificate name.
 * @param {Array} digestAlgorithm Set digestAlgorithm[0] to the signature
 * algorithm's digest algorithm, e.g. DigestAlgorithm.SHA256.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If false, this may return a SyncPromise or an async
 * Promise.
 * @return {Promise|SyncPromise} A promise which returns a new object of the
 * correct subclass of Signature.
 */
IdentityManager.prototype.makeSignatureByCertificatePromise = function
  (certificateName, digestAlgorithm, useSync)
{
  var keyName = IdentityManager.certificateNameToPublicKeyName(certificateName);
  return this.privateKeyStorage.getPublicKeyPromise(keyName, useSync)
  .then(function(publicKey) {
    var keyType = publicKey.getKeyType();

    var signature = null;
    if (keyType == KeyType.RSA) {
      signature = new Sha256WithRsaSignature();
      digestAlgorithm[0] = DigestAlgorithm.SHA256;

      signature.getKeyLocator().setType(KeyLocatorType.KEYNAME);
      signature.getKeyLocator().setKeyName(certificateName.getPrefix(-1));
    }
    else if (keyType == KeyType.EC) {
      signature = new Sha256WithEcdsaSignature();
      digestAlgorithm[0] = DigestAlgorithm.SHA256;

      signature.getKeyLocator().setType(KeyLocatorType.KEYNAME);
      signature.getKeyLocator().setKeyName(certificateName.getPrefix(-1));
    }
    else
      throw new SecurityException(new Error("Key type is not recognized"));

    return SyncPromise.resolve(signature);
  });
};

/**
 * A private method to generate a pair of keys for the specified identity.
 * @param {Name} identityName The name of the identity.
 * @param {boolean} isKsk true for generating a Key-Signing-Key (KSK), false for
 * a Data-Signing-Key (DSK).
 * @param {KeyParams} params The parameters of the key.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If false, this may return a SyncPromise or an async
 * Promise.
 * @return {Promise|SyncPromise} A promise which returns the generated key name.
 */
IdentityManager.prototype.generateKeyPairPromise = function
  (identityName, isKsk, params, useSync)
{
  var keyName;
  var thisManager = this;
  return this.identityStorage.getNewKeyNamePromise(identityName, isKsk, useSync)
  .then(function(localKeyName) {
    keyName = localKeyName;
    return thisManager.privateKeyStorage.generateKeyPairPromise
      (keyName, params, useSync);
  })
  .then(function() {
    return thisManager.privateKeyStorage.getPublicKeyPromise
      (keyName, useSync);
  })
  .then(function(publicKey) {
    return thisManager.identityStorage.addKeyPromise
      (keyName, params.getKeyType(), publicKey.getKeyDer());
  })
  .then(function() {
    return SyncPromise.resolve(keyName);
  });
};

/**
 * Get the IdentityStorage from the pib value in the configuration file if
 * supplied. Otherwise, get the default for this platform.
 * @param {ConfigFile} config The configuration file to check.
 * @param {function} initialCheckPromise This is passed to the
 * BasicIdentityStorage constructor. See it for details.
 * @return {IdentityStorage} A new IdentityStorage.
 */
IdentityManager.getDefaultIdentityStorage_ = function(config, initialCheckPromise)
{
  // Assume we are in Node.js.
  var pibLocator = config.get("pib", "");

  if (pibLocator !== "") {
    // Don't support non-default locations for now.
    if (pibLocator !== "pib-sqlite3")
      throw new SecurityException(new Error
        ("Invalid config file pib value: " + pibLocator));
  }

  return new BasicIdentityStorage(initialCheckPromise);
};

/**
 * Get the PrivateKeyStorage from the tpm value in the configuration file if
 * supplied. Otherwise, get the default for this platform.
 * @param {ConfigFile} config The configuration file to check.
 * @param {Array<string>} canonicalTpmLocator Set canonicalTpmLocator[0] to the
 * canonical value including the colon, * e.g. "tpm-file:".
 * @return A new PrivateKeyStorage.
 */
IdentityManager.getDefaultPrivateKeyStorage_ = function
  (config, canonicalTpmLocator)
{
  var tpmLocator = config.get("tpm", "");

  if (tpmLocator === "") {
    // Assume we are in Node.js, so check the system.
    if (process.platform === "darwin") {
      canonicalTpmLocator[0] = "tpm-osxkeychain:";
      throw new SecurityException(new Error
        ("IdentityManager: OS X key chain storage is not yet implemented. You must supply a privateKeyStorage."));
    }
    else {
      canonicalTpmLocator[0] = "tpm-file:";
      return new FilePrivateKeyStorage();
    }
  }
  else if (tpmLocator === "tpm-osxkeychain") {
    canonicalTpmLocator[0] = "tpm-osxkeychain:";
    throw new SecurityException(new Error
      ("IdentityManager: tpm-osxkeychain is not yet implemented."));
  }
  else if (tpmLocator === "tpm-file") {
    canonicalTpmLocator[0] = "tpm-file:";
    return new FilePrivateKeyStorage();
  }
  else
    throw new SecurityException(new Error
      ("Invalid config file tpm value: " + tpmLocator));
};

/**
 * Check that identityStorage.getTpmLocatorPromise() (if defined) matches the
 * canonicalTpmLocator. This has to be an async Promise because it calls async
 * getTpmLocatorPromise.
 * @param canonicalTpmLocator The canonical locator from
 * getDefaultPrivateKeyStorage().
 * @return {Promise} A promise which resolves if canonicalTpmLocator is OK, or a
 * promise rejected with SecurityException if the private key storage does not
 * match.
 */
IdentityManager.prototype.checkTpmPromise_ = function(canonicalTpmLocator)
{
  return this.identityStorage.getTpmLocatorPromise()
  .then(function(tpmLocator) {
    // Just check. If a PIB reset is required, expect ndn-cxx/NFD to do it.
    if (tpmLocator !== "" && tpmLocator !== canonicalTpmLocator)
      return Promise.reject(new SecurityException(new Error
        ("The TPM locator supplied does not match the TPM locator in the PIB: " +
         tpmLocator + " != " + canonicalTpmLocator)));
    else
      return Promise.resolve();
  }, function(err) {
    // The TPM locator is not set in the PIB yet.
    return Promise.resolve();
  });
};
