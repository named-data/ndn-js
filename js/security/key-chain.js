/**
 * Copyright (C) 2014-2016 Regents of the University of California.
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

/** @ignore */
var Crypto = require('../crypto.js'); /** @ignore */
var Name = require('../name.js').Name; /** @ignore */
var Interest = require('../interest.js').Interest; /** @ignore */
var Data = require('../data.js').Data; /** @ignore */
var Blob = require('../util/blob.js').Blob; /** @ignore */
var WireFormat = require('../encoding/wire-format.js').WireFormat; /** @ignore */
var SecurityException = require('./security-exception.js').SecurityException; /** @ignore */
var RsaKeyParams = require('./key-params.js').RsaKeyParams; /** @ignore */
var IdentityCertificate = require('./certificate/identity-certificate.js').IdentityCertificate; /** @ignore */
var SyncPromise = require('../util/sync-promise.js').SyncPromise; /** @ignore */
var NdnCommon = require('../util/ndn-common.js').NdnCommon; /** @ignore */
var IdentityManager = require('./identity/identity-manager.js').IdentityManager; /** @ignore */
var NoVerifyPolicyManager = require('./policy/no-verify-policy-manager.js').NoVerifyPolicyManager;

/**
 * A KeyChain provides a set of interfaces to the security library such as
 * identity management, policy configuration and packet signing and verification.
 * Note: This class is an experimental feature. See the API docs for more detail at
 * http://named-data.net/doc/ndn-ccl-api/key-chain.html .
 *
 * Create a new KeyChain with the identityManager and policyManager.
 * @param {IdentityManager} identityManager (optional) The identity manager as a
 * subclass of IdentityManager. If omitted, use the default IdentityManager
 * constructor.
 * @param {PolicyManager} policyManager (optional) The policy manager as a
 * subclass of PolicyManager. If omitted, use NoVerifyPolicyManager.
 * @throws SecurityException if this is not in Node.js and this uses the default
 * IdentityManager constructor. (See IdentityManager for details.)
 * @constructor
 */
var KeyChain = function KeyChain(identityManager, policyManager)
{
  if (!identityManager)
    identityManager = new IdentityManager();
  if (!policyManager)
    policyManager = new NoVerifyPolicyManager();

  this.identityManager = identityManager;
  this.policyManager = policyManager;
  this.face = null;
};

exports.KeyChain = KeyChain;

/*****************************************
 *          Identity Management          *
 *****************************************/

/**
 * Create an identity by creating a pair of Key-Signing-Key (KSK) for this
 * identity and a self-signed certificate of the KSK. If a key pair or
 * certificate for the identity already exists, use it.
 * @param {Name} identityName The name of the identity.
 * @param {KeyParams} params (optional) The key parameters if a key needs to be
 * generated for the identity. If omitted, use KeyChain.DEFAULT_KEY_PARAMS.
 * @param {function} onComplete (optional) This calls onComplete(certificateName)
 * with name of the default certificate of the identity. If omitted, the return
 * value is described below. (Some crypto libraries only use a callback, so
 * onComplete is required to use these.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @returns {Name} If onComplete is omitted, return the name of the default
 * certificate of the identity. Otherwise, if onComplete is supplied then return
 * undefined and use onComplete as described above.
 */
KeyChain.prototype.createIdentityAndCertificate = function
  (identityName, params, onComplete, onError)
{
  onError = (typeof params === "function") ? onComplete : onError;
  onComplete = (typeof params === "function") ? params : onComplete;
  params = (typeof params === "function" || !params) ?
    KeyChain.DEFAULT_KEY_PARAMS : params;

  return this.identityManager.createIdentityAndCertificate
    (identityName, params, onComplete, onError);
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
 * @param {KeyParams} params (optional) The key parameters if a key needs to be
 * generated for the identity. If omitted, use KeyChain.DEFAULT_KEY_PARAMS.
 * @returns {Name} The key name of the auto-generated KSK of the identity.
 */
KeyChain.prototype.createIdentity = function(identityName, params)
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
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 */
KeyChain.prototype.deleteIdentity = function
  (identityName, onComplete, onError)
{
  this.identityManager.deleteIdentity(identityName, onComplete, onError);
};

/**
 * Get the default identity.
 * @param {function} onComplete (optional) This calls onComplete(identityName)
 * with name of the default identity. If omitted, the return value is described
 * below. (Some crypto libraries only use a callback, so onComplete is required
 * to use these.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * @returns {Name} If onComplete is omitted, return the name of the default
 * identity. Otherwise, if onComplete is supplied then return undefined and use
 * onComplete as described above.
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @throws SecurityException if the default identity is not set. However, if
 * onComplete and onError are defined, then if there is an exception return
 * undefined and call onError(exception).
 */
KeyChain.prototype.getDefaultIdentity = function(onComplete, onError)
{
  return this.identityManager.getDefaultIdentity(onComplete, onError);
};

/**
 * Get the default certificate name of the default identity, which will be used
 * when signing is based on identity and the identity is not specified.
 * @param {function} onComplete (optional) This calls onComplete(certificateName)
 * with name of the default certificate. If omitted, the return value is described
 * below. (Some crypto libraries only use a callback, so onComplete is required
 * to use these.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @return {Name} If onComplete is omitted, return the default certificate name.
 * Otherwise, if onComplete is supplied then return undefined and use onComplete
 * as described above.
 * @throws SecurityException if the default identity is not set or the default
 * key name for the identity is not set or the default certificate name for
 * the key name is not set. However, if onComplete and onError are defined, then
 * if there is an exception return undefined and call onError(exception).
 */
KeyChain.prototype.getDefaultCertificateName = function(onComplete, onError)
{
  return this.identityManager.getDefaultCertificateName(onComplete, onError);
};

/**
 * Generate a pair of RSA keys for the specified identity.
 * @param {Name} identityName The name of the identity.
 * @param {boolean} isKsk (optional) true for generating a Key-Signing-Key (KSK),
 * false for a Data-Signing-Key (DSK). If omitted, generate a Data-Signing-Key.
 * @param {number} keySize (optional) The size of the key. If omitted, use a
 * default secure key size.
 * @returns {Name} The generated key name.
 */
KeyChain.prototype.generateRSAKeyPair = function(identityName, isKsk, keySize)
{
  keySize = (typeof isKsk === "boolean") ? isKsk : keySize;
  isKsk = (typeof isKsk === "boolean") ? isKsk : false;

  if (!keySize)
    keySize = 2048;

  return this.identityManager.generateRSAKeyPair(identityName, isKsk, keySize);
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
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 */
KeyChain.prototype.setDefaultKeyForIdentity = function
  (keyName, identityNameCheck, onComplete, onError)
{
  return this.identityManager.setDefaultKeyForIdentity
    (keyName, identityNameCheck, onComplete, onError);
};

/**
 * Generate a pair of RSA keys for the specified identity and set it as default
 * key for the identity.
 * @param {Name} identityName The name of the identity.
 * @param {boolean} isKsk (optional) true for generating a Key-Signing-Key (KSK),
 * false for a Data-Signing-Key (DSK). If omitted, generate a Data-Signing-Key.
 * @param {number} keySize (optional) The size of the key. If omitted, use a
 * default secure key size.
 * @returns {Name} The generated key name.
 */
KeyChain.prototype.generateRSAKeyPairAsDefault = function
  (identityName, isKsk, keySize)
{
  return this.identityManager.generateRSAKeyPairAsDefault
    (identityName, isKsk, keySize);
};

/**
 * Create a public key signing request.
 * @param {Name} keyName The name of the key.
 * @returns {Blob} The signing request data.
 */
KeyChain.prototype.createSigningRequest = function(keyName)
{
  return this.identityManager.getPublicKey(keyName).getKeyDer();
};

/**
 * Install an identity certificate into the public key identity storage.
 * @param {IdentityCertificate} certificate The certificate to to added.
 * @param {function} onComplete (optional) This calls onComplete() when complete.
 * (Some database libraries only use a callback, so onComplete is required to
 * use these.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 */
KeyChain.prototype.installIdentityCertificate = function
  (certificate, onComplete, onError)
{
  this.identityManager.addCertificate(certificate, onComplete, onError);
};

/**
 * Set the certificate as the default for its corresponding key.
 * @param {IdentityCertificate} certificate The certificate.
 * @param {function} onComplete (optional) This calls onComplete() when complete.
 * (Some database libraries only use a callback, so onComplete is required to
 * use these.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 */
KeyChain.prototype.setDefaultCertificateForKey = function
  (certificate, onComplete, onError)
{
  this.identityManager.setDefaultCertificateForKey
    (certificate, onComplete, onError);
};

/**
 * Get a certificate which is still valid with the specified name.
 * @param {Name} certificateName The name of the requested certificate.
 * @param {function} onComplete (optional) This calls onComplete(certificate)
 * with the requested IdentityCertificate. If omitted, the return value is 
 * described below. (Some crypto libraries only use a callback, so onComplete is
 * required to use these.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @return {IdentityCertificate} If onComplete is omitted, return the requested
 * certificate. Otherwise, if onComplete is supplied then return undefined and
 * use onComplete as described above.
 */
KeyChain.prototype.getCertificate = function
  (certificateName, onComplete, onError)
{
  return this.identityManager.getCertificate
    (certificateName, onComplete, onError);
};

/**
 * @deprecated Use getCertificate.
 */
KeyChain.prototype.getIdentityCertificate = function
  (certificateName, onComplete, onError)
{
  return this.identityManager.getCertificate
    (certificateName, onComplete, onError);
};

/**
 * Revoke a key.
 * @param {Name} keyName The name of the key that will be revoked.
 */
KeyChain.prototype.revokeKey = function(keyName)
{
  //TODO: Implement
};

/**
 * Revoke a certificate.
 * @param {Name} certificateName The name of the certificate that will be
 * revoked.
 */
KeyChain.prototype.revokeCertificate = function(certificateName)
{
  //TODO: Implement
};

/**
 * Get the identity manager given to or created by the constructor.
 * @returns {IdentityManager} The identity manager.
 */
KeyChain.prototype.getIdentityManager = function()
{
  return this.identityManager;
};

/*****************************************
 *           Policy Management           *
 *****************************************/

/**
 * Get the policy manager given to or created by the constructor.
 * @returns {PolicyManager} The policy manager.
 */
KeyChain.prototype.getPolicyManager = function()
{
  return this.policyManager;
};

/*****************************************
 *              Sign/Verify              *
 *****************************************/

/**
 * Sign the target. If it is a Data or Interest object, set its signature. If it
 * is an array, produce a Signature object. There are two forms of sign:
 * sign(target, certificateName [, wireFormat] [, onComplete] [, onError]).
 * sign(target [, wireFormat] [, onComplete] [, onError]).
 * @param {Data|Interest|Buffer} target If this is a Data object, wire encode for
 * signing, update its signature and key locator field and wireEncoding. If this
 * is an Interest object, wire encode for signing, append a SignatureInfo to the
 * Interest name, sign the name components and append a final name component
 * with the signature bits. If it is an array, sign it and produce a Signature
 * object.
 * @param {Name} certificateName (optional) The certificate name of the key to
 * use for signing. If omitted, use the default identity in the identity storage.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * the input. If omitted, use WireFormat getDefaultWireFormat().
 * @param {function} onComplete (optional) If target is a Data object, this calls
 * onComplete(data) with the supplied Data object which has been modified to set
 * its signature. If target is an Interest object, this calls
 * onComplete(interest) with the supplied Interest object which has been
 * modified to set its signature. If target is a Buffer, this calls
 * onComplete(signature) where signature is the produced Signature object. If
 * omitted, the return value is described below. (Some crypto libraries only use
 * a callback, so onComplete is required to use these.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @returns {Signature} If onComplete is omitted, return the generated Signature
 * object (if target is a Buffer) or the target (if target is Data or Interest).
 * Otherwise, if onComplete is supplied then return undefined and use onComplete as
 * described above.
 */
KeyChain.prototype.sign = function
  (target, certificateName, wireFormat, onComplete, onError)
{
  var arg2 = certificateName;
  var arg3 = wireFormat;
  var arg4 = onComplete;
  var arg5 = onError;
  // arg2,            arg3,       arg4,       arg5
  // certificateName, wireFormat, onComplete, onError
  // certificateName, wireFormat, null,       null
  // certificateName, onComplete, onError,    null
  // certificateName, null,       null,       null
  // wireFormat,      onComplete, onError,    null
  // wireFormat,      null,       null,       null
  // onComplete,      onError,    null,       null
  // null,            null,       null,       null
  if (arg2 instanceof Name)
    certificateName = arg2;
  else
    certificateName = null;

  if (arg2 instanceof WireFormat)
    wireFormat = arg2;
  else if (arg3 instanceof WireFormat)
    wireFormat = arg3;
  else
    wireFormat = null;

  if (typeof arg2 === "function") {
    onComplete = arg2;
    onError = arg3;
  }
  else if (typeof arg3 === "function") {
    onComplete = arg3;
    onError = arg4;
  }
  else if (typeof arg4 === "function") {
    onComplete = arg4;
    onError = arg5;
  }
  else {
    onComplete = null;
    onError = null;
  }

  return SyncPromise.complete(onComplete, onError,
    this.signPromise(target, certificateName, wireFormat, !onComplete));
};

/**
 * Sign the target. If it is a Data or Interest object, set its signature. If it
 * is an array, produce a Signature object. There are two forms of signPromise:
 * signPromise(target, certificateName [, wireFormat] [, useSync]).
 * sign(target [, wireFormat] [, useSync]).
 * @param {Data|Interest|Buffer} target If this is a Data object, wire encode for
 * signing, update its signature and key locator field and wireEncoding. If this
 * is an Interest object, wire encode for signing, append a SignatureInfo to the
 * Interest name, sign the name components and append a final name component
 * with the signature bits. If it is an array, sign it and produce a Signature
 * object.
 * @param {Name} certificateName (optional) The certificate name of the key to
 * use for signing. If omitted, use the default identity in the identity storage.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * the input. If omitted, use WireFormat getDefaultWireFormat().
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that returns the generated Signature
 * object (if target is a Buffer) or the target (if target is Data or Interest).
 */
KeyChain.prototype.signPromise = function
  (target, certificateName, wireFormat, useSync)
{
  var arg2 = certificateName;
  var arg3 = wireFormat;
  var arg4 = useSync;
  // arg2,            arg3,       arg4
  // certificateName, wireFormat, useSync
  // certificateName, wireFormat, null
  // certificateName, useSync,    null
  // certificateName, null,       null
  // wireFormat,      useSync,    null
  // wireFormat,      null,       null
  // useSync,         null,       null
  // null,            null,       null
  if (arg2 instanceof Name)
    certificateName = arg2;
  else
    certificateName = null;

  if (arg2 instanceof WireFormat)
    wireFormat = arg2;
  else if (arg3 instanceof WireFormat)
    wireFormat = arg3;
  else
    wireFormat = null;

  if (typeof arg2 === 'boolean')
    useSync = arg2;
  else if (typeof arg3 === 'boolean')
    useSync = arg3;
  else if (typeof arg4 === 'boolean')
    useSync = arg4;
  else
    useSync = false;

  var thisKeyChain = this;
  return SyncPromise.resolve()
  .then(function() {
    if (certificateName != null)
      return SyncPromise.resolve();

    // Get the default certificate name.
    return thisKeyChain.identityManager.getDefaultCertificatePromise(useSync)
    .then(function(signingCertificate) {
      if (signingCertificate != null) {
        certificateName = signingCertificate.getName();
        return SyncPromise.resolve();
      }

      // Set the default certificate and default certificate name again.
      return thisKeyChain.prepareDefaultCertificateNamePromise_(useSync)
      .then(function(localCertificateName) {
        certificateName =localCertificateName;
        return SyncPromise.resolve();
      });
    });
  })
  .then(function() {
    // certificateName is now set. Do the actual signing.
    if (target instanceof Interest)
      return thisKeyChain.identityManager.signInterestByCertificatePromise
        (target, certificateName, wireFormat, useSync);
    else if (target instanceof Data)
      return thisKeyChain.identityManager.signByCertificatePromise
        (target, certificateName, wireFormat, useSync);
    else
      return thisKeyChain.identityManager.signByCertificatePromise
        (target, certificateName, useSync);
  });
};

/**
 * Sign the target. If it is a Data object, set its signature. If it is an
 * array, produce a signature object.
 * @param {Data|Buffer} target If this is a Data object, wire encode for
 * signing, update its signature and key locator field and wireEncoding. If it
 * is an array, sign it and return a Signature object.
 * @param {Name} identityName (optional) The identity name for the key to use for
 * signing.  If omitted, infer the signing identity from the data packet name.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * the input. If omitted, use WireFormat getDefaultWireFormat().
 * @param {function} onComplete (optional) If target is a Data object, this calls
 * onComplete(data) with the supplied Data object which has been modified to set
 * its signature. If target is a Buffer, this calls
 * onComplete(signature) where signature is the produced Signature object. If
 * omitted, the return value is described below. (Some crypto libraries only use
 * a callback, so onComplete is required to use these.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @returns {Signature} If onComplete is omitted, return the generated Signature
 * object (if target is a Buffer) or undefined (if target is Data).
 * Otherwise, if onComplete is supplied then return undefined and use onComplete
 * as described above.
 */
KeyChain.prototype.signByIdentity = function
  (target, identityName, wireFormat, onComplete, onError)
{
  onError = (typeof wireFormat === "function") ? onComplete : onError;
  onComplete = (typeof wireFormat === "function") ? wireFormat : onComplete;
  wireFormat = (typeof wireFormat === "function" || !wireFormat) ? WireFormat.getDefaultWireFormat() : wireFormat;

  var useSync = !onComplete;
  var thisKeyChain = this;

  if (identityName == null)
    identityName = new Name();

  if (target instanceof Data) {
    var data = target;

    var mainPromise = SyncPromise.resolve()
    .then(function() {
      if (identityName.size() == 0) {
        var inferredIdentity = thisKeyChain.policyManager.inferSigningIdentity
          (data.getName());
        if (inferredIdentity.size() == 0)
          return thisKeyChain.identityManager.getDefaultCertificateNamePromise
            (useSync);
        else
          return thisKeyChain.identityManager.getDefaultCertificateNameForIdentityPromise
              (inferredIdentity, useSync);
      }
      else
        return thisKeyChain.identityManager.getDefaultCertificateNameForIdentityPromise
          (identityName, useSync);
    })
    .then(function(signingCertificateName) {
      if (signingCertificateName.size() == 0)
        throw new SecurityException(new Error
          ("No qualified certificate name found!"));

      if (!thisKeyChain.policyManager.checkSigningPolicy
           (data.getName(), signingCertificateName))
        throw new SecurityException(new Error
          ("Signing Cert name does not comply with signing policy"));

      return thisKeyChain.identityManager.signByCertificatePromise
        (data, signingCertificateName, wireFormat, useSync);
    });

    return SyncPromise.complete(onComplete, onError, mainPromise);
  }
  else {
    var array = target;

    return SyncPromise.complete(onComplete, onError,
      this.identityManager.getDefaultCertificateNameForIdentityPromise
        (identityName, useSync)
      .then(function(signingCertificateName) {
        if (signingCertificateName.size() == 0)
          throw new SecurityException(new Error
            ("No qualified certificate name found!"));

        return thisKeyChain.identityManager.signByCertificatePromise
          (array, signingCertificateName, wireFormat, useSync);
      }));
  }
};

/**
 * Sign the target using DigestSha256.
 * @param {Data|Interest} target If this is a Data object, wire encode for
 * signing, digest it and set its SignatureInfo to a DigestSha256, updating its
 * signature and wireEncoding. If this is an Interest object, wire encode for
 * signing, append a SignatureInfo for DigestSha256 to the Interest name, digest
 * the name components and append a final name component with the signature bits.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * the input. If omitted, use WireFormat getDefaultWireFormat().
 */
KeyChain.prototype.signWithSha256 = function(target, wireFormat)
{
  if (target instanceof Interest)
    this.identityManager.signInterestWithSha256(target, wireFormat);
  else
    this.identityManager.signWithSha256(target, wireFormat);
};

/**
 * Check the signature on the Data object and call either onVerify or
 * onVerifyFailed. We use callback functions because verify may fetch
 * information to check the signature.
 * @param {Data} data The Data object with the signature to check.
 * @param {function} onVerified If the signature is verified, this calls
 * onVerified(data).
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onVerifyFailed If the signature check fails, this calls
 * onVerifyFailed(data).
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {number} stepCount
 */
KeyChain.prototype.verifyData = function
  (data, onVerified, onVerifyFailed, stepCount)
{
  if (this.policyManager.requireVerify(data)) {
    var nextStep = this.policyManager.checkVerificationPolicy
      (data, stepCount, onVerified, onVerifyFailed);
    if (nextStep != null) {
      var thisKeyChain = this;
      this.face.expressInterest
        (nextStep.interest,
         function(callbackInterest, callbackData) {
           thisKeyChain.onCertificateData(callbackInterest, callbackData, nextStep);
         },
         function(callbackInterest) {
           thisKeyChain.onCertificateInterestTimeout
             (callbackInterest, nextStep.retry, onVerifyFailed, data, nextStep);
         });
    }
  }
  else if (this.policyManager.skipVerifyAndTrust(data)) {
    try {
      onVerified(data);
    } catch (ex) {
      console.log("Error in onVerified: " + NdnCommon.getErrorWithStackTrace(ex));
    }
  }
  else {
    try {
      onVerifyFailed(data);
    } catch (ex) {
      console.log("Error in onVerifyFailed: " + NdnCommon.getErrorWithStackTrace(ex));
    }
  }
};

/**
 * Check the signature on the signed interest and call either onVerify or
 * onVerifyFailed. We use callback functions because verify may fetch
 * information to check the signature.
 * @param {Interest} interest The interest with the signature to check.
 * @param {function} onVerified If the signature is verified, this calls
 * onVerified(interest).
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onVerifyFailed If the signature check fails, this calls
 * onVerifyFailed(interest).
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 */
KeyChain.prototype.verifyInterest = function
  (interest, onVerified, onVerifyFailed, stepCount, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());

  if (this.policyManager.requireVerify(interest)) {
    var nextStep = this.policyManager.checkVerificationPolicy
      (interest, stepCount, onVerified, onVerifyFailed, wireFormat);
    if (nextStep != null) {
      var thisKeyChain = this;
      this.face.expressInterest
        (nextStep.interest,
         function(callbackInterest, callbackData) {
           thisKeyChain.onCertificateData(callbackInterest, callbackData, nextStep);
         },
         function(callbackInterest) {
           thisKeyChain.onCertificateInterestTimeout
             (callbackInterest, nextStep.retry, onVerifyFailed, data, nextStep);
         });
    }
  }
  else if (this.policyManager.skipVerifyAndTrust(interest)) {
    try {
      onVerified(interest);
    } catch (ex) {
      console.log("Error in onVerified: " + NdnCommon.getErrorWithStackTrace(ex));
    }
  }
  else {
    try {
      onVerifyFailed(interest);
    } catch (ex) {
      console.log("Error in onVerifyFailed: " + NdnCommon.getErrorWithStackTrace(ex));
    }
  }
};

/**
 * Set the Face which will be used to fetch required certificates.
 * @param {Face} face A pointer to the Face object.
 */
KeyChain.prototype.setFace = function(face)
{
  this.face = face;
};

/**
 * Wire encode the target, compute an HmacWithSha256 and update the signature
 * value.
 * Note: This method is an experimental feature. The API may change.
 * @param {Data} target If this is a Data object, update its signature and wire
 * encoding.
 * @param {Blob} key The key for the HmacWithSha256.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * the target. If omitted, use WireFormat getDefaultWireFormat().
 */
KeyChain.signWithHmacWithSha256 = function(target, key, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());

  if (target instanceof Data) {
    var data = target;
    // Encode once to get the signed portion.
    var encoding = data.wireEncode(wireFormat);

    var signer = Crypto.createHmac('sha256', key.buf());
    signer.update(encoding.signedBuf());
    data.getSignature().setSignature(
      new Blob(signer.digest(), false));
  }
  else
    throw new SecurityException(new Error
      ("signWithHmacWithSha256: Unrecognized target type"));
};

/**
 * Compute a new HmacWithSha256 for the target and verify it against the
 * signature value.
 * Note: This method is an experimental feature. The API may change.
 * @param {Data} target The Data object to verify.
 * @param {Blob} key The key for the HmacWithSha256.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * the target. If omitted, use WireFormat getDefaultWireFormat().
 * @returns {boolean} True if the signature verifies, otherwise false.
 */
KeyChain.verifyDataWithHmacWithSha256 = function(data, key, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());

  // wireEncode returns the cached encoding if available.
  var encoding = data.wireEncode(wireFormat);

  var signer = Crypto.createHmac('sha256', key.buf());
  signer.update(encoding.signedBuf());
  var newSignatureBits = new Blob(signer.digest(), false);

  // Use the flexible Blob.equals operator.
  return newSignatureBits.equals(data.getSignature().getSignature());
};

KeyChain.DEFAULT_KEY_PARAMS = new RsaKeyParams();

KeyChain.prototype.onCertificateData = function(interest, data, nextStep)
{
  // Try to verify the certificate (data) according to the parameters in nextStep.
  this.verifyData
    (data, nextStep.onVerified, nextStep.onVerifyFailed, nextStep.stepCount);
};

KeyChain.prototype.onCertificateInterestTimeout = function
  (interest, retry, onVerifyFailed, originalDataOrInterest, nextStep)
{
  if (retry > 0) {
    // Issue the same expressInterest as in verifyData except decrement retry.
    var thisKeyChain = this;
    this.face.expressInterest
      (interest,
       function(callbackInterest, callbackData) {
         thisKeyChain.onCertificateData(callbackInterest, callbackData, nextStep);
       },
       function(callbackInterest) {
         thisKeyChain.onCertificateInterestTimeout
           (callbackInterest, retry - 1, onVerifyFailed, originalDataOrInterest, nextStep);
       });
  }
  else {
    try {
      onVerifyFailed(originalDataOrInterest);
    } catch (ex) {
      console.log("Error in onVerifyFailed: " + NdnCommon.getErrorWithStackTrace(ex));
    }
  }
};

/**
 * Get the default certificate from the identity storage and return its name.
 * If there is no default identity or default certificate, then create one.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that returns the default certificate
 * name.
 */
KeyChain.prototype.prepareDefaultCertificateNamePromise_ = function(useSync)
{
  var signingCertificate;
  var thisKeyChain = this;
  return this.identityManager.getDefaultCertificatePromise(useSync)
  .then(function(localCertificate) {
    signingCertificate = localCertificate;
    if (signingCertificate != null)
      return SyncPromise.resolve();

    // Set the default certificate and get the certificate again.
    return thisKeyChain.setDefaultCertificatePromise_(useSync)
    .then(function() {
      return thisKeyChain.identityManager.getDefaultCertificatePromise(useSync);
    })
    .then(function(localCertificate) {
      signingCertificate = localCertificate;
      return SyncPromise.resolve();
    });
  })
  .then(function() {
    return SyncPromise.resolve(signingCertificate.getName());
  });
}

/**
 * Create the default certificate if it is not initialized. If there is no
 * default identity yet, creating a new tmp-identity.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that resolves when the default
 * certificate is set.
 */
KeyChain.prototype.setDefaultCertificatePromise_ = function(useSync)
{
  var thisKeyChain = this;

  return this.identityManager.getDefaultCertificatePromise(useSync)
  .then(function(certificate) {
    if (certificate != null)
      // We already have a default certificate.
      return SyncPromise.resolve();

    var defaultIdentity;
    return thisKeyChain.identityManager.getDefaultIdentityPromise(useSync)
    .then(function(localDefaultIdentity) {
      defaultIdentity = localDefaultIdentity;
      return SyncPromise.resolve();
    }, function(ex) {
      // Create a default identity name.
      randomComponent = Crypto.randomBytes(4);
      defaultIdentity = new Name().append("tmp-identity")
        .append(new Blob(randomComponent, false));

      return SyncPromise.resolve();
    })
    .then(function() {
      return thisKeyChain.identityManager.createIdentityAndCertificatePromise
        (defaultIdentity, KeyChain.DEFAULT_KEY_PARAMS, useSync);
    })
    .then(function() {
      return thisKeyChain.identityManager.setDefaultIdentityPromise
        (defaultIdentity, useSync);
    });
  });
};
