/**
 * Copyright (C) 2014-2015 Regents of the University of California.
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

var Crypto = require('../crypto.js');
var Name = require('../name.js').Name;
var Interest = require('../interest.js').Interest;
var Data = require('../data.js').Data;
var Blob = require('../util/blob.js').Blob;
var KeyLocatorType = require('../key-locator.js').KeyLocatorType;
var Sha256WithRsaSignature = require('../sha256-with-rsa-signature.js').Sha256WithRsaSignature;
var WireFormat = require('../encoding/wire-format.js').WireFormat;
var Tlv = require('../encoding/tlv/tlv.js').Tlv;
var TlvEncoder = require('../encoding/tlv/tlv-encoder.js').TlvEncoder;
var SecurityException = require('./security-exception.js').SecurityException;
var RsaKeyParams = require('./key-params.js').RsaKeyParams;
var IdentityCertificate = require('./certificate/identity-certificate.js').IdentityCertificate;
var SyncPromise = require('../util/sync-promise.js').SyncPromise;

/**
 * A KeyChain provides a set of interfaces to the security library such as
 * identity management, policy configuration and packet signing and verification.
 * Note: This class is an experimental feature. See the API docs for more detail at
 * http://named-data.net/doc/ndn-ccl-api/key-chain.html .
 *
 * Create a new KeyChain with the given IdentityManager and PolicyManager.
 * @param {IdentityManager} identityManager An object of a subclass of
 * IdentityManager.
 * @param {PolicyManager} policyManager An object of a subclass of
 * PolicyManager.
 * @constructor
 */
var KeyChain = function KeyChain(identityManager, policyManager)
{
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
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
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
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
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
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * @returns {Name} If onComplete is omitted, return the name of the default
 * identity. Otherwise, if onComplete is supplied then return undefined and use
 * onComplete as described above.
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
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
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
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
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
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
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
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
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
 * with the requested IdentityCertificate which is valid. If omitted, the return
 * value is described below. (Some crypto libraries only use a callback, so
 * onComplete is required to use these.)
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * @return {IdentityCertificate} If onComplete is omitted, return the requested
 * certificate which is valid. Otherwise, if onComplete is supplied then return
 * undefined and use onComplete as described above.
 */
KeyChain.prototype.getCertificate = function
  (certificateName, onComplete, onError)
{
  return this.identityManager.getCertificate
    (certificateName, onComplete, onError);
};

/**
 * Get a certificate even if the certificate is not valid anymore.
 * @param {Name} certificateName The name of the requested certificate.
 * @param {function} onComplete (optional) This calls onComplete(certificate)
 * with the requested IdentityCertificate. If omitted, the return value is
 * described below. (Some crypto libraries only use a callback, so onComplete is
 * required to use these.)
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * @return {IdentityCertificate} If onComplete is omitted, return the requested
 * certificate. Otherwise, if onComplete is supplied then return undefined and
 * use onComplete as described above.
 */
KeyChain.prototype.getAnyCertificate = function
  (certificateName, onComplete, onError)
{
  return this.identityManager.getAnyCertificate
    (certificateName, onComplete, onError);
};

/**
 * Get an identity certificate which is still valid with the specified name.
 * @param {Name} certificateName The name of the requested certificate.
 * @param {function} onComplete (optional) This calls onComplete(certificate)
 * with the requested IdentityCertificate which is valid. If omitted, the return
 * value is described below. (Some crypto libraries only use a callback, so
 * onComplete is required to use these.)
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * @return {IdentityCertificate} If onComplete is omitted, return the requested
 * certificate which is valid. Otherwise, if onComplete is supplied then return
 * undefined and use onComplete as described above.
 */
KeyChain.prototype.getIdentityCertificate = function
  (certificateName, onComplete, onError)
{
  return this.identityManager.getCertificate
    (certificateName, onComplete, onError);
};

/**
 * Get an identity certificate even if the certificate is not valid anymore.
 * @param {Name} certificateName The name of the requested certificate.
 * @param {function} onComplete (optional) This calls onComplete(certificate)
 * with the requested IdentityCertificate. If omitted, the return value is
 * described below. (Some crypto libraries only use a callback, so onComplete is
 * required to use these.)
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * @return {IdentityCertificate} If onComplete is omitted, return the requested
 * certificate. Otherwise, if onComplete is supplied then return undefined and
 * use onComplete as described above.
 */
KeyChain.prototype.getAnyIdentityCertificate = function
  (certificateName, onComplete, onError)
{
  return this.identityManager.getAnyCertificate
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
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * @returns {Signature} If onComplete is omitted, return the generated Signature
 * object (if target is a Buffer) or the target (if target is Data or Interest).
 * Otherwise, if onComplete is supplied then return undefined and use onComplete as
 * described above.
 */
KeyChain.prototype.sign = function
  (target, certificateNameOrWireFormat, wireFormat, onComplete, onError)
{
  var certificateName;
  if (certificateNameOrWireFormat instanceof Name)
    // sign(target, certificateName [, wireFormat] [, onComplete] [, onError]).
    // sign(target, certificateName [, onComplete] [, onError]).
    certificateName = certificateNameOrWireFormat;
    // If wireFormat is omitted, we'll shift below.
  else {
    // sign(target [, wireFormat] [, onComplete] [, onError]).
    // sign(target [, onComplete] [, onError]).
    // Shift the parameters. If wireFormat is omitted, we'll shift again below.
    onError = onComplete;
    onComplete = wireFormat;
    wireFormat = certificateNameOrWireFormat;
    certificateName = null;
  }

  if (!(wireFormat instanceof WireFormat)) {
    // wireFormat is omitted. Shift the parameters.
    onError = onComplete;
    onComplete = wireFormat;
    wireFormat = undefined;
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
  (target, certificateNameOrWireFormat, wireFormat, useSync)
{
  var certificateName;
  if (certificateNameOrWireFormat instanceof Name)
    // sign(target, certificateName [, wireFormat] [, useSync]).
    // sign(target, certificateName [, useSync]).
    certificateName = certificateNameOrWireFormat;
    // If wireFormat is omitted, we'll shift below.
  else {
    // sign(target [, wireFormat] [, useSync]).
    // sign(target [, useSync]).
    // Shift the parameters. If wireFormat is omitted, we'll shift again below.
    useSync = wireFormat;
    wireFormat = certificateNameOrWireFormat;
    certificateName = null;
  }

  if (!(wireFormat instanceof WireFormat)) {
    // wireFormat is omitted. Shift the parameters.
    useSync = wireFormat;
    wireFormat = undefined;
  }

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
      return thisKeyChain.setDefaultCertificatePromise_(useSync)
      .then(function() {
        return thisKeyChain.identityManager.getDefaultCertificatePromise(useSync);
      })
      .then(function(signingCertificate) {
        certificateName = signingCertificate.getName();
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
 * @returns {Signature} If onComplete is omitted, return the generated Signature
 * object (if target is a Buffer) or undefined (if target is Data).
 * Otherwise, if onComplete is supplied then return undefined and use onComplete
 * as described above.
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some database libraries only use a
 * callback, so onError is required to be notified of an exception.)
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
 * @param {function} onVerifyFailed If the signature check fails, this calls
 * onVerifyFailed(data).
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
  else if (this.policyManager.skipVerifyAndTrust(data))
    onVerified(data);
  else
    onVerifyFailed(data);
};

/**
 * Check the signature on the signed interest and call either onVerify or
 * onVerifyFailed. We use callback functions because verify may fetch
 * information to check the signature.
 * @param {Interest} interest The interest with the signature to check.
 * @param {function} onVerified If the signature is verified, this calls
 * onVerified(interest).
 * @param {function} onVerifyFailed If the signature check fails, this calls
 * onVerifyFailed(interest).
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
  else if (this.policyManager.skipVerifyAndTrust(interest))
    onVerified(interest);
  else
    onVerifyFailed(interest);
};

/**
 * Set the Face which will be used to fetch required certificates.
 * @param {Face} face A pointer to the Face object.
 */
KeyChain.prototype.setFace = function(face)
{
  this.face = face;
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
  else
    onVerifyFailed(originalDataOrInterest);
};

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
