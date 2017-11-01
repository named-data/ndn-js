/**
 * Copyright (C) 2014-2017 Regents of the University of California.
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
var ConfigFile = require('../util/config-file.js').ConfigFile; /** @ignore */
var WireFormat = require('../encoding/wire-format.js').WireFormat; /** @ignore */
var SecurityException = require('./security-exception.js').SecurityException; /** @ignore */
var RsaKeyParams = require('./key-params.js').RsaKeyParams; /** @ignore */
var IdentityCertificate = require('./certificate/identity-certificate.js').IdentityCertificate; /** @ignore */
var Pib = require('./pib/pib.js').Pib; /** @ignore */
var PibImpl = require('./pib/pib-impl.js').PibImpl; /** @ignore */
var PibKey = require('./pib/pib-key.js').PibKey; /** @ignore */
var Tpm = require('./tpm/tpm.js').Tpm; /** @ignore */
var SyncPromise = require('../util/sync-promise.js').SyncPromise; /** @ignore */
var NdnCommon = require('../util/ndn-common.js').NdnCommon; /** @ignore */
var IdentityManager = require('./identity/identity-manager.js').IdentityManager; /** @ignore */
var CertificateV2 = require('./v2/certificate-v2.js').CertificateV2; /** @ignore */
var SigningInfo = require('./signing-info.js').SigningInfo; /** @ignore */
var Sha256WithRsaSignature = require('../sha256-with-rsa-signature.js').Sha256WithRsaSignature; /** @ignore */
var Sha256WithEcdsaSignature = require('../sha256-with-ecdsa-signature.js').Sha256WithEcdsaSignature; /** @ignore */
var DigestSha256Signature = require('../digest-sha256-signature.js').DigestSha256Signature; /** @ignore */
var KeyLocator = require('../key-locator.js').KeyLocator; /** @ignore */
var KeyLocatorType = require('../key-locator.js').KeyLocatorType; /** @ignore */
var DigestAlgorithm = require('./security-types.js').DigestAlgorithm; /** @ignore */
var KeyType = require('./security-types.js').KeyType; /** @ignore */
var ValidityPeriod = require('./validity-period.js').ValidityPeriod; /** @ignore */
var VerificationHelpers = require('./verification-helpers.js').VerificationHelpers; /** @ignore */
var PublicKey = require('./certificate/public-key.js').PublicKey; /** @ignore */
var NoVerifyPolicyManager = require('./policy/no-verify-policy-manager.js').NoVerifyPolicyManager;

/**
 * A KeyChain provides a set of interfaces to the security library such as
 * identity management, policy configuration and packet signing and verification.
 * Note: This class is an experimental feature. See the API docs for more detail at
 * http://named-data.net/doc/ndn-ccl-api/key-chain.html .
 *
 * There are four forms to create a KeyChain:
 * KeyChain(pibLocator, tpmLocator, allowReset = false) - Create a KeyChain to
 * use the PIB and TPM defined by the given locators, which creates a security
 * v2 KeyChain that uses CertificateV2, Pib, Tpm and Validator (instead of v1
 * Certificate, IdentityStorage, PrivateKeyStorage and PolicyManager).
 * KeyChain(identityManager = null, policyManager = null) - Create a security v1
 * KeyChain to use the optional identityManager and policyManager.
 * KeyChain(pibImpl, tpmBackEnd, policyManager) - Create a KeyChain using this
 * temporary constructor for the transition to security v2, which creates a
 * security v2 KeyChain but still uses the v1 PolicyManager.
 * Finally, the default constructor KeyChain() creates a KeyChain with the
 * default PIB and TPM, which are platform-dependent and can be overridden
 * system-wide or individually by the user. The default constructor creates a
 * security v2 KeyChain that uses CertificateV2, Pib, Tpm and Validator.
 * However, if the default security v1 database file still exists, and the
 * default security v2 database file does not yet exists, then assume that the
 * system is running an older NFD and create a security v1 KeyChain with the
 * default IdentityManager and a NoVerifyPolicyManager.
 * @param {string} pibLocator The PIB locator, e.g., "pib-sqlite3:/example/dir".
 * @param {string} tpmLocator The TPM locator, e.g., "tpm-memory:".
 * @param {boolean} allowReset (optional) If True, the PIB will be reset when
 * the supplied tpmLocator mismatches the one in the PIB. If omitted, don't
 * allow reset.
 * @param {IdentityManager} identityManager (optional) The identity manager as a
 * subclass of IdentityManager. If omitted, use the default IdentityManager
 * constructor.
 * @param {PolicyManager} policyManager: (optional) The policy manager as a
 * subclass of PolicyManager. If omitted, use NoVerifyPolicyManager.
 * @param {PibImpl} pibImpl The PibImpl when using the constructor form
 * KeyChain(pibImpl, tpmBackEnd, policyManager).
 * @param {TpmBackEnd} tpmBackEnd: The TpmBackEnd when using the constructor
 * form KeyChain(pibImpl, tpmBackEnd, policyManager).
 * @throws SecurityException if this is not in Node.js and this uses the default
 * IdentityManager constructor. (See IdentityManager for details.)
 * @constructor
 */
var KeyChain = function KeyChain(arg1, arg2, arg3)
{
  this.identityManager_ = null;  // for security v1
  this.policyManager_ = null;    // for security v1
  this.face_ = null;             // for security v1

  this.pib_ = null;
  this.tpm_ = null;

  if (arg1 == undefined) {
    // The default constructor.
/* debug
    if (os.path.isfile(BasicIdentityStorage.getDefaultDatabaseFilePath()) and
        not os.path.isfile(PibSqlite3.getDefaultDatabaseFilePath())):
*/
    if (true) {
      // The security v1 SQLite file still exists and the security v2
      //   does not yet.
      arg1 = new IdentityManager();
      arg2 = new NoVerifyPolicyManager();
    }
    else {
      // Set the security v2 locators to default empty strings.
      arg1 = "";
      arg2 = "";
    }
  }

  if (typeof arg1 === 'string') {
    var pibLocator = arg1;
    var tpmLocator = arg2;
    var allowReset = arg3;
    if (allowReset == undefined)
      allowReset = false;

    this.isSecurityV1_ = false;

    // PIB locator.
    var pibScheme = [null];
    var pibLocation = [null];
    KeyChain.parseAndCheckPibLocator_(pibLocator, pibScheme, pibLocation);
    var canonicalPibLocator = pibScheme[0] + ":" + pibLocation[0];

    // Create the PIB.
    this.pib_ = KeyChain._createPib(canonicalPibLocator);
    var oldTpmLocator = "";
    try {
      oldTpmLocator = this.pib_.getTpmLocator();
    } catch (ex) {
      // The TPM locator is not set in the PIB yet.
    }

    // TPM locator.
    var tpmScheme = [null];
    var tpmLocation = [null];
    KeyChain.parseAndCheckTpmLocator_(tpmLocator, tpmScheme, tpmLocation);
    var canonicalTpmLocator = tpmScheme[0] + ":" + tpmLocation[0];

    var config = new ConfigFile();
    if (canonicalPibLocator == KeyChain.getDefaultPibLocator_(config)) {
      // The default PIB must use the default TPM.
      if (oldTpmLocator != "" &&
          oldTpmLocator != KeyChain.getDefaultTpmLocator_(config)) {
        this.pib_.reset_();
        canonicalTpmLocator = this.getDefaultTpmLocator_(config);
      }
    }
    else {
      // Check the consistency of the non-default PIB.
      if (oldTpmLocator != "" && oldTpmLocator != canonicalTpmLocator) {
        if (allowReset)
          this.pib_.reset_();
        else
          throw new LocatorMismatchError(new Error
            ("The supplied TPM locator does not match the TPM locator in the PIB: " +
             oldTpmLocator + " != " + canonicalTpmLocator));
      }
    }

    // Note that a key mismatch may still happen if the TPM locator is
    // initially set to a wrong one or if the PIB was shared by more than
    // one TPM before. This is due to the old PIB not having TPM info.
    // The new PIB should not have this problem.
    this.tpm_ = KeyChain.createTpm_(canonicalTpmLocator);
    this.pib_.setTpmLocator(canonicalTpmLocator);
  }
  else if (arg1 instanceof PibImpl) {
    var pibImpl = arg1;
    var tpmBackEnd = arg2;
    var policyManager = arg3;

    this.isSecurityV1_ = false;
    this.policyManager_ = policyManager;

    this.pib_ = new Pib("", "", pibImpl);
    this.tpm_ = new Tpm("", "", tpmBackEnd);
  }
  else {
    var identityManager = arg1;
    var policyManager = arg2;

    this.isSecurityV1_ = true;
    if (identityManager == undefined)
      identityManager = new IdentityManager();
    if (policyManager == undefined)
      policyManager = new NoVerifyPolicyManager();

    this.identityManager_ = identityManager;
    this.policyManager_ = policyManager;
  }
};

exports.KeyChain = KeyChain;

/**
 * Create a KeyChain.Error which represents an error in KeyChain processing.
 * Call with: throw new KeyChain.Error(new Error("message")).
 * @constructor
 * @param {Error} error The exception created with new Error.
 */
KeyChain.Error = function KeyChainError(error)
{
  if (error) {
    error.__proto__ = KeyChain.Error.prototype;
    return error;
  }
};

KeyChain.Error.prototype = new Error();
KeyChain.Error.prototype.name = "KeyChainError";

/**
 * @return {Pib}
 */
KeyChain.prototype.getPib = function()
{
  if (this.isSecurityV1_)
    throw new SecurityException(new Error
      ("getPib is not supported for security v1"));

  return this.pib_;
};

/**
 * @return {Tpm}
 */
KeyChain.prototype.getTpm = function()
{
  if (this.isSecurityV1_)
    throw new SecurityException(new Error
      ("getTpm is not supported for security v1"));

  return this.tpm_;
};

// Identity management

// Key management

// Certificate management

// Signing

/**
 * Sign the target. If it is a Data or Interest object, set its signature. If it
 * is a Buffer, produce a Signature object.
 * @param {Data|Interest|Buffer} target If this is a Data object, wire encode
 * for signing, replace its Signature object based on the type of key and other
 * info in the SigningInfo params or default identity, and update the
 * wireEncoding. If this is an Interest object, wire encode for signing, append
 * a SignatureInfo to the Interest name, sign the name components and append a
 * final name component with the signature bits. If it is a buffer, sign it and
 * return a Signature object.
 * @param {SigningInfo|Name} paramsOrCertificateName (optional) If a SigningInfo,
 * it is the signing parameters. If a Name, it is the certificate name of the
 * key to use for signing. If omitted and this is a security v1 KeyChain then
 * use the IdentityManager to get the default identity. Otherwise, use the PIB
 * to get the default key of the default identity.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * the input. If omitted, use WireFormat getDefaultWireFormat().
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise that returns the target (if target is
 * Data or Interest), or returns the generated Signature object (if target is a
 * Buffer).
 */
KeyChain.prototype.signPromise = function
  (target, paramsOrCertificateName, wireFormat, useSync)
{
  var arg2 = paramsOrCertificateName;
  var arg3 = wireFormat;
  var arg4 = useSync;
  // arg2,                    arg3,       arg4
  // paramsOrCertificateName, wireFormat, useSync
  // paramsOrCertificateName, wireFormat, null
  // paramsOrCertificateName, useSync,    null
  // paramsOrCertificateName, null,       null
  // wireFormat,              useSync,    null
  // wireFormat,              null,       null
  // useSync,                 null,       null
  // null,                    null,       null
  if (arg2 instanceof SigningInfo || arg2 instanceof Name)
    paramsOrCertificateName = arg2;
  else
    paramsOrCertificateName = undefined;

  if (arg2 instanceof WireFormat)
    wireFormat = arg2;
  else if (arg3 instanceof WireFormat)
    wireFormat = arg3;
  else
    wireFormat = undefined;

  if (typeof arg2 === "boolean")
    useSync = arg2;
  else if (typeof arg3 === "boolean")
    useSync = arg3;
  else if (typeof arg4 === "boolean")
    useSync = arg4;
  else
    useSync = false;

  if (wireFormat == undefined)
    wireFormat = WireFormat.getDefaultWireFormat();

  var thisKeyChain = this;

  return SyncPromise.resolve()
  .then(function() {
    if (paramsOrCertificateName == undefined) {
      // Convert sign(target) into sign(target, paramsOrCertificateName)
      if (thisKeyChain.isSecurityV1_) {
        return thisKeyChain.prepareDefaultCertificateNamePromise_(useSync)
        .then(function(name) {
          paramsOrCertificateName = name;
          return SyncPromise.resolve();
        });
      }
      else {
        paramsOrCertificateName = KeyChain.defaultSigningInfo_;
        return SyncPromise.resolve();
      }
    }
    else
      return SyncPromise.resolve();
  })
  .then(function() {
    if (paramsOrCertificateName instanceof Name) {
      var certificateName = paramsOrCertificateName;

      if (!thisKeyChain.isSecurityV1_) {
        // Make and use a SigningInfo for backwards compatibility.
        if (!((target instanceof Interest) || (target instanceof Data)))
          return SyncPromise.reject(new SecurityException(new Error
("sign(buffer, certificateName) is not supported for security v2. Use sign with SigningInfo.")));

        var signingInfo = new SigningInfo();
        signingInfo.setSigningCertificateName(certificateName);
        return thisKeyChain.signPromise(target, signingInfo, wireFormat, useSync)
        .catch(function(err) {
          return SyncPromise.reject(new SecurityException(new Error
            ("Error in sign: " + err)));
        });
      }
      else {
        if (target instanceof Interest)
          return thisKeyChain.identityManager_.signInterestByCertificatePromise
            (target, certificateName, wireFormat, useSync);
        else if (target instanceof Data)
          return thisKeyChain.identityManager_.signByCertificatePromise
            (target, certificateName, wireFormat, useSync);
        else
          return thisKeyChain.identityManager_.signByCertificatePromise
            (target, certificateName, useSync);
      }
    }

    var params = paramsOrCertificateName;

    if (target instanceof Data) {
      var data = target;

      var keyName = [null];
      return thisKeyChain.prepareSignatureInfoPromise_(params, keyName, useSync)
      .then(function(signatureInfo) {
        data.setSignature(signatureInfo);

        // Encode once to get the signed portion.
        var encoding = data.wireEncode(wireFormat);

        return thisKeyChain.signBufferPromise_
          (encoding.signedBuf(), keyName[0], params.getDigestAlgorithm(), useSync);
      })
      .then(function(signatureBytes) {
        data.getSignature().setSignature(signatureBytes);

        // Encode again to include the signature.
        data.wireEncode(wireFormat);
        return SyncPromise.resolve(data);
      });
    }
    else if (target instanceof Interest) {
      var interest = target;
      var signatureInfo;

      var keyName = [null];
      return thisKeyChain.prepareSignatureInfoPromise_(params, keyName, useSync)
      .then(function(localSignatureInfo) {
        signatureInfo = localSignatureInfo;

        // Append the encoded SignatureInfo.
        interest.getName().append(wireFormat.encodeSignatureInfo(signatureInfo));

        // Append an empty signature so that the "signedPortion" is correct.
        interest.getName().append(new Name.Component());
        // Encode once to get the signed portion, and sign.
        var encoding = interest.wireEncode(wireFormat);
        return thisKeyChain.signBufferPromise_
          (encoding.signedBuf(), keyName[0], params.getDigestAlgorithm(), useSync);
      })
      .then(function(signatureBytes) {
        signatureInfo.setSignature(signatureBytes);

        // Remove the empty signature and append the real one.
        interest.setName(interest.getName().getPrefix(-1).append
          (wireFormat.encodeSignatureValue(signatureInfo)));
        return SyncPromise.resolve(interest);
      });
    }
    else {
      var buffer = target;

      var keyName = [null];
      return thisKeyChain.prepareSignatureInfoPromise_(params, keyName, useSync)
      .then(function(signatureInfo) {
        return thisKeyChain.signBufferPromise_
          (buffer, keyName[0], params.getDigestAlgorithm(), useSync);
      });
    }
  });
};

/**
 * Sign the target. If it is a Data or Interest object, set its signature. If it
 * is a Buffer, produce a Signature object.
 * @param {Data|Interest|Buffer} target If this is a Data object, wire encode
 * for signing, replace its Signature object based on the type of key and other
 * info in the SigningInfo params or default identity, and update the
 * wireEncoding. If this is an Interest object, wire encode for signing, append
 * a SignatureInfo to the Interest name, sign the name components and append a
 * final name component with the signature bits. If it is a buffer, sign it and
 * return a Signature object.
 * @param {SigningInfo|Name} paramsOrCertificateName (optional) If a SigningInfo,
 * it is the signing parameters. If a Name, it is the certificate name of the
 * key to use for signing. If omitted and this is a security v1 KeyChain then
 * use the IdentityManager to get the default identity. Otherwise, use the PIB
 * to get the default key of the default identity.
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
 * @return {Signature} If onComplete is omitted, return the generated Signature
 * object (if target is a Buffer) or the target (if target is Data or Interest).
 * Otherwise, if onComplete is supplied then return undefined and use onComplete as
 * described above.
 */
KeyChain.prototype.sign = function
  (target, paramsOrCertificateName, wireFormat, onComplete, onError)
{
  var arg2 = paramsOrCertificateName;
  var arg3 = wireFormat;
  var arg4 = onComplete;
  var arg5 = onError;
  // arg2,                    arg3,       arg4,       arg5
  // paramsOrCertificateName, wireFormat, onComplete, onError
  // paramsOrCertificateName, wireFormat, null,       null
  // paramsOrCertificateName, onComplete, onError,    null
  // paramsOrCertificateName, null,       null,       null
  // wireFormat,              onComplete, onError,    null
  // wireFormat,              null,       null,       null
  // onComplete,              onError,    null,       null
  // null,                    null,       null,       null
  if (arg2 instanceof SigningInfo || arg2 instanceof Name)
    paramsOrCertificateName = arg2;
  else
    paramsOrCertificateName = null;

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
    this.signPromise(target, paramsOrCertificateName, wireFormat, !onComplete));
};

// Import and export

/**
 * Import a certificate and its corresponding private key encapsulated in a
 * SafeBag. If the certificate and key are imported properly, the default
 * setting will be updated as if a new key and certificate is added into this
 * KeyChain.
 * @param {SafeBag} safeBag The SafeBag containing the certificate and private
 * key. This copies the values from the SafeBag.
 * @param {Buffer} password (optional) The password for decrypting the private
 * key. If the password is supplied, use it to decrypt the PKCS #8
 * EncryptedPrivateKeyInfo. If the password is omitted or null, import an
 * unencrypted PKCS #8 PrivateKeyInfo.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which fulfills when finished.
 */
KeyChain.prototype.importSafeBagPromise = function(safeBag, password, useSync)
{
  if (typeof password === 'boolean') {
    // password is omitted, so shift.
    useSync = password;
    password = null;
  }

  var certificate;
  try {
    certificate = new CertificateV2(safeBag.getCertificate());
  } catch (ex) {
    return SyncPromise.reject(new Error("Error reading CertificateV2: " + ex));
  }
  var identity = certificate.getIdentity();
  var keyName = certificate.getKeyName();
  var publicKeyBits = certificate.getPublicKey();
  var content = new Blob([0x01, 0x02, 0x03, 0x04]);
  var signatureBits;
  var thisKeyChain = this;

  return SyncPromise.resolve()
  .then(function() {
    return thisKeyChain.tpm_.hasKeyPromise(keyName, useSync);
  })
  .then(function(hasKey) {
    if (hasKey)
      return SyncPromise.reject(new KeyChain.Error(new Error
        ("Private key `" + keyName.toUri() + "` already exists")));

    return thisKeyChain.pib_.getIdentityPromise(identity, useSync)
    .then(function(existingId) {
      return existingId.getKeyPromise(keyName, useSync);
    })
    .then(function() {
      return SyncPromise.reject(new KeyChain.Error(new Error
        ("Public key `" + keyName.toUri() + "` already exists")));
    }, function(err) {
      // Either the identity or the key doesn't exist, so OK to import.
      return SyncPromise.resolve();
    });
  })
  .then(function() {
    return thisKeyChain.tpm_.importPrivateKeyPromise_
      (keyName, safeBag.getPrivateKeyBag().buf(), password, useSync)
    .catch(function(err) {
      return SyncPromise.reject(new KeyChain.Error(new Error
        ("Failed to import private key `" + keyName.toUri() + "`")));
    });
  })
  .then(function() {
    // Check the consistency of the private key and certificate.
    return thisKeyChain.tpm_.signPromise
      (content.buf(), keyName, DigestAlgorithm.SHA256, useSync)
    .then(function(localSignatureBits) {
      signatureBits = localSignatureBits;
      return SyncPromise.resolve();
    }, function(err) {
      return thisKeyChain.tpm_.deleteKeyPromise_(keyName, useSync)
      .then(function() {
        return SyncPromise.reject(new KeyChain.Error(new Error
          ("Invalid private key `" + keyName.toUri() + "`")));
      });
    });
  })
  .then(function() {
    var publicKey;
    try {
      publicKey = new PublicKey(publicKeyBits);
    } catch (ex) {
      // Promote to KeyChain.Error.
      return thisKeyChain.tpm_.deleteKeyPromise_(keyName, useSync)
      .then(function() {
        return SyncPromise.reject(new KeyChain.Error(new Error
          ("Error decoding public key " + ex)));
      });
    }

    return VerificationHelpers.verifySignaturePromise
      (content, signatureBits, publicKey);
  })
  .then(function(isVerified) {
    if (!isVerified) {
      return thisKeyChain.tpm_.deleteKeyPromise_(keyName, useSync)
      .then(function() {
        return SyncPromise.reject(new KeyChain.Error(new Error
          ("Certificate `" + certificate.getName().toUri() +
           "` and private key `" + keyName.toUri() + "` do not match")));
      });
    }

    // The consistency is verified. Add to the PIB.
    return thisKeyChain.pib_.addIdentityPromise_(identity, useSync);
  })
  .then(function(id) {
    return id.addKeyPromise_(certificate.getPublicKey().buf(), keyName, useSync);
  })
  .then(function(key) {
    return key.addCertificatePromise_(certificate, useSync);
  });
};

/**
 * Import a certificate and its corresponding private key encapsulated in a
 * SafeBag. If the certificate and key are imported properly, the default
 * setting will be updated as if a new key and certificate is added into this
 * KeyChain.
 * @param {SafeBag} safeBag The SafeBag containing the certificate and private
 * key. This copies the values from the SafeBag.
 * @param {Buffer} password (optional) The password for decrypting the private
 * key. If the password is supplied, use it to decrypt the PKCS #8
 * EncryptedPrivateKeyInfo. If the password is omitted or null, import an
 * unencrypted PKCS #8 PrivateKeyInfo.
 * @param {function} onComplete (optional) This calls onComplete() when finished.
 * If omitted, just return when finished. (Some crypto libraries only use a
 * callback, so onComplete is required to use these.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onError (optional) If defined, then onComplete must be
 * defined and if there is an exception, then this calls onError(exception)
 * with the exception. If onComplete is defined but onError is undefined, then
 * this will log any thrown exception. (Some crypto libraries only use a
 * callback, so onError is required to be notified of an exception.)
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 */
KeyChain.prototype.importSafeBag = function
  (safeBag, password, onComplete, onError)
{
  onError = (typeof password === "function") ? onComplete : onError;
  onComplete = (typeof password === "function") ? password : onComplete;
  password = (typeof password === "function") ? null : password;

  return SyncPromise.complete(onComplete, onError,
    this.importSafeBagPromise(safeBag, password, !onComplete));
};

// PIB & TPM backend registry

// Security v1 methods

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
 * @return {Name} If onComplete is omitted, return the name of the default
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

  return this.identityManager_.createIdentityAndCertificate
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
 * @return {Name} The key name of the auto-generated KSK of the identity.
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
  this.identityManager_.deleteIdentity(identityName, onComplete, onError);
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
 * @return {Name} If onComplete is omitted, return the name of the default
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
  return this.identityManager_.getDefaultIdentity(onComplete, onError);
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
  if (!this.isSecurityV1_) {
    return SyncPromise.complete(onComplete, onError,
      this.pib_.getDefaultIdentityPromise(!onComplete)
      .then(function(identity) {
        return identity.getDefaultKeyPromise(!onComplete);
      })
      .then(function(key) {
        return key.getDefaultCertificatePromise(!onComplete);
      })
      .then(function(certificate) {
        return SyncPromise.resolve(certificate.getName());
      }));
  }

  return this.identityManager_.getDefaultCertificateName(onComplete, onError);
};

/**
 * Generate a pair of RSA keys for the specified identity.
 * @param {Name} identityName The name of the identity.
 * @param {boolean} isKsk (optional) true for generating a Key-Signing-Key (KSK),
 * false for a Data-Signing-Key (DSK). If omitted, generate a Data-Signing-Key.
 * @param {number} keySize (optional) The size of the key. If omitted, use a
 * default secure key size.
 * @return {Name} The generated key name.
 */
KeyChain.prototype.generateRSAKeyPair = function(identityName, isKsk, keySize)
{
  keySize = (typeof isKsk === "boolean") ? isKsk : keySize;
  isKsk = (typeof isKsk === "boolean") ? isKsk : false;

  if (!keySize)
    keySize = 2048;

  return this.identityManager_.generateRSAKeyPair(identityName, isKsk, keySize);
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
  return this.identityManager_.setDefaultKeyForIdentity
    (keyName, identityNameCheck, onComplete, onError);
};

/**
 * Generate a pair of RSA keys for the specified identity and set it as the
 * default key for the identity.
 * @param {Name} identityName The name of the identity.
 * @param {boolean} isKsk (optional) true for generating a Key-Signing-Key (KSK),
 * false for a Data-Signing-Key (DSK). If omitted, generate a Data-Signing-Key.
 * @param {number} keySize (optional) The size of the key. If omitted, use a
 * default secure key size.
 * @return {Name} The generated key name.
 */
KeyChain.prototype.generateRSAKeyPairAsDefault = function
  (identityName, isKsk, keySize)
{
  return this.identityManager_.generateRSAKeyPairAsDefault
    (identityName, isKsk, keySize);
};

/**
 * Create a public key signing request.
 * @param {Name} keyName The name of the key.
 * @return {Blob} The signing request data.
 */
KeyChain.prototype.createSigningRequest = function(keyName)
{
  return this.identityManager_.getPublicKey(keyName).getKeyDer();
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
  this.identityManager_.addCertificate(certificate, onComplete, onError);
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
  this.identityManager_.setDefaultCertificateForKey
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
  return this.identityManager_.getCertificate
    (certificateName, onComplete, onError);
};

/**
 * @deprecated Use getCertificate.
 */
KeyChain.prototype.getIdentityCertificate = function
  (certificateName, onComplete, onError)
{
  return this.identityManager_.getCertificate
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
 * @return {IdentityManager} The identity manager.
 */
KeyChain.prototype.getIdentityManager = function()
{
  return this.identityManager_;
};

/*****************************************
 *           Policy Management           *
 *****************************************/

/**
 * Get the policy manager given to or created by the constructor.
 * @return {PolicyManager} The policy manager.
 */
KeyChain.prototype.getPolicyManager = function()
{
  return this.policyManager_;
};

/*****************************************
 *              Sign/Verify              *
 *****************************************/

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
 * @return {Signature} If onComplete is omitted, return the generated Signature
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
        var inferredIdentity = thisKeyChain.policyManager_.inferSigningIdentity
          (data.getName());
        if (inferredIdentity.size() == 0)
          return thisKeyChain.identityManager_.getDefaultCertificateNamePromise
            (useSync);
        else
          return thisKeyChain.identityManager_.getDefaultCertificateNameForIdentityPromise
              (inferredIdentity, useSync);
      }
      else
        return thisKeyChain.identityManager_.getDefaultCertificateNameForIdentityPromise
          (identityName, useSync);
    })
    .then(function(signingCertificateName) {
      if (signingCertificateName.size() == 0)
        throw new SecurityException(new Error
          ("No qualified certificate name found!"));

      if (!thisKeyChain.policyManager_.checkSigningPolicy
           (data.getName(), signingCertificateName))
        throw new SecurityException(new Error
          ("Signing Cert name does not comply with signing policy"));

      return thisKeyChain.identityManager_.signByCertificatePromise
        (data, signingCertificateName, wireFormat, useSync);
    });

    return SyncPromise.complete(onComplete, onError, mainPromise);
  }
  else {
    var array = target;

    return SyncPromise.complete(onComplete, onError,
      this.identityManager_.getDefaultCertificateNameForIdentityPromise
        (identityName, useSync)
      .then(function(signingCertificateName) {
        if (signingCertificateName.size() == 0)
          throw new SecurityException(new Error
            ("No qualified certificate name found!"));

        return thisKeyChain.identityManager_.signByCertificatePromise
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
    this.identityManager_.signInterestWithSha256(target, wireFormat);
  else
    this.identityManager_.signWithSha256(target, wireFormat);
};

/**
 * Check the signature on the Data object and call either onVerify or
 * onValidationFailed. We use callback functions because verify may fetch
 * information to check the signature.
 * @param {Data} data The Data object with the signature to check.
 * @param {function} onVerified If the signature is verified, this calls
 * onVerified(data).
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onValidationFailed If the signature check fails, this calls
 * onValidationFailed(data, reason) with the Data object and reason string.
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {number} stepCount
 */
KeyChain.prototype.verifyData = function
  (data, onVerified, onValidationFailed, stepCount)
{
  if (stepCount == null)
    stepCount = 0;

  if (this.policyManager_.requireVerify(data)) {
    var nextStep = this.policyManager_.checkVerificationPolicy
      (data, stepCount, onVerified, onValidationFailed);
    if (nextStep != null) {
      var thisKeyChain = this;
      this.face_.expressInterest
        (nextStep.interest,
         function(callbackInterest, callbackData) {
           thisKeyChain.onCertificateData(callbackInterest, callbackData, nextStep);
         },
         function(callbackInterest) {
           thisKeyChain.onCertificateInterestTimeout
             (callbackInterest, nextStep.retry, onValidationFailed, data, nextStep);
         });
    }
  }
  else if (this.policyManager_.skipVerifyAndTrust(data)) {
    try {
      onVerified(data);
    } catch (ex) {
      console.log("Error in onVerified: " + NdnCommon.getErrorWithStackTrace(ex));
    }
  }
  else {
    try {
      onValidationFailed
        (data, "The packet has no verify rule but skipVerifyAndTrust is false");
    } catch (ex) {
      console.log("Error in onValidationFailed: " + NdnCommon.getErrorWithStackTrace(ex));
    }
  }
};

/**
 * Check the signature on the signed interest and call either onVerify or
 * onValidationFailed. We use callback functions because verify may fetch
 * information to check the signature.
 * @param {Interest} interest The interest with the signature to check.
 * @param {function} onVerified If the signature is verified, this calls
 * onVerified(interest).
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 * @param {function} onValidationFailed If the signature check fails, this calls
 * onValidationFailed(interest, reason) with the Interest object and reason
 * string.
 * NOTE: The library will log any exceptions thrown by this callback, but for
 * better error handling the callback should catch and properly handle any
 * exceptions.
 */
KeyChain.prototype.verifyInterest = function
  (interest, onVerified, onValidationFailed, stepCount, wireFormat)
{
  if (stepCount == null)
    stepCount = 0;
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());

  if (this.policyManager_.requireVerify(interest)) {
    var nextStep = this.policyManager_.checkVerificationPolicy
      (interest, stepCount, onVerified, onValidationFailed, wireFormat);
    if (nextStep != null) {
      var thisKeyChain = this;
      this.face_.expressInterest
        (nextStep.interest,
         function(callbackInterest, callbackData) {
           thisKeyChain.onCertificateData(callbackInterest, callbackData, nextStep);
         },
         function(callbackInterest) {
           thisKeyChain.onCertificateInterestTimeout
             (callbackInterest, nextStep.retry, onValidationFailed, interest,
              nextStep);
         });
    }
  }
  else if (this.policyManager_.skipVerifyAndTrust(interest)) {
    try {
      onVerified(interest);
    } catch (ex) {
      console.log("Error in onVerified: " + NdnCommon.getErrorWithStackTrace(ex));
    }
  }
  else {
    try {
      onValidationFailed
        (interest,
         "The packet has no verify rule but skipVerifyAndTrust is false");
    } catch (ex) {
      console.log("Error in onValidationFailed: " + NdnCommon.getErrorWithStackTrace(ex));
    }
  }
};

/**
 * Set the Face which will be used to fetch required certificates.
 * @param {Face} face A pointer to the Face object.
 */
KeyChain.prototype.setFace = function(face)
{
  this.face_ = face;
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
 * @return {boolean} True if the signature verifies, otherwise false.
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

// Private security v2 methods


/**
 * Prepare a Signature object according to signingInfo and get the signing key
 * name.
 * @param {SigningInfo} params The signing parameters.
 * @param {Array<Name>} keyName Set keyName[0] to the signing key name.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns a new Signature object
 * with the SignatureInfo, or a promise rejected with InvalidSigningInfoError
 * when the requested signing method cannot be satisfied.
 */
KeyChain.prototype.prepareSignatureInfoPromise_ = function
  (params, keyName, useSync)
{
  var identity = null;
  var key = null;
  var thisKeyChain = this;

  return SyncPromise.resolve()
  .then(function() {
    if (params.getSignerType() == SigningInfo.SignerType.NULL) {
      return thisKeyChain.pib_.getDefaultIdentityPromise(useSync)
      .then(function(localIdentity) {
        identity = localIdentity;
        return SyncPromise.resolve(null);
      }, function(err) {
        // There is no default identity, so use sha256 for signing.
        keyName[0] = SigningInfo.getDigestSha256Identity();
        return SyncPromise.resolve(new DigestSha256Signature());
      });
    }
    else if (params.getSignerType() == SigningInfo.SignerType.ID) {
      identity = params.getPibIdentityPromise();
      if (identity == null) {
        return thisKeyChain.pib_.getIdentityPromise(params.getSignerName(), useSync)
        .then(function(localIdentity) {
          identity = localIdentity;
          return SyncPromise.resolve(null);
        }, function(err) {
          return SyncPromise.reject(new InvalidSigningInfoError(new Error
            ("Signing identity `" + params.getSignerName().toUri() +
             "` does not exist")));
        });
      }
      else
        return SyncPromise.resolve(null);
    }
    else if (params.getSignerType() == SigningInfo.SignerType.KEY) {
      key = params.getPibKey();
      if (key == null) {
        identityName = PibKey.extractIdentityFromKeyName(
          params.getSignerName());

        return thisKeyChain.pib_.getIdentityPromise(identityName, useSync)
        .then(function(localIdentity) {
          return localIdentity.getKeyPromise(params.getSignerName(), useSync)
          .then(function(localKey) {
            key = localKey;
            // We will use the PIB key instance, so reset the identity.
            identity = null;
            return SyncPromise.resolve(null);
          });
        }, function(err) {
          return SyncPromise.reject(new InvalidSigningInfoError(new Error
            ("Signing key `" + params.getSignerName().toUri() +
             "` does not exist")));
        });
      }
      else
        return SyncPromise.resolve(null);
    }
    else if (params.getSignerType() == SigningInfo.SignerType.CERT) {
      var identityName = CertificateV2.extractIdentityFromCertName
        (params.getSignerName());

      return thisKeyChain.pib_.getIdentityPromise(identityName, useSync)
      .then(function(localIdentity) {
        identity = localIdentity;
        return identity.getKeyPromise
          (CertificateV2.extractKeyNameFromCertName(params.getSignerName()), useSync)
        .then(function(localKey) {
          key = localKey;
          return SyncPromise.resolve(null);
        });
      }, function(err) {
        return SyncPromise.reject(new InvalidSigningInfoError(new Error
          ("Signing certificate `" + params.getSignerName().toUri() +
           "` does not exist")));
      });
    }
    else if (params.getSignerType() == SigningInfo.SignerType.SHA256) {
      keyName[0] = SigningInfo.getDigestSha256Identity();
      return SyncPromise.resolve(new DigestSha256Signature());
    }
    else
      // We don't expect this to happen.
      return SyncPromise.reject(new InvalidSigningInfoError(new Error
        ("Unrecognized signer type")));
  })
  .then(function(signingInfo) {
    if (signingInfo != null)
      // We already have the result (a DigestSha256Signature).
      return SyncPromise.resolve(signingInfo);
    else {
      if (identity == null && key == null)
        return SyncPromise.reject(new InvalidSigningInfoError(new Error
          ("Cannot determine signing parameters")));

      return SyncPromise.resolve()
      .then(function() {
        if (identity != null && key == null) {
          return identity.getDefaultKeyPromise(useSync)
          .then(function(localKey) {
            key = localKey;
            return SyncPromise.resolve(null);
          }, function(err) {
            return SyncPromise.reject(new InvalidSigningInfoError(new Error
              ("Signing identity `" + identity.getName().toUri() +
               "` does not have default certificate")));
          });
        }
        else
          return SyncPromise.resolve();
      })
      .then(function() {
        if (key.getKeyType() == KeyType.RSA &&
            params.getDigestAlgorithm() == DigestAlgorithm.SHA256)
          signatureInfo = new Sha256WithRsaSignature();
        else if (key.getKeyType() == KeyType.ECDSA &&
                 params.getDigestAlgorithm() == DigestAlgorithm.SHA256)
          signatureInfo = new Sha256WithEcdsaSignature()
        else
          return SyncPromise.reject(new KeyChain.Error(new Error
            ("Unsupported key type")));

        if (params.getValidityPeriod().hasPeriod() &&
            ValidityPeriod.canGetFromSignature(signatureInfo))
          // Set the ValidityPeriod from the SigningInfo params.
          ValidityPeriod.getFromSignature(signatureInfo).setPeriod
            (params.getValidityPeriod().getNotBefore(),
             params.getValidityPeriod().getNotAfter());

        var keyLocator = KeyLocator.getFromSignature(signatureInfo);
        keyLocator.setType(KeyLocatorType.KEYNAME);
        keyLocator.setKeyName(key.getName());

        keyName[0] = key.getName();
        return SyncPromise.resolve(signatureInfo);
      });
    }
  });
};

/**
 * Sign the byte buffer using the key with name keyName.
 * @param {Buffer} buffer The input byte buffer.
 * @param {Name} keyName The name of the key.
 * @param {number} digestAlgorithm The digest algorithm as an int from the
 * DigestAlgorithm enum.
 * @param {boolean} useSync (optional) If true then return a SyncPromise which
 * is already fulfilled. If omitted or false, this may return a SyncPromise or
 * an async Promise.
 * @return {Promise|SyncPromise} A promise which returns the signature Blob (or
 * an isNull Blob if the key does not exist), or a promise rejected
 * with TpmBackEnd.Error for an error in signing.
 */
KeyChain.prototype.signBufferPromise_ = function
  (buffer, keyName, digestAlgorithm, useSync)
{
  if (keyName.equals(SigningInfo.getDigestSha256Identity())) {
    var hash = Crypto.createHash('sha256');
    hash.update(buffer);
    return SyncPromise.resolve(new Blob(hash.digest(), false));
  }

  return this.tpm_.signPromise(buffer, keyName, digestAlgorithm, useSync);
};

// Private security v1 methods

KeyChain.prototype.onCertificateData = function(interest, data, nextStep)
{
  // Try to verify the certificate (data) according to the parameters in nextStep.
  this.verifyData
    (data, nextStep.onVerified, nextStep.onValidationFailed, nextStep.stepCount);
};

KeyChain.prototype.onCertificateInterestTimeout = function
  (interest, retry, onValidationFailed, originalDataOrInterest, nextStep)
{
  if (retry > 0) {
    // Issue the same expressInterest as in verifyData except decrement retry.
    var thisKeyChain = this;
    this.face_.expressInterest
      (interest,
       function(callbackInterest, callbackData) {
         thisKeyChain.onCertificateData(callbackInterest, callbackData, nextStep);
       },
       function(callbackInterest) {
         thisKeyChain.onCertificateInterestTimeout
           (callbackInterest, retry - 1, onValidationFailed,
            originalDataOrInterest, nextStep);
       });
  }
  else {
    try {
      onValidationFailed
        (originalDataOrInterest, "The retry count is zero after timeout for fetching " +
          interest.getName().toUri());
    } catch (ex) {
      console.log("Error in onValidationFailed: " + NdnCommon.getErrorWithStackTrace(ex));
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
  return this.identityManager_.getDefaultCertificatePromise(useSync)
  .then(function(localCertificate) {
    signingCertificate = localCertificate;
    if (signingCertificate != null)
      return SyncPromise.resolve();

    // Set the default certificate and get the certificate again.
    return thisKeyChain.setDefaultCertificatePromise_(useSync)
    .then(function() {
      return thisKeyChain.identityManager_.getDefaultCertificatePromise(useSync);
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

  return this.identityManager_.getDefaultCertificatePromise(useSync)
  .then(function(certificate) {
    if (certificate != null)
      // We already have a default certificate.
      return SyncPromise.resolve();

    var defaultIdentity;
    return thisKeyChain.identityManager_.getDefaultIdentityPromise(useSync)
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
      return thisKeyChain.identityManager_.createIdentityAndCertificatePromise
        (defaultIdentity, KeyChain.DEFAULT_KEY_PARAMS, useSync);
    })
    .then(function() {
      return thisKeyChain.identityManager_.setDefaultIdentityPromise
        (defaultIdentity, useSync);
    });
  });
};

KeyChain.defaultSigningInfo_ = new SigningInfo();


/**
 * Create an InvalidSigningInfoError which extends KeyChain.Error to indicate
 * that the supplied SigningInfo is invalid.
 * Call with: throw new InvalidSigningInfoError(new Error("message")).
 * @param {Error} error The exception created with new Error.
 * @constructor
 */
function InvalidSigningInfoError(error)
{
  if (error) {
    error.__proto__ = InvalidSigningInfoError.prototype;
    return error;
  }
}

InvalidSigningInfoError.prototype = new Error();
InvalidSigningInfoError.prototype.name = "InvalidSigningInfoError";

exports.InvalidSigningInfoError = InvalidSigningInfoError;

/**
 * Create a LocatorMismatchError which extends KeyChain.Error to indicate that
 * the supplied TPM locator does not match the locator stored in the PIB.
 * Call with: throw new LocatorMismatchError(new Error("message")).
 * @param {Error} error The exception created with new Error.
 * @constructor
 */
function LocatorMismatchError(error)
{
  if (error) {
    error.__proto__ = LocatorMismatchError.prototype;
    return error;
  }
}

LocatorMismatchError.prototype = new Error();
LocatorMismatchError.prototype.name = "LocatorMismatchError";

exports.LocatorMismatchError = LocatorMismatchError;
