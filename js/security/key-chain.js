/**
 * Copyright (C) 2014 Regents of the University of California.
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

var Name = require('../name.js').Name;
var Interest = require('../interest.js').Interest;
var Data = require('../data.js').Data;
var KeyLocatorType = require('../key-locator.js').KeyLocatorType;
var Sha256WithRsaSignature = require('../sha256-with-rsa-signature.js').Sha256WithRsaSignature;
var WireFormat = require('../encoding/wire-format.js').WireFormat;
var Tlv = require('../encoding/tlv/tlv.js').Tlv;
var TlvEncoder = require('../encoding/tlv/tlv-encoder.js').TlvEncoder;
var SecurityException = require('./security-exception.js').SecurityException;

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
  this.encryptionManager = null;
  this.face = null;
  this.maxSteps = 100;
};

exports.KeyChain = KeyChain;

/*****************************************
 *          Identity Management          *
 *****************************************/

/**
 * Create an identity by creating a pair of Key-Signing-Key (KSK) for this
 * identity and a self-signed certificate of the KSK.
 * @param {Name} identityName The name of the identity.
 * @returns {Name} The key name of the auto-generated KSK of the identity.
 */
KeyChain.prototype.createIdentity = function(identityName)
{
  return this.identityManager.createIdentity(identityName);
};

/**
 * Get the default identity.
 * @returns {Name} The name of default identity.
 * @throws SecurityException if the default identity is not set.
 */
KeyChain.prototype.getDefaultIdentity = function()
{
  return this.identityManager.getDefaultIdentity();
};

/**
 * Get the default certificate name of the default identity.
 * @returns {Name} The requested certificate name.
 * @throws SecurityException if the default identity is not set or the default
 * key name for the identity is not set or the default certificate name for
 * the key name is not set.
 */
KeyChain.prototype.getDefaultCertificateName = function()
{
  return this.identityManager.getDefaultCertificateName();
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
  return this.identityManager.generateRSAKeyPair(identityName, isKsk, keySize);
};

/**
 * Set a key as the default key of an identity.
 * @param {Name} keyName The name of the key.
 * @param {Name} identityName (optional) the name of the identity. If not
 * specified, the identity name is inferred from the keyName.
 */
KeyChain.prototype.setDefaultKeyForIdentity = function(keyName, identityName)
{
  if (identityName == null)
    identityName = new Name();
  return this.identityManager.setDefaultKeyForIdentity(keyName, identityName);
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
 */
KeyChain.prototype.installIdentityCertificate = function(certificate)
{
  this.identityManager.addCertificate(certificate);
};

/**
 * Set the certificate as the default for its corresponding key.
 * @param {IdentityCertificate} certificate The certificate.
 */
KeyChain.prototype.setDefaultCertificateForKey = function(certificate)
{
  this.identityManager.setDefaultCertificateForKey(certificate);
};

/**
 * Get a certificate with the specified name.
 * @param {Name} certificateName The name of the requested certificate.
 * @returns {IdentityCertificate} The requested certificate which is valid.
 */
KeyChain.prototype.getCertificate = function(certificateName)
{
  return this.identityManager.getCertificate(certificateName);
};

/**
 * Get a certificate even if the certificate is not valid anymore.
 * @param {Name} certificateName The name of the requested certificate.
 * @returns {IdentityCertificate} The requested certificate.
 */
KeyChain.prototype.getAnyCertificate = function(certificateName)
{
  return this.identityManager.getAnyCertificate(certificateName);
};

/**
 * Get an identity certificate with the specified name.
 * @param {Name} certificateName The name of the requested certificate.
 * @returns {IdentityCertificate} The requested certificate which is valid.
 */
KeyChain.prototype.getIdentityCertificate = function(certificateName)
{
  return this.identityManager.getCertificate(certificateName);
};

/**
 * Get an identity certificate even if the certificate is not valid anymore.
 * @param {Name} certificateName The name of the requested certificate.
 * @returns {IdentityCertificate} The requested certificate.
 */
KeyChain.prototype.getAnyIdentityCertificate = function(certificateName)
{
  return this.identityManager.getAnyCertificate(certificateName);
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
 * is an array, return a signature object.
 * @param {Data|Interest|Buffer} target If this is a Data object, wire encode for
 * signing, update its signature and key locator field and wireEncoding. If this
 * is an Interest object, wire encode for signing, append a SignatureInfo to the
 * Interest name, sign the name components and append a final name component
 * with the signature bits. If it is an array, sign it and return a Signature
 * object.
 * @param {Name} certificateName The certificate name of the key to use for
 * signing.
 * @param {WireFormat} wireFormat (optional) A WireFormat object used to encode
 * the input. If omitted, use WireFormat getDefaultWireFormat().
 */
KeyChain.prototype.sign = function(target, certificateName, wireFormat)
{
  if (target instanceof Interest)
    this.signInterest(target, certificateName, wireFormat);
  else if (target instanceof Data)
    this.identityManager.signByCertificate(target, certificateName, wireFormat);
  else
    return this.identityManager.signByCertificate(target, certificateName);
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
 */
KeyChain.prototype.signInterest = function(interest, certificateName, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());

  // TODO: Handle signature algorithms other than Sha256WithRsa.
  var signature = new Sha256WithRsaSignature();
  signature.getKeyLocator().setType(KeyLocatorType.KEYNAME);
  signature.getKeyLocator().setKeyName(certificateName.getPrefix(-1));

  // Append the encoded SignatureInfo.
  interest.getName().append(wireFormat.encodeSignatureInfo(signature));

  // Append an empty signature so that the "signedPortion" is correct.
  interest.getName().append(new Name.Component());
  // Encode once to get the signed portion.
  var encoding = interest.wireEncode(wireFormat);
  var signedSignature = this.sign(encoding.signedBuf(), certificateName);

  // Remove the empty signature and append the real one.
  var encoder = new TlvEncoder(256);
  encoder.writeBlobTlv
    (Tlv.SignatureValue, signedSignature.getSignature().buf());
  interest.setName(interest.getName().getPrefix(-1).append
    (wireFormat.encodeSignatureValue(signedSignature)));
};

/**
 * Sign the target. If it is a Data object, set its signature. If it is an
 * array, return a signature object.
 * @param {Data|Buffer} target If this is a Data object, wire encode for
 * signing, update its signature and key locator field and wireEncoding. If it
 * is an array, sign it and return a Signature object.
 * @param identityName (optional) The identity name for the key to use for
 * signing.  If omitted, infer the signing identity from the data packet name.
 * @param wireFormat (optional) A WireFormat object used to encode the input. If
 * omitted, use WireFormat getDefaultWireFormat().
 */
KeyChain.prototype.signByIdentity = function(target, identityName, wireFormat)
{
  if (identityName == null)
    identityName = new Name();

  if (target instanceof Data) {
    var signingCertificateName;
    if (identityName.size() == 0) {
      var inferredIdentity = this.policyManager.inferSigningIdentity
        (data.getName());
      if (inferredIdentity.size() == 0)
        signingCertificateName = this.identityManager.getDefaultCertificateName();
      else
        signingCertificateName =
          this.identityManager.getDefaultCertificateNameForIdentity
            (inferredIdentity);
    }
    else
      signingCertificateName =
        this.identityManager.getDefaultCertificateNameForIdentity(identityName);

    if (signingCertificateName.size() == 0)
      throw new SecurityException(new Error
        ("No qualified certificate name found!"));

    if (!this.policyManager.checkSigningPolicy
         (data.getName(), signingCertificateName))
      throw new SecurityException(new Error
        ("Signing Cert name does not comply with signing policy"));

    this.identityManager.signByCertificate
      (data, signingCertificateName, wireFormat);
  }
  else {
    var signingCertificateName =
      this.identityManager.getDefaultCertificateNameForIdentity(identityName);

    if (signingCertificateName.size() == 0)
      throw new SecurityException(new Error
        ("No qualified certificate name found!"));

    return this.identityManager.signByCertificate(array, signingCertificateName);
  }
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

/*****************************************
 *           Encrypt/Decrypt             *
 *****************************************/

/**
 * Generate a symmetric key.
 * @param {Name} keyName The name of the generated key.
 * @param {number} keyType (optional) The type of the key from KeyType, e.g.
 * KeyType.AES.
 */
KeyChain.prototype.generateSymmetricKey = function(keyName, keyType)
{
  this.encryptionManager.createSymmetricKey(keyName, keyType);
};

/**
 * Encrypt a byte array.
 * @param {Name} keyName The name of the encrypting key.
 * @param {Buffer} data The byte array that will be encrypted.
 * @param {boolean} useSymmetric (optional) If true then symmetric encryption is
 * used, otherwise asymmetric encryption is used. If omitted, use symmetric
 * encryption.
 * @param encryptMode (optional) The encryption mode from EncryptMode. If
 * omitted, use EncryptMode.DEFAULT.
 * @returns {Blob} The encrypted data as an immutable Blob.
 */
KeyChain.prototype.encrypt = function(keyName, data, useSymmetric, encryptMode)
{
  return this.encryptionManager.encrypt(keyName, data, useSymmetric, encryptMode);
}

/**
 * Decrypt a byte array.
 * @param {Name} keyName The name of the decrypting key.
 * @param {Buffer} data The byte array that will be decrypted.
 * @param {boolean} useSymmetric (optional) If true then symmetric encryption is
 * used, otherwise asymmetric encryption is used. If omitted, use symmetric
 * encryption.
 * @param encryptMode (optional) The encryption mode from EncryptMode. If
 * omitted, use EncryptMode.DEFAULT.
 * @returns {Blob} The decrypted data as an immutable Blob.
 */
KeyChain.prototype.decrypt = function(keyName, data, useSymmetric, encryptMode)
{
   return this.encryptionManager.decrypt
     (keyName, data, useSymmetric, encryptMode);
};

/**
 * Set the Face which will be used to fetch required certificates.
 * @param {Face} face A pointer to the Face object.
 */
KeyChain.prototype.setFace = function(face)
{ 
  this.face = face;
};

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
