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

var crypto = require("crypto");
var Name = require('../../name.js').Name;
var Data = require('../../data.js').Data;
var Blob = require('../../util/blob.js').Blob;
var DigestSha256Signature = require('../../digest-sha256-signature.js').DigestSha256Signature;
var Sha256WithRsaSignature = require('../../sha256-with-rsa-signature.js').Sha256WithRsaSignature;
var KeyLocatorType = require('../../key-locator.js').KeyLocatorType;
var WireFormat = require('../../encoding/wire-format.js').WireFormat;
var SecurityException = require('../security-exception.js').SecurityException;
var DigestAlgorithm = require('../security-types.js').DigestAlgorithm;
var KeyType = require('../security-types.js').KeyType;
var RsaKeyParams = require('../key-params.js').RsaKeyParams;
var IdentityCertificate = require('../certificate/identity-certificate.js').IdentityCertificate;
var PublicKey = require('../certificate/public-key.js').PublicKey;
var CertificateSubjectDescription = require('../certificate/certificate-subject-description.js').CertificateSubjectDescription;

/**
 * An IdentityManager is the interface of operations related to identity, keys,
 * and certificates.
 *
 * Create a new IdentityManager to use the given IdentityStorage and
 * PrivateKeyStorage.
 * @param {IdentityStorage} identityStorage An object of a subclass of
 * IdentityStorage.
 * @param {PrivateKeyStorage} privateKeyStorage An object of a subclass of
 * PrivateKeyStorage.
 * @constructor
 */
var IdentityManager = function IdentityManager
  (identityStorage, privateKeyStorage)
{
  this.identityStorage = identityStorage;
  this.privateKeyStorage = privateKeyStorage;
};

exports.IdentityManager = IdentityManager;

/**
 * Create an identity by creating a pair of Key-Signing-Key (KSK) for this
 * identity and a self-signed certificate of the KSK. If a key pair or
 * certificate for the identity already exists, use it.
 * @param {Name} identityName The name of the identity.
 * @params {KeyParams} params The key parameters if a key needs to be generated
 * for the identity.
 * @returns {Name} The name of the default certificate of the identity.
 */
IdentityManager.prototype.createIdentityAndCertificate = function
  (identityName, params)
{
  this.identityStorage.addIdentity(identityName);

  var keyName = null;
  var generateKey = true;
  try {
    keyName = this.identityStorage.getDefaultKeyNameForIdentity(identityName);
    var key = new PublicKey(this.identityStorage.getKey(keyName));
    if (key.getKeyType() == params.getKeyType())
      // The key exists and has the same type, so don't need to generate one.
      generateKey = false;
  } catch (ex) {}

  if (generateKey) {
    keyName = this.generateKeyPair(identityName, true, params);
    this.identityStorage.setDefaultKeyNameForIdentity(keyName, identityName);
  }

  var certName = null;
  var makeCert = true;
  try {
    certName = this.identityStorage.getDefaultCertificateNameForKey(keyName);
    // The cert exists, so don't need to make it.
    makeCert = false;
  } catch (ex) {}

  if (makeCert) {
    var selfCert = this.selfSign(keyName);
    this.addCertificateAsIdentityDefault(selfCert);
    certName = selfCert.getName();
  }

  return certName;
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
 * @returns {Name} The key name of the auto-generated KSK of the identity.
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
 * @param identityName {Name} The name of the identity.
 */
IdentityManager.prototype.deleteIdentity = function(identityName)
{
  try {
    if (this.identityStorage.getDefaultIdentity().equals(identityName))
      // Don't delete the default identity!
      return;
  }
  catch (ex) {
    // There is no default identity to check.
  }

  var keysToDelete = [];
  this.identityStorage.getAllKeyNamesOfIdentity(identityName, keysToDelete, true);
  this.identityStorage.getAllKeyNamesOfIdentity(identityName, keysToDelete, false);

  this.identityStorage.deleteIdentityInfo(identityName);

  for (var i = 0; i < keysToDelete.length; ++i)
    this.privateKeyStorage.deleteKeyPair(keysToDelete[i]);
};

/**
 * Set the default identity.  If the identityName does not exist, then clear the
 * default identity so that getDefaultIdentity() throws an exception.
 * @param {Name} identityName The default identity name.
 */
IdentityManager.prototype.setDefaultIdentity = function(identityName)
{
  this.identityStorage.setDefaultIdentity(identityName);
};

/**
 * Get the default identity.
 * @returns {Name} The name of default identity.
 * @throws SecurityException if the default identity is not set.
 */
IdentityManager.prototype.getDefaultIdentity = function()
{
  return this.identityStorage.getDefaultIdentity();
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
IdentityManager.prototype.generateRSAKeyPair = function
  (identityName, isKsk, keySize)
{
  return this.generateKeyPair(identityName, isKsk, new RsaKeyParams(keySize));
};

/**
 * Set a key as the default key of an identity.
 * @param {Name} keyName The name of the key.
 * @param {Name} identityName (optional) the name of the identity. If not
 * specified, the identity name is inferred from the keyName.
 */
IdentityManager.prototype.setDefaultKeyForIdentity = function
  (keyName, identityName)
{
  if (identityName == null)
    identityName = new Name();
  this.identityStorage.setDefaultKeyNameForIdentity(keyName, identityName);
};

/**
 * Get the default key for an identity.
 * @param {Name} identityName The name of the identity.
 * @returns {Name} The default key name.
 * @throws SecurityException if the default key name for the identity is not set.
 */
IdentityManager.prototype.getDefaultKeyNameForIdentity = function(identityName)
{
  return this.identityStorage.getDefaultKeyNameForIdentity(identityName);
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
IdentityManager.prototype.generateRSAKeyPairAsDefault = function
  (identityName, isKsk, keySize)
{
  var newKeyName = this.generateRSAKeyPair(identityName, isKsk, keySize);
  this.identityStorage.setDefaultKeyNameForIdentity(newKeyName, identityName);
  return newKeyName;
};

/**
 * Get the public key with the specified name.
 * @param {Name} keyName The name of the key.
 * @returns {PublicKey} The public key.
 */
IdentityManager.prototype.getPublicKey = function(keyName)
{
  return PublicKey(this.identityStorage.getKey(keyName));
};

// TODO: Add two versions of createIdentityCertificate.

/**
 * Add a certificate into the public key identity storage.
 * @param {IdentityCertificate} certificate The certificate to to added. This
 * makes a copy of the certificate.
 */
IdentityManager.prototype.addCertificate = function(certificate)
{
  this.identityStorage.addCertificate(certificate);
};

/**
 * Set the certificate as the default for its corresponding key.
 * @param {IdentityCertificate} certificate The certificate.
 */
IdentityManager.prototype.setDefaultCertificateForKey = function(certificate)
{
  var keyName = certificate.getPublicKeyName();

  if (!this.identityStorage.doesKeyExist(keyName))
      throw new SecurityException(new Error
        ("No corresponding Key record for certificate!"));

  this.identityStorage.setDefaultCertificateNameForKey
    (keyName, certificate.getName());
};

/**
 * Add a certificate into the public key identity storage and set the
 * certificate as the default for its corresponding identity.
 * @param {IdentityCertificate} certificate The certificate to be added. This
 * makes a copy of the certificate.
 */
IdentityManager.prototype.addCertificateAsIdentityDefault = function(certificate)
{
  this.identityStorage.addCertificate(certificate);
  var keyName = certificate.getPublicKeyName();
  this.setDefaultKeyForIdentity(keyName);
  this.setDefaultCertificateForKey(certificate);
};

/**
 * Add a certificate into the public key identity storage and set the
 * certificate as the default of its corresponding key.
 * @param {IdentityCertificate} certificate The certificate to be added.  This makes a copy of the certificate.
 */
IdentityManager.prototype.addCertificateAsDefault = function(certificate)
{
  this.identityStorage.addCertificate(certificate);
  this.setDefaultCertificateForKey(certificate);
};

/**
 * Get a certificate with the specified name.
 * @param {Name} certificateName The name of the requested certificate.
 * @returns {IdentityCertificate} the requested certificate which is valid.
 */
IdentityManager.prototype.getCertificate = function(certificateName)
{
  return this.identityStorage.getCertificate(certificateName, false);
};

/**
 * Get a certificate even if the certificate is not valid anymore.
 * @param {Name} certificateName The name of the requested certificate.
 * @returns {IdentityCertificate} the requested certificate.
 */
IdentityManager.prototype.getAnyCertificate = function(certificateName)
{
  return this.identityStorage.getCertificate(certificateName, true);
};

/**
 * Get the default certificate name for the specified identity, which will be
 * used when signing is performed based on identity.
 * @param {Name} identityName The name of the specified identity.
 * @returns {Name} The requested certificate name.
 * @throws SecurityException if the default key name for the identity is not
 * set or the default certificate name for the key name is not set.
 */
IdentityManager.prototype.getDefaultCertificateNameForIdentity = function
  (identityName)
{
  return this.identityStorage.getDefaultCertificateNameForIdentity(identityName);
};

/**
 * Get the default certificate name of the default identity, which will be used when signing is based on identity and
 * the identity is not specified.
 * @returns {Name} The requested certificate name.
 * @throws SecurityException if the default identity is not set or the default
 * key name for the identity is not set or the default certificate name for
 * the key name is not set.
 */
IdentityManager.prototype.getDefaultCertificateName = function()
{
  return this.identityStorage.getDefaultCertificateNameForIdentity
    (this.getDefaultIdentity());
};

/**
 * Sign the Data packet or byte array data based on the certificate name.
 * @param {Data|Buffer} target If this is a Data object, wire encode for signing,
 * update its signature and key locator field and wireEncoding. If it is a
 * Biffer, sign it to produce a Signature object.
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
 * @returns {Signature} If onComplete is omitted, return the generated Signature
 * object (if target is a Buffer) or null (if target is Data). Otherwise, if
 * onComplete is supplied then return null and use onComplete as described above.
 */
IdentityManager.prototype.signByCertificate = function
  (target, certificateName, wireFormat, onComplete)
{
  onComplete = (typeof wireFormat === "function") ? wireFormat : onComplete;
  wireFormat = (typeof wireFormat === "function" || !wireFormat) ? WireFormat.getDefaultWireFormat() : wireFormat;

  var keyName = IdentityManager.certificateNameToPublicKeyName(certificateName);

  if (target instanceof Data) {
    var data = target;
    var digestAlgorithm = [0];
    var signature = this.makeSignatureByCertificate
      (certificateName, digestAlgorithm);

    data.setSignature(signature);
    // Encode once to get the signed portion.
    var encoding = data.wireEncode(wireFormat);

    if (onComplete) {
      this.privateKeyStorage.sign
        (encoding.signedBuf(), keyName, digestAlgorithm[0], function(signatureValue) {
          data.getSignature().setSignature(signatureValue);
          // Encode again to include the signature.
          data.wireEncode(wireFormat);
          onComplete(data);
        });
    }
    else {
      data.getSignature().setSignature(this.privateKeyStorage.sign
        (encoding.signedBuf(), keyName, digestAlgorithm[0]));

      // Encode again to include the signature.
      data.wireEncode(wireFormat);
    }
  }
  else {
    var digestAlgorithm = [0];
    var signature = this.makeSignatureByCertificate
      (certificateName, digestAlgorithm);

    if (onComplete) {
      this.privateKeyStorage.sign
        (target, keyName, digestAlgorithm[0], function(signatureValue) {
          signature.setSignature(signatureValue);
          onComplete(signature);
        });
    }
    else {
      signature.setSignature(this.privateKeyStorage.sign
        (target, keyName, digestAlgorithm[0]));

      return signature;
    }
  }

  return null;
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
 */
IdentityManager.prototype.signInterestByCertificate = function
  (interest, certificateName, wireFormat, onComplete)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());

  var digestAlgorithm = [0];
  var signature = this.makeSignatureByCertificate
    (certificateName, digestAlgorithm);

  // Append the encoded SignatureInfo.
  interest.getName().append(wireFormat.encodeSignatureInfo(signature));

  // Append an empty signature so that the "signedPortion" is correct.
  interest.getName().append(new Name.Component());
  // Encode once to get the signed portion.
  var encoding = interest.wireEncode(wireFormat);
  var keyName = IdentityManager.certificateNameToPublicKeyName(certificateName);

  if (onComplete) {
    this.privateKeyStorage.sign
      (encoding.signedBuf(), keyName, digestAlgorithm[0], function(signatureValue) {
        signature.setSignature(signatureValue);

        // Remove the empty signature and append the real one.
        interest.setName(interest.getName().getPrefix(-1).append
          (wireFormat.encodeSignatureValue(signature)));
        onComplete(interest);
      });
  }
  else {
    signature.setSignature(this.privateKeyStorage.sign
      (encoding.signedBuf(), keyName, digestAlgorithm[0]));

    // Remove the empty signature and append the real one.
    interest.setName(interest.getName().getPrefix(-1).append
      (wireFormat.encodeSignatureValue(signature)));
  }
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
  var hash = crypto.createHash('sha256');
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
  var hash = crypto.createHash('sha256');
  hash.update(encoding.signedBuf());
  signature.setSignature(new Blob(hash.digest(), false));

  // Remove the empty signature and append the real one.
  interest.setName(interest.getName().getPrefix(-1).append
    (wireFormat.encodeSignatureValue(signature)));
};

/**
 * Generate a self-signed certificate for a public key.
 * @param {Name} keyName The name of the public key.
 * @returns {IdentityCertificate} The generated certificate.
 */
IdentityManager.prototype.selfSign = function(keyName)
{
  var certificate = new IdentityCertificate();

  var keyBlob = this.identityStorage.getKey(keyName);
  var publicKey = new PublicKey(keyBlob);

  var notBefore = new Date().getTime();
  var notAfter = notBefore + 2 * 365 * 24 * 3600 * 1000; // about 2 years

  certificate.setNotBefore(notBefore);
  certificate.setNotAfter(notAfter);

  var certificateName = keyName.getPrefix(-1).append("KEY").append
    (keyName.get(-1)).append("ID-CERT").append
    (Name.Component.fromNumber(certificate.getNotBefore()));
  certificate.setName(certificateName);

  certificate.setPublicKeyInfo(publicKey);
  certificate.addSubjectDescription(new CertificateSubjectDescription
    ("2.5.4.41", keyName.toUri()));
  certificate.encode();

  this.signByCertificate(certificate, certificate.getName());

  return certificate;
};

/**
 * Get the public key name from the full certificate name.
 *
 * @param {Name} certificateName The full certificate name.
 * @returns {Name} The related public key name.
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
 * @returns {Signature} A new object of the correct subclass of Signature.
 */
IdentityManager.prototype.makeSignatureByCertificate = function
  (certificateName, digestAlgorithm)
{
  var keyName = IdentityManager.certificateNameToPublicKeyName(certificateName);
  var publicKey = this.privateKeyStorage.getPublicKey(keyName);
  var keyType = publicKey.getKeyType();

  if (keyType == KeyType.RSA) {
    var signature = new Sha256WithRsaSignature();
    digestAlgorithm[0] = DigestAlgorithm.SHA256;

    signature.getKeyLocator().setType(KeyLocatorType.KEYNAME);
    signature.getKeyLocator().setKeyName(certificateName.getPrefix(-1));

    return signature;
  }
  else
    throw new SecurityException(new Error("Key type is not recognized"));
};

/**
 * A private method to generate a pair of keys for the specified identity.
 * @param {Name} identityName The name of the identity.
 * @param {boolean} isKsk true for generating a Key-Signing-Key (KSK), false for
 * a Data-Signing-Key (DSK).
 * @param {KeyParams} params The parameters of the key.
 * @returns {Name} The generated key name.
 */
IdentityManager.prototype.generateKeyPair = function(identityName, isKsk, params)
{
  var keyName = this.identityStorage.getNewKeyName(identityName, isKsk);
  this.privateKeyStorage.generateKeyPair(keyName, params);
  var publicKeyBits = this.privateKeyStorage.getPublicKey(keyName).getKeyDer();
  this.identityStorage.addKey(keyName, params.getKeyType(), publicKeyBits);

  return keyName;
};
