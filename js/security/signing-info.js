/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/signing-info.cpp
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
var PibIdentity = require('./pib/pib-identity.js').PibIdentity; /** @ignore */
var PibKey = require('./pib/pib-key.js').PibKey; /** @ignore */
var DigestAlgorithm = require('./security-types.js').DigestAlgorithm; /** @ignore */
var ValidityPeriod = require('./validity-period.js').ValidityPeriod;

/**
 * SigningInfo holds the signing parameters passed to the KeyChain. A
 * SigningInfo is invalid if the specified identity/key/certificate does not
 * exist, or the PibIdentity or PibKey instance is not valid.
 *
 * The SigningInfo constructor has multiple forms:
 * SigningInfo() - Create a default SigningInfo with
 * SigningInfo.SignerType.NULL and an empty Name.
 * SigningInfo(signerType, signerName) - Create a SigningInfo with the
 * signerType and optional signer Name.
 * Signinginfo(identity) - Create a SigningInfo of type
 * SigningInfo.SignerType.ID according to the given PibIdentity, where the
 * digest algorithm is set to DigestAlgorithm.SHA256.
 * SigningInfo(key) - Create a SigningInfo of type SigningInfo.SignerType.KEY
 * according to the given PibKey, where the digest algorithm is set to
 * DigestAlgorithm.SHA256.
 * SigningInfo(signingString) - Create a SigningInfo from its string
 * representation, where the digest algorithm is set to DigestAlgorithm.SHA256.

 * @param {number} signerType The type of signer as an int from the
 * SigningInfo.SignerType enum.
 * @param {Name} signerName The name of signer. The interpretation of the
 * signerName differs based on the signerType. This copies the Name.
 * @param {PibIdentity} identity An existing PibIdentity which is not copied.
 * @param {PibKey} key An existing PibKey which is not copied.
 * @param {string} signingString The representative signing string for the
 * signing method, as follows:
 * Default signing: "" (the empty string).
 * Signing with the default certificate of the default key for the identity
 * with the specified name:
 * `id:/my-identity`.
 * Signing with the default certificate of the key with the specified name:
 * `key:/my-identity/ksk-1`.
 * Signing with the certificate with the specified name:
 * `cert:/my-identity/KEY/ksk-1/ID-CERT/%FD%01`.
 * Signing with sha256 digest: `id:/localhost/identity/digest-sha256` (the
 * value returned by getDigestSha256Identity()).
 * @throws Error If the signingString format is invalid.
 * @constructor
 */
var SigningInfo = function SigningInfo(arg1, arg2)
{
  this.validityPeriod_ = new ValidityPeriod();
  if (arg1 == undefined) {
    this.reset(SigningInfo.SignerType.NULL);
    this.digestAlgorithm_ = DigestAlgorithm.SHA256;
  }
  else if (typeof arg1 === 'number') {
    var signerType = arg1;

    this.reset(signerType);
    if (arg2 != undefined)
      this.name_ = new Name(arg2);
    this.digestAlgorithm_ = DigestAlgorithm.SHA256;
  }
  else if (arg1 instanceof PibIdentity) {
    this.digestAlgorithm_ = DigestAlgorithm.SHA256;
    this.setPibIdentity(arg1);
  }
  else if (arg1 instanceof PibKey) {
    this.digestAlgorithm_ = DigestAlgorithm.SHA256;
    this.setPibKey(arg1);
  }
  else if (typeof arg1 === 'string') {
    signingString = arg1;

    this.reset(SigningInfo.SignerType.NULL);
    this.digestAlgorithm_ = DigestAlgorithm.SHA256;

    if (signingString == "")
      return;

    var iColon = signingString.indexOf(':');
    if (iColon < 0)
      throw new Error("Invalid signing string cannot represent SigningInfo");

    var scheme = signingString.substring(0, iColon);
    var nameArg = signingString.substring(iColon + 1);

    if (scheme == "id") {
      if (nameArg == SigningInfo.getDigestSha256Identity().toUri())
        this.setSha256Signing();
      else
        this.setSigningIdentity(new Name(nameArg));
    }
    else if (scheme == "key")
      this.setSigningKeyName(new Name(nameArg));
    else if (scheme == "cert")
      this.setSigningCertificateName(new Name(nameArg));
    else
      throw new Error("Invalid signing string scheme");
  }
  else
    throw new Error("SigningInfo: Unrecognized type");
};

exports.SigningInfo = SigningInfo;

SigningInfo.SignerType = function SigningInfoSignerType() {};

/** No signer is specified. Use default settings or follow the trust schema. */
SigningInfo.SignerType.NULL = 0;
/** The signer is an identity. Use its default key and default certificate. */
SigningInfo.SignerType.ID = 1;
/** The signer is a key. Use its default certificate. */
SigningInfo.SignerType.KEY = 2;
/** The signer is a certificate. Use it directly. */
SigningInfo.SignerType.CERT = 3;
/** Use a SHA-256 digest. No signer needs to be specified. */
SigningInfo.SignerType.SHA256 = 4;

/**
 * Set this to type SignerType.ID and an identity with name identityName. This
 * does not change the digest algorithm.
 * @param {Name} identityName The name of the identity. This copies the Name.
 * @return {SigningInfo} This SigningInfo.
 */
SigningInfo.prototype.setSigningIdentity = function(identityName)
{
  this.reset(SigningInfo.SignerType.ID);
  this.name_ = new Name(identityName);
  return this;
};

/**
 * Set this to type SignerType.KEY and a key with name keyName. This does not
 * change the digest algorithm.
 * @param {Name} keyName The name of the key. This copies the Name.
 * @return {SigningInfo} This SigningInfo.
 */
SigningInfo.prototype.setSigningKeyName = function(keyName)
{
  this.reset(SigningInfo.SignerType.KEY);
  this.name_ = new Name(keyName);
  return this;
};

/**
 * Set this to type SignerType.CERT and a certificate with name certificateName.
 * This does not change the digest algorithm.
 * @param {Name} certificateName The name of the certificate. This copies the
 * Name.
 * @return {SigningInfo} This SigningInfo.
 */
SigningInfo.prototype.setSigningCertificateName = function(certificateName)
{
  this.reset(SigningInfo.SignerType.CERT);
  this.name_ = new Name(certificateName);
  return this;
};

/**
 * Set this to type SignerType.SHA256, and set the digest algorithm to
 * DigestAlgorithm.SHA256.
 * @return {SigningInfo} This SigningInfo.
 */
SigningInfo.prototype.setSha256Signing = function()
{
  this.reset(SigningInfo.SignerType.SHA256);
  this.digestAlgorithm_ = DigestAlgorithm.SHA256;
  return this;
};

/**
 * Set this to type SignerType.ID according to the given PibIdentity. This does
 * not change the digest algorithm.
 * @param {PibIdentity} identity An existing PibIdentity which is not copied, or
 * null. If this is null then use the default identity, otherwise use
 * identity.getName().
 * @return {SigningInfo} This SigningInfo.
 */
SigningInfo.prototype.setPibIdentity = function(identity)
{
  this.reset(SigningInfo.SignerType.ID);
  if (identity != null)
    this.name_ = identity.getName();
  this.identity_ = identity;
  return this;
};

/**
 * Set this to type SignerType.KEY according to the given PibKey. This does not
 * change the digest algorithm.
 * @param {PibKey} key An existing PibKey which is not copied, or null. If this
 * is null then use the default key for the identity, otherwise use
 * key.getName().
 * @return {SigningInfo} This SigningInfo.
 */
SigningInfo.prototype.setPibKey = function(key)
{
  this.reset(SigningInfo.SignerType.KEY);
  if (key != null)
    this.name_ = key.getName();
  this.key_ = key;
  return this;
};

/**
 * Get the type of the signer.
 * @return {number} The type of the signer, as an int from the
 * SigningInfo.SignerType enum.
 */
SigningInfo.prototype.getSignerType = function() { return this.type_; };

/**
 * Get the name of signer.
 * @return {Name} The name of signer. The interpretation differs based on the
 * signerType.
 */
SigningInfo.prototype.getSignerName = function() { return this.name_; };

/**
 * Get the PibIdentity of the signer.
 * @return {PibIdentity} The PibIdentity handler of the signer, or null if
 * getSignerName() should be used to find the identity.
 * @throws Error if the signer type is not SignerType.ID.
 */
SigningInfo.prototype.getPibIdentity = function()
{
  if (this.type_ != SigningInfo.SignerType.ID)
    throw new Error("getPibIdentity: The signer type is not SignerType.ID");
  return this.identity_;
};

/**
 * Get the PibKey of the signer.
 * @return {PibKey} The PibKey handler of the signer, or null if
 * getSignerName() should be used to find the key.
 * @throws Error if the signer type is not SignerType.KEY.
 */
SigningInfo.prototype.getPibKey = function()
{
  if (this.type_ != SigningInfo.SignerType.KEY)
    throw new Error("getPibKey: The signer type is not SignerType.KEY");
  return this.key_;
};

/**
 * Set the digest algorithm for public key operations.
 * @param {number} digestAlgorithm The digest algorithm, as an int from the
 * DigestAlgorithm enum.
 * @return {SigningInfo} This SigningInfo.
 */
SigningInfo.prototype.setDigestAlgorithm = function(digestAlgorithm)
{
  this.digestAlgorithm_ = digestAlgorithm;
  return this;
};

/**
 * Get the digest algorithm for public key operations.
 * @return {number} The digest algorithm, as an int from the DigestAlgorithm
 * enum.
 */
SigningInfo.prototype.getDigestAlgorithm = function()
{
  return this.digestAlgorithm_;
};

/**
 * Set the validity period for the signature info.
 * Note that the equivalent ndn-cxx method uses a semi-prepared SignatureInfo,
 * but this method only uses the ValidityPeriod from the SignatureInfo.
 * @param {ValidityPeriod} validityPeriod The validity period, which is copied.
 * @return {SigningInfo} This SigningInfo.
 */
SigningInfo.prototype.setValidityPeriod = function(validityPeriod)
{
  this.validityPeriod_ = new ValidityPeriod(validityPeriod);
  return this;
};

/**
 * Get the validity period for the signature info.
 * Note that the equivalent ndn-cxx method uses a semi-prepared SignatureInfo,
 * but this method only uses the ValidityPeriod from the SignatureInfo.
 * @return {ValidityPeriod} The validity period.
 */
SigningInfo.prototype.getValidityPeriod = function()
{
  return this.validityPeriod_;
};

/**
 * Get the string representation of this SigningInfo.
 * @return {string} The string representation.
 */
SigningInfo.prototype.toString = function()
{
  if (this.type_ == SigningInfo.SignerType.NULL)
    return "";
  else if (this.type_ == SigningInfo.SignerType.ID)
    return "id:" + this.getSignerName().toUri();
  else if (this.type_ == SigningInfo.SignerType.KEY)
    return "key:" + this.getSignerName().toUri();
  else if (this.type_ == SigningInfo.SignerType.CERT)
    return "cert:" + this.getSignerName().toUri();
  else if (this.type_ == SigningInfo.SignerType.SHA256)
    return "id:" + SigningInfo.getDigestSha256Identity().toUri();
  else
    // We don't expect this to happen.
    throw new Error("Unknown signer type");
};

/**
 * Get the localhost identity which indicates that the signature is generated
 * using SHA-256.
 * @return {Name} A new Name of the SHA-256 identity.
 */
SigningInfo.getDigestSha256Identity = function()
{
  return new Name("/localhost/identity/digest-sha256");
};

/**
 * Check and set the signerType, and set others to default values. This does NOT
 * reset the digest algorithm.
 * @param {number} signerType The type of signer as an int from the
 * SigningInfo.SignerType enum.
 */
SigningInfo.prototype.reset = function(signerType)
{
  if (!(signerType == SigningInfo.SignerType.NULL ||
        signerType == SigningInfo.SignerType.ID ||
        signerType == SigningInfo.SignerType.KEY ||
        signerType == SigningInfo.SignerType.CERT ||
        signerType == SigningInfo.SignerType.SHA256))
    throw new Error("SigningInfo: The signerType is not valid");

  this.type_ = signerType;
  this.name_ = new Name();
  this.identity_ = null;
  this.key_ = null;
  this.validityPeriod_ = new ValidityPeriod();
};
