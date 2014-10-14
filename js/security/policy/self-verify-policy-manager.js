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

var Name = require('../../name.js').Name;
var Interest = require('../../interest.js').Interest;
var Data = require('../../data.js').Data;
var DataUtils = require('../../encoding/data-utils.js').DataUtils;
var IdentityCertificate = require('../certificate/identity-certificate.js').IdentityCertificate;
var KeyLocatorType = require('../../key-locator.js').KeyLocatorType;
var SecurityException = require('../security-exception.js').SecurityException;
var WireFormat = require('../../encoding/wire-format.js').WireFormat;
var PolicyManager = require('./policy-manager.js').PolicyManager;

/**
 * A SelfVerifyPolicyManager implements a PolicyManager to use the public key
 * DER in the data packet's KeyLocator (if available) or look in the
 * IdentityStorage for the public key with the name in the KeyLocator (if
 * available) and use it to verify the data packet, without searching a
 * certificate chain.  If the public key can't be found, the verification fails.
 *
 * @param {IdentityStorage} identityStorage (optional) The IdentityStorage for
 * looking up the public key. This object must remain valid during the life of
 * this SelfVerifyPolicyManager. If omitted, then don't look for a public key
 * with the name in the KeyLocator and rely on the KeyLocator having the full
 * public key DER.
 * @constructor
 */
var SelfVerifyPolicyManager = function SelfVerifyPolicyManager(identityStorage)
{
  // Call the base constructor.
  PolicyManager.call(this);

  this.identityStorage = identityStorage;
};

SelfVerifyPolicyManager.prototype = new PolicyManager();
SelfVerifyPolicyManager.prototype.name = "SelfVerifyPolicyManager";

exports.SelfVerifyPolicyManager = SelfVerifyPolicyManager;

/**
 * Never skip verification.
 *
 * @param {Data|Interest} dataOrInterest The received data packet or interest.
 * @returns {boolean} False.
 */
SelfVerifyPolicyManager.prototype.skipVerifyAndTrust = function(dataOrInterest)
{
  return false;
};

/**
 * Always return true to use the self-verification rule for the received data.
 *
 * @param {Data|Interest} dataOrInterest The received data packet or interest.
 * @returns {boolean} True.
 */
SelfVerifyPolicyManager.prototype.requireVerify = function(dataOrInterest)
{
  return true;
};

/**
 * Use the public key DER in the KeyLocator (if available) or look in the
 * IdentityStorage for the public key with the name in the KeyLocator (if
 * available) and use it to verify the data packet.  If the public key can't
   * be found, call onVerifyFailed.
 *
 * @param {Data|Interest} dataOrInterest The Data object or interest with the
 * signature to check.
 * @param {number} stepCount The number of verification steps that have been
 * done, used to track the verification progress.
 * @param {function} onVerified If the signature is verified, this calls
 * onVerified(data).
 * @param {function} onVerifyFailed If the signature check fails, this calls
 * onVerifyFailed(data).
 * @param {WireFormat} wireFormat
 * @returns {ValidationRequest} null for no further step for looking up a
 * certificate chain.
 */
SelfVerifyPolicyManager.prototype.checkVerificationPolicy = function
  (dataOrInterest, stepCount, onVerified, onVerifyFailed, wireFormat)
{
  wireFormat = (wireFormat || WireFormat.getDefaultWireFormat());

  if (dataOrInterest instanceof Data) {
    var data = dataOrInterest;
    // wireEncode returns the cached encoding if available.
    if (this.verify(data.getSignature(), data.wireEncode()))
      onVerified(data);
    else
      onVerifyFailed(data);
  }
  else if (dataOrInterest instanceof Interest) {
    var interest = dataOrInterest;
    // Decode the last two name components of the signed interest
    var signature = wireFormat.decodeSignatureInfoAndValue
      (interest.getName().get(-2).getValue().buf(),
       interest.getName().get(-1).getValue().buf());

    // wireEncode returns the cached encoding if available.
    if (this.verify(signature, interest.wireEncode()))
      onVerified(interest);
    else
      onVerifyFailed(interest);
  }
  else
    throw new SecurityException(new Error
      ("checkVerificationPolicy: unrecognized type for dataOrInterest"));

  // No more steps, so return a None.
  return null;
};

/**
 * Override to always indicate that the signing certificate name and data name
 * satisfy the signing policy.
 *
 * @param {Name} dataName The name of data to be signed.
 * @param {Name} certificateName The name of signing certificate.
 * @returns {boolean} True to indicate that the signing certificate can be used
 * to sign the data.
 */
SelfVerifyPolicyManager.prototype.checkSigningPolicy = function
  (dataName, certificateName)
{
  return true;
};

/**
 * Override to indicate that the signing identity cannot be inferred.
 *
 * @param {Name} dataName The name of data to be signed.
 * @returns {Name} An empty name because cannot infer.
 */
SelfVerifyPolicyManager.prototype.inferSigningIdentity = function(dataName)
{
  return new Name();
};

/**
 * Check the type of signatureInfo to get the KeyLocator. Use the public key
 * DER in the KeyLocator (if available) or look in the IdentityStorage for the
 * public key with the name in the KeyLocator (if available) and use it to
 * verify the signedBlob. If the public key can't be found, return false.
 * (This is a generalized method which can verify both a Data packet and an
 * interest.)
 * @param {Signature} signatureInfo An object of a subclass of Signature, e.g.
 * Sha256WithRsaSignature.
 * @param {SignedBlob} signedBlob the SignedBlob with the signed portion to
 * verify.
 * @returns {boolean} True if the signature is verified, false if failed.
 */
SelfVerifyPolicyManager.prototype.verify = function(signatureInfo, signedBlob)
{
  var signature = signatureInfo;
  /*
  if (!signature)
    throw new SecurityException(new Error
      ("SelfVerifyPolicyManager: Signature is not Sha256WithRsaSignature.");
  */

  if (signature.getKeyLocator().getType() == KeyLocatorType.KEY)
    // Use the public key DER directly.
    return SelfVerifyPolicyManager.verifySha256WithRsaSignature
      (signature, signedBlob, signature.getKeyLocator().getKeyData());
  else if (signature.getKeyLocator().getType() == KeyLocatorType.KEYNAME &&
           this.identityStorage != null) {
    // Assume the key name is a certificate name.
    var publicKeyDer = this.identityStorage.getKey
      (IdentityCertificate.certificateNameToPublicKeyName
       (signature.getKeyLocator().getKeyName()));
    if (publicKeyDer.isNull())
      // Can't find the public key with the name.
      return false;

    return SelfVerifyPolicyManager.verifySha256WithRsaSignature
      (signature, signedBlob, publicKeyDer);
  }
  else
    // Can't find a key to verify.
    return false;
};

// The first time verify is called, it sets this to determine if a signature
//   buffer needs to be converted to a string for the crypto verifier.
SelfVerifyPolicyManager.verifyUsesString = null;

/**
 * Verify the RSA signature on the SignedBlob using the given public key.
 * TODO: Move this general verification code to a more central location.
 * @param signature {Sha256WithRsaSignature} The Sha256WithRsaSignature.
 * @param signedBlob {SignedBlob} the SignedBlob with the signed portion to
 * verify.
 * @param publicKeyDer {Blob} The DER-encoded public key used to verify the
 * signature.
 * @returns true if the signature verifies, false if not.
 */
SelfVerifyPolicyManager.verifySha256WithRsaSignature = function
  (signature, signedBlob, publicKeyDer)
{
  if (SelfVerifyPolicyManager.verifyUsesString === null) {
    var hashResult = require("crypto").createHash('sha256').digest();
    // If the hash result is a string, we assume that this is a version of
    //   crypto where verify also uses a string signature.
    SelfVerifyPolicyManager.verifyUsesString = (typeof hashResult === 'string');
  }

  // The crypto verifier requires a PEM-encoded public key.
  var keyBase64 = publicKeyDer.buf().toString('base64');
  var keyPem = "-----BEGIN PUBLIC KEY-----\n";
  for (var i = 0; i < keyBase64.length; i += 64)
    keyPem += (keyBase64.substr(i, 64) + "\n");
  keyPem += "-----END PUBLIC KEY-----";

  var verifier = require('crypto').createVerify('RSA-SHA256');
  verifier.update(signedBlob.signedBuf());
  var signatureBytes = Data.verifyUsesString ?
    DataUtils.toString(signature.getSignature().buf()) :
    signature.getSignature().buf();
  return verifier.verify(keyPem, signatureBytes);
};
